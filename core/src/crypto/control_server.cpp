#include "pf/control_server.h"

#include <algorithm>

#include "pf/control_client.h"
#include "pf/crypto/os_random.h"
#include "pf/secure_mem.h"

namespace pf {

namespace {

constexpr uint8_t op(OvpnOpcode o) { return static_cast<uint8_t>(o); }
constexpr size_t kMaxUsername = 256, kMaxPassword = 1024;

bool all_zero(const uint8_t* p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc = static_cast<uint8_t>(acc | p[i]);
    return acc == 0;
}

// No control characters (a newline would break the via-file format of the V6 hook), bounded length.
bool clean_text(const std::string& s, size_t max) {
    if (s.empty() || s.size() > max) return false;
    for (const char c : s)
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F) return false;
    return true;
}

std::string swap_role(std::string s, const char* from, const char* to) {
    const size_t pos = s.rfind(from);
    if (pos != std::string::npos) s.replace(pos, 10, to);
    return s;
}

}  // namespace

std::string default_server_options() { return swap_role(default_client_options(), "tls-client", "tls-server"); }

ControlServer::ControlServer(ControlServerConfig cfg)
    : cfg_(std::move(cfg)), channel_(derive_tls_crypt_keys(cfg_.tls_crypt_key, TlsCryptRole::Server)) {
    secure_zero(cfg_.tls_crypt_key.data(), cfg_.tls_crypt_key.size());
}

ControlServer::~ControlServer() { close("destroyed"); }

std::unique_ptr<ControlServer> ControlServer::create(ControlServerConfig cfg, std::string& error) {
    if (cfg.tls.role != TlsRole::Server) { error = "ControlServer needs a TLS server configuration"; return nullptr; }
    if (cfg.max_payload < 16) { error = "max_payload too small"; return nullptr; }
    if (cfg.require_user_pass && !cfg.external_auth) { error = "require_user_pass needs external_auth (who checks the password?)"; return nullptr; }
    std::string push;
    if (!build_push_reply(cfg.push, push)) { error = "push options are not usable (address, peer-id or length)"; return nullptr; }
    if (TlsSession::create(cfg.tls, error) == nullptr) return nullptr;
    std::unique_ptr<ControlServer> s(new ControlServer(std::move(cfg)));
    if (s->cfg_.random == nullptr) s->own_random_ = make_os_random();
    s->random_ = s->cfg_.random ? s->cfg_.random : s->own_random_.get();
    if (!s->random_ || !s->random_->fill(s->my_sid_.data(), s->my_sid_.size()) || all_zero(s->my_sid_.data(), s->my_sid_.size())) {
        error = "random source failed";
        return nullptr;
    }
    return s;
}

std::unique_ptr<ControlServer> ControlServer::adopt(ControlServerConfig cfg, const Adopted& a, uint64_t now_ms, std::string& error) {
    std::unique_ptr<ControlServer> s = create(std::move(cfg), error);
    if (!s) return nullptr;
    s->now_ms_ = now_ms;
    KeyState* ks = s->add_state(0, /*initial=*/true);
    if (ks == nullptr) { error = "cannot create TLS session"; return nullptr; }
    s->my_sid_ = a.server_sid;
    s->client_sid_ = a.client_sid;
    s->have_client_sid_ = true;
    uint32_t id = 0;
    ks->sender.enqueue(op(OvpnOpcode::ControlHardResetServerV2), {}, id);
    ks->sender.on_ack(&id, 1);                                 // the client echoed our session id: it has message 0
    std::vector<ReliableReceiver::Delivered> delivered;
    ks->receiver.on_message(0, {}, delivered);                 // its reset, already acknowledged in the stateless reply
    (void)ks->receiver.take_acks(kMaxAcksPerPacket);
    s->channel_.skip_packet_ids_to(a.next_tls_crypt_packet_id);
    s->state_ = State::TlsHandshake;
    s->hand_deadline_ms_ = now_ms + s->cfg_.hand_window_ms;
    return s;
}

ControlServer::KeyState* ControlServer::find_state(uint8_t key_id) {
    auto it = states_.find(key_id);
    return it == states_.end() ? nullptr : it->second.get();
}

ControlServer::KeyState* ControlServer::add_state(uint8_t key_id, bool initial) {
    auto ks = std::make_unique<KeyState>(key_id, initial, cfg_.reliable);
    std::string err;
    ks->tls = TlsSession::create(cfg_.tls, err);
    if (!ks->tls) return nullptr;
    ks->started_ms = now_ms_;
    KeyState* raw = ks.get();
    states_[key_id] = std::move(ks);
    return raw;
}

ControlPacket ControlServer::base_packet(const KeyState& ks) const {
    ControlPacket p;
    p.key_id = ks.key_id;
    p.session_id = my_sid_;
    p.remote_session_id = client_sid_;
    return p;
}

bool ControlServer::on_datagram(const uint8_t* data, size_t len, uint64_t now_ms, uint32_t) {
    now_ms_ = now_ms;
    ControlPacket p;
    ReplayTicket ticket;
    switch (open_control_packet_deferred(channel_, data, len, p, ticket)) {
        case OpenControlStatus::NotControl: ++stats_.not_control; return false;
        case OpenControlStatus::AuthFailed: ++stats_.auth_failed; return true;
        case OpenControlStatus::Replay: ++stats_.replays; return true;
        case OpenControlStatus::Malformed: ++stats_.malformed; return true;   // authentic but broken: not committed either
        case OpenControlStatus::Ok: break;
    }
    if (state_ == State::Closed) return true;

    // Session binding: only the client's first reset (key_id 0, message 0, nothing to acknowledge yet) opens it.
    if (!have_client_sid_) {
        if (p.opcode != op(OvpnOpcode::ControlHardResetClientV2) || p.key_id != 0 || !p.has_message || p.message_id != 0 ||
            !p.acks.empty()) {
            ++stats_.wrong_session;
            return true;
        }
        KeyState* ks = add_state(0, /*initial=*/true);
        if (ks == nullptr) { close("cannot create TLS session"); return true; }
        client_sid_ = p.session_id;
        have_client_sid_ = true;
        uint32_t id = 0;
        ks->sender.enqueue(op(OvpnOpcode::ControlHardResetServerV2), {}, id);
        state_ = State::TlsHandshake;
        hand_deadline_ms_ = now_ms + cfg_.hand_window_ms;
    } else if (p.session_id != client_sid_ || (!p.acks.empty() && p.remote_session_id != my_sid_)) {
        ++stats_.wrong_session;
        return true;
    }
    commit_control_packet(channel_, ticket);                  // ours: only now may it move the replay window

    KeyState* ks = find_state(p.key_id);
    if (ks == nullptr) {
        // Only a client SOFT_RESET for exactly the next key_id, on an accepted session with no key change in flight,
        // may create key state. Anything else is dropped without allocating anything.
        if (p.opcode == op(OvpnOpcode::ControlSoftResetV1) && state_ == State::Established && !reneg_pending_ && !switch_pending_ &&
            p.key_id == next_key_id(tx_key_id_) && begin_reneg(p.key_id)) {
            ks = find_state(p.key_id);
        }
        if (ks == nullptr) { ++stats_.unknown_key_id; return true; }
    }

    if (!p.acks.empty()) ks->sender.on_ack(p.acks.data(), p.acks.size());
    if (p.has_message) {
        ks->opcodes[p.message_id] = p.opcode;
        std::vector<ReliableReceiver::Delivered> delivered;
        ks->receiver.on_message(p.message_id, p.payload, delivered);
        const uint8_t key_id = ks->key_id;
        for (const auto& m : delivered) {
            KeyState* cur = find_state(key_id);               // a handler may abandon/retire this state or close
            if (cur == nullptr || state_ == State::Closed) break;
            const uint8_t o = cur->opcodes[m.id];
            cur->opcodes.erase(m.id);
            handle_message(*cur, o, m.payload);
        }
    }
    return true;
}

void ControlServer::handle_message(KeyState& ks, uint8_t opcode, const std::vector<uint8_t>& payload) {
    if (opcode != op(OvpnOpcode::ControlV1)) return;        // resets carry nothing; the TLS client (peer) speaks first
    if (state_ == State::Rejected && ks.initial) return;    // refused: stop processing TLS data
    ks.tls->feed(payload.data(), payload.size());
    pump_tls(ks);
}

void ControlServer::flush_tls_output(KeyState& ks) {
    std::vector<uint8_t> out = ks.tls->take_output();
    for (size_t i = 0; i < out.size(); i += cfg_.max_payload) {
        const size_t n = std::min(cfg_.max_payload, out.size() - i);
        ks.backlog.emplace_back(out.begin() + static_cast<std::ptrdiff_t>(i), out.begin() + static_cast<std::ptrdiff_t>(i + n));
    }
}

void ControlServer::pump_tls(KeyState& ks) {
    const uint8_t key_id = ks.key_id;
    const bool initial = ks.initial;
    ks.tls->step();
    flush_tls_output(ks);                                      // carries our alert on failure
    if (ks.tls->state() == TlsSession::State::Failed) {
        const std::string why = "TLS: " + ks.tls->failure_reason();
        if (initial) reject(why, ""); else abandon_reneg(why);
        return;
    }
    if (ks.tls->state() != TlsSession::State::Established) return;
    if (initial && state_ == State::TlsHandshake) state_ = State::KeyExchange;
    std::vector<uint8_t> in = ks.tls->read();
    if (ks.tls->state() == TlsSession::State::Failed) {
        secure_zero(in.data(), in.size());
        const std::string why = "TLS: " + ks.tls->failure_reason();
        if (initial) reject(why, ""); else abandon_reneg(why);
        return;
    }
    ks.app_in.insert(ks.app_in.end(), in.begin(), in.end());
    secure_zero(in.data(), in.size());                         // may hold the password
    if (find_state(key_id) != nullptr) process_app_stream(ks);
}

bool ControlServer::send_key_method(KeyState& ks) {
    KeyMethod2Message m;
    if (!random_->fill(m.random1.data(), m.random1.size()) || !random_->fill(m.random2.data(), m.random2.size())) return false;
    m.options = cfg_.options_string;
    std::vector<uint8_t> w;
    if (!build_key_method2(m, KeyMethod2From::Server, w)) return false;   // empty username, password, peer info (observed)
    const bool ok = ks.tls->write(w.data(), w.size());
    flush_tls_output(ks);
    return ok;
}

void ControlServer::send_control_string(KeyState& ks, const std::string& s) {
    std::vector<uint8_t> b(s.begin(), s.end());
    b.push_back(0);
    ks.tls->write(b.data(), b.size());
    flush_tls_output(ks);
}

void ControlServer::process_app_stream(KeyState& ks) {
    const uint8_t key_id = ks.key_id;
    for (;;) {
        if (state_ == State::Closed || state_ == State::Rejected) return;
        KeyState* cur = find_state(key_id);
        if (cur == nullptr) return;
        KeyState& k = *cur;
        if (!k.km_done) {
            KeyMethod2Message m;
            size_t used = 0;
            const KeyMethod2Status st = parse_key_method2(k.app_in.data(), k.app_in.size(), KeyMethod2From::Client, m, used);
            if (st == KeyMethod2Status::Truncated) return;
            secure_zero(k.app_in.data(), used);
            k.app_in.erase(k.app_in.begin(), k.app_in.begin() + static_cast<std::ptrdiff_t>(used));
            secure_zero(m.pre_master.data(), m.pre_master.size());
            if (st != KeyMethod2Status::Ok) {
                secure_zero(k.app_in.data(), k.app_in.size());
                if (k.initial) reject("invalid key-method 2 message from client", ""); else abandon_reneg("invalid key-method 2 message");
                return;
            }
            k.km_done = true;
            if (!send_key_method(k) || !derive_data_keys_ekm(*k.tls, cfg_.ekm, TlsRole::Server, k.tx, k.rx)) {
                secure_zero(m.password.data(), m.password.size());
                if (k.initial) reject("key exchange failed on our side", ""); else abandon_reneg("key exchange failed on our side");
                return;
            }
            if (k.initial) on_initial_key_method(k, m); else on_reneg_key_method(k, m);
            secure_zero(m.password.data(), m.password.size());
            continue;
        }
        const auto nul = std::find(k.app_in.begin(), k.app_in.end(), uint8_t(0));
        if (nul == k.app_in.end()) return;
        const std::string msg(k.app_in.begin(), nul);
        k.app_in.erase(k.app_in.begin(), nul + 1);
        if (k.initial && classify_control_message(msg) == ControlMessageKind::PushRequest) {
            push_requested_ = true;
            maybe_push();
        } else {
            ++stats_.ignored_control_messages;
        }
    }
}

void ControlServer::on_initial_key_method(KeyState& ks, KeyMethod2Message& m) {
    client_options_ = m.options;
    const std::string expect = swap_role(cfg_.options_string, "tls-server", "tls-client");
    if (m.options != expect) warnings_.push_back("client options differ from the expected string: " + m.options);
    common_name_ = ks.tls->peer_common_name();
    if (!ks.tls->peer_certificate_sha256(cert_sha256_)) { reject("no client certificate fingerprint", "AUTH_FAILED"); return; }

    if (parse_peer_info(m.peer_info, peer_info_) != PeerInfoStatus::Ok) { reject("malformed peer info", "AUTH_FAILED"); return; }
    const std::string unsupported = peer_info_unsupported_reason(peer_info_);
    if (!unsupported.empty()) { reject(unsupported, "AUTH_FAILED," + unsupported); return; }

    if (!m.username.empty() && !clean_text(m.username, kMaxUsername)) { reject("unusable username", "AUTH_FAILED"); return; }
    if (cfg_.require_user_pass) {
        if (m.username.empty()) { reject("client sent no username", "AUTH_FAILED"); return; }
        if (!clean_text(m.password, kMaxPassword)) { reject("unusable password", "AUTH_FAILED"); return; }
    }
    username_ = m.username;
    if (!cfg_.external_auth) { accept_client(); return; }
    AuthRequest r;
    r.common_name = common_name_;
    r.cert_sha256 = cert_sha256_;
    r.username = username_;
    r.password = SecretString(m.password);
    r.peer_info = m.peer_info;
    auth_request_ = std::move(r);
    state_ = State::AuthPending;
}

void ControlServer::on_reneg_key_method(KeyState& ks, KeyMethod2Message& m) {
    std::array<uint8_t, 32> fp{};
    if (!ks.tls->peer_certificate_sha256(fp) || !ct_equal(fp.data(), cert_sha256_.data(), fp.size())) {
        close("renegotiation presented a different certificate");
        return;
    }
    if (m.username != username_) { close("renegotiation presented a different username"); return; }
    if (!install(ks)) { abandon_reneg("cannot install the renegotiated keys"); return; }
    switch_pending_ = ks.key_id;                               // RX works now; TX moves once the client has our reply
    reneg_pending_.reset();
}

std::optional<AuthRequest> ControlServer::take_auth_request() {
    std::optional<AuthRequest> r = std::move(auth_request_);
    auth_request_.reset();
    return r;
}

void ControlServer::resolve_auth(bool accept, const std::string& reason) {
    if (state_ != State::AuthPending) return;
    auth_request_.reset();
    if (accept) accept_client();
    else reject(reason.empty() ? "authentication refused" : "authentication refused: " + reason, "AUTH_FAILED");
}

void ControlServer::accept_client() {
    KeyState* ks = find_state(0);
    if (ks == nullptr || !install(*ks)) { reject("cannot install the data keys", "AUTH_FAILED"); return; }
    tx_key_id_ = 0;
    last_key_at_ms_ = now_ms_;
    state_ = State::Established;
    maybe_push();
}

void ControlServer::maybe_push() {
    if (state_ != State::Established || push_sent_) return;
    if (!push_requested_ && !(peer_info_.iv_proto & kIvProtoRequestPush)) return;
    KeyState* ks = find_state(0);
    std::string msg;
    if (ks == nullptr || !build_push_reply(cfg_.push, msg)) return;   // validated in create()
    send_control_string(*ks, msg);
    push_sent_ = true;
}

void ControlServer::reject(const std::string& why, const std::string& client_message) {
    if (state_ == State::Rejected || state_ == State::Closed) return;
    reason_ = why;
    auth_request_.reset();
    KeyState* ks = find_state(0);
    if (ks != nullptr && !client_message.empty()) send_control_string(*ks, client_message);
    for (auto& kv : states_) wipe_keys(*kv.second);
    state_ = State::Rejected;
    linger_until_ms_ = now_ms_ + cfg_.reject_linger_ms;
}

bool ControlServer::install(KeyState& ks) {
    if (cfg_.keys != nullptr) {
        const KeyRef tr = cfg_.keys->add(ks.tx), rr = cfg_.keys->add(ks.rx);
        if (!cfg_.keys->bind_tx(ks.key_id, tr) || !cfg_.keys->bind_rx(ks.key_id, rr)) {
            cfg_.keys->remove(tr);
            cfg_.keys->remove(rr);
            ks.tx.wipe(); ks.rx.wipe();
            return false;
        }
        ks.tx_ref = tr;
        ks.rx_ref = rr;
    }
    ks.tx.wipe();
    ks.rx.wipe();
    return true;
}

void ControlServer::wipe_keys(KeyState& ks) {
    if (cfg_.keys != nullptr) {
        if (ks.tx_ref.valid()) cfg_.keys->remove(ks.tx_ref);
        if (ks.rx_ref.valid()) cfg_.keys->remove(ks.rx_ref);
    }
    ks.tx_ref = KeyRef{};
    ks.rx_ref = KeyRef{};
    ks.tx.wipe();
    ks.rx.wipe();
}

bool ControlServer::begin_reneg(uint8_t key_id) {
    KeyState* ks = add_state(key_id, /*initial=*/false);
    if (ks == nullptr) return false;
    uint32_t id = 0;
    ks->sender.enqueue(op(OvpnOpcode::ControlSoftResetV1), {}, id);
    reneg_pending_ = key_id;
    return true;
}

void ControlServer::abandon_reneg(const std::string& why) {
    // Once the client's key-method 2 arrived we sent ours: the client may already have switched to the new key. Dropping
    // it here would black-hole its traffic, keeping the old one would black-hole ours. Neither side can tell, so the
    // session ends cleanly instead of limping on (the client reconnects, D-048).
    if (switch_pending_) { close("renegotiation could not be confirmed: " + why); return; }
    if (!reneg_pending_) return;
    const uint8_t id = *reneg_pending_;
    if (KeyState* ks = find_state(id)) wipe_keys(*ks);
    states_.erase(id);
    reneg_pending_.reset();
    ++stats_.reneg_failures;
    last_key_at_ms_ = now_ms_;                                 // a full interval before we start another one
}

void ControlServer::retire_key(uint8_t key_id) {
    if (KeyState* ks = find_state(key_id)) {
        wipe_keys(*ks);
        states_.erase(key_id);
    }
    if (retiring_ && retiring_->key_id == key_id) retiring_.reset();
}

void ControlServer::close(const std::string& why) {
    if (state_ == State::Closed) return;
    for (auto& kv : states_) wipe_keys(*kv.second);
    for (auto& kv : states_) secure_zero(kv.second->app_in.data(), kv.second->app_in.size());
    states_.clear();
    auth_request_.reset();
    reneg_pending_.reset();
    switch_pending_.reset();
    retiring_.reset();
    data_ready_ = false;
    if (state_ != State::Rejected || reason_.empty()) reason_ = why;
    state_ = State::Closed;
}

bool ControlServer::flushed(uint8_t key_id) const {
    const auto it = states_.find(key_id);
    return it != states_.end() && it->second->backlog.empty() && it->second->sender.outstanding() == 0;
}

std::vector<std::vector<uint8_t>> ControlServer::poll(uint64_t now_ms, uint32_t unix_s) {
    std::vector<std::vector<uint8_t>> out;
    now_ms_ = now_ms;
    if (state_ == State::Closed || state_ == State::WaitReset) return out;
    if (state_ == State::Rejected && now_ms >= linger_until_ms_) { close(reason_); return out; }
    if ((state_ == State::TlsHandshake || state_ == State::KeyExchange || state_ == State::AuthPending) && now_ms >= hand_deadline_ms_) {
        close("handshake did not finish within the hand-window");
        return out;
    }

    if (state_ == State::Established) {
        if (push_sent_ && !data_ready_ && flushed(0)) data_ready_ = true;
        if (switch_pending_ && flushed(*switch_pending_)) {
            if (retiring_) retire_key(retiring_->key_id);
            retiring_ = Retiring{tx_key_id_, now_ms + cfg_.old_key_grace_ms};
            tx_key_id_ = *switch_pending_;
            switch_pending_.reset();
            last_key_at_ms_ = now_ms;
            ++stats_.renegotiations;
        }
        if (retiring_ && now_ms >= retiring_->at_ms) retire_key(retiring_->key_id);
        if (reneg_pending_ || switch_pending_) {
            const KeyState* r = find_state(reneg_pending_ ? *reneg_pending_ : *switch_pending_);
            if (r == nullptr || now_ms >= r->started_ms + cfg_.reneg_timeout_ms) abandon_reneg("renegotiation timed out");
        } else if (cfg_.reneg_interval_ms != 0 && now_ms >= last_key_at_ms_ + cfg_.reneg_interval_ms) {
            if (!begin_reneg(next_key_id(tx_key_id_))) last_key_at_ms_ = now_ms;
        }
    }

    std::vector<uint8_t> ids;
    for (const auto& kv : states_) ids.push_back(kv.first);
    for (const uint8_t id : ids) {
        KeyState* ks = find_state(id);
        if (ks == nullptr) continue;
        while (!ks->backlog.empty() && ks->sender.can_send()) {
            uint32_t mid = 0;
            ks->sender.enqueue(op(OvpnOpcode::ControlV1), std::move(ks->backlog.front()), mid);
            ks->backlog.erase(ks->backlog.begin());
        }
        const auto due = ks->sender.due(now_ms);
        if (ks->sender.failed()) {
            if (ks->initial) { close("control channel timeout: no acknowledgement from the client"); return out; }
            if ((reneg_pending_ && *reneg_pending_ == id) || (switch_pending_ && *switch_pending_ == id)) abandon_reneg("no acknowledgement from the client");
            continue;
        }
        for (const auto& o : due) {
            ControlPacket p = base_packet(*ks);
            p.opcode = o.opcode;
            p.has_message = true;
            p.message_id = o.id;
            p.payload = o.payload;
            p.acks = ks->receiver.take_acks(kMaxAcksPerPacket);
            std::vector<uint8_t> dg;
            if (seal_control_packet(channel_, p, unix_s, dg)) {
                out.push_back(std::move(dg));
                ++stats_.datagrams_out;
                if (o.attempt > 1) ++stats_.retransmits;
            }
        }
        while (ks->receiver.has_pending_acks()) {
            ControlPacket p = base_packet(*ks);
            p.opcode = op(OvpnOpcode::AckV1);
            p.acks = ks->receiver.take_acks(kMaxAcksPerPacket);
            std::vector<uint8_t> dg;
            if (seal_control_packet(channel_, p, unix_s, dg)) {
                out.push_back(std::move(dg));
                ++stats_.datagrams_out;
            }
        }
    }
    return out;
}

std::optional<uint64_t> ControlServer::next_wakeup_ms() const {
    if (state_ == State::Closed || state_ == State::WaitReset) return std::nullopt;
    std::optional<uint64_t> best;
    auto consider = [&](uint64_t t) { if (!best || t < *best) best = t; };
    for (const auto& kv : states_) {
        const KeyState& ks = *kv.second;
        if (!ks.backlog.empty() || ks.receiver.has_pending_acks()) return 0;
        if (auto d = ks.sender.next_deadline_ms()) consider(*d);
    }
    switch (state_) {
        case State::TlsHandshake: case State::KeyExchange: case State::AuthPending: consider(hand_deadline_ms_); break;
        case State::Rejected: consider(linger_until_ms_); break;
        case State::Established:
            if ((push_sent_ && !data_ready_ && flushed(0)) || (switch_pending_ && flushed(*switch_pending_))) return 0;
            if (retiring_) consider(retiring_->at_ms);
            if (reneg_pending_ || switch_pending_) {
                if (const auto it = states_.find(reneg_pending_ ? *reneg_pending_ : *switch_pending_); it != states_.end())
                    consider(it->second->started_ms + cfg_.reneg_timeout_ms);
            } else if (cfg_.reneg_interval_ms != 0) {
                consider(last_key_at_ms_ + cfg_.reneg_interval_ms);
            }
            break;
        default: break;
    }
    return best;
}

}  // namespace pf

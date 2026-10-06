#include "pf/control_client.h"

#include <openssl/rand.h>

#include <algorithm>
#include <cstring>

#include "pf/secure_mem.h"

namespace pf {

std::string default_client_options() {
    return "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,"
           "key-method 2,tls-client";
}

// IV_VER states the protocol level we implement (2.6), not that this is the OpenVPN program.
std::string default_peer_info() {
    return "IV_VER=2.6.0\nIV_PLAT=linux\nIV_PROTO=14\nIV_CIPHERS=AES-256-GCM\n";
}

namespace {

void default_random(uint8_t* p, size_t n) {
    if (RAND_bytes(p, static_cast<int>(n)) != 1) std::memset(p, 0, n);   // failure is caught by the all-zero check below
}

bool all_zero(const uint8_t* p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc = static_cast<uint8_t>(acc | p[i]);
    return acc == 0;
}

constexpr uint8_t op(OvpnOpcode o) { return static_cast<uint8_t>(o); }

}  // namespace

ControlClient::ControlClient(ControlClientConfig cfg)
    : cfg_(std::move(cfg)), channel_(derive_tls_crypt_keys(cfg_.tls_crypt_key, TlsCryptRole::Client)) {
    secure_zero(cfg_.tls_crypt_key.data(), cfg_.tls_crypt_key.size());   // channel_ holds what it needs
}

ControlClient::~ControlClient() { secure_zero(cfg_.password.data(), cfg_.password.size()); }

std::unique_ptr<ControlClient> ControlClient::create(ControlClientConfig cfg, std::string& error) {
    if (cfg.tls.role != TlsRole::Client) { error = "ControlClient needs a TLS client configuration"; return nullptr; }
    if (cfg.max_payload < 16) { error = "max_payload too small"; return nullptr; }
    if (cfg.username.empty() && !cfg.password.empty()) { error = "a password needs a username"; return nullptr; }
    if (!cfg.random) cfg.random = default_random;
    std::unique_ptr<ControlClient> c(new ControlClient(std::move(cfg)));
    // Validate the TLS configuration once up front; each key state builds its own session from it.
    if (TlsSession::create(c->cfg_.tls, error) == nullptr) return nullptr;
    c->cfg_.random(c->my_sid_.data(), c->my_sid_.size());
    if (all_zero(c->my_sid_.data(), c->my_sid_.size())) { error = "random source failed"; return nullptr; }
    return c;
}

void ControlClient::fail(const std::string& why, FailureKind kind) {
    if (state_ == State::Failed) return;
    state_ = State::Failed;
    reason_ = why;
    failure_kind_ = kind;
}

ControlClient::KeyState* ControlClient::find_state(uint8_t key_id) {
    auto it = states_.find(key_id);
    return it == states_.end() ? nullptr : it->second.get();
}

ControlClient::KeyState* ControlClient::add_state(uint8_t key_id, bool initial) {
    auto ks = std::make_unique<KeyState>(key_id, initial, cfg_.reliable);
    std::string err;
    ks->tls = TlsSession::create(!initial && cfg_.reneg_override_for_test.tls ? *cfg_.reneg_override_for_test.tls : cfg_.tls, err);
    if (!ks->tls) return nullptr;
    ks->started_ms = now_ms_;
    KeyState* raw = ks.get();
    states_[key_id] = std::move(ks);
    return raw;
}

ControlPacket ControlClient::base_packet(const KeyState& ks) const {
    ControlPacket p;
    p.key_id = ks.key_id;
    p.session_id = my_sid_;
    p.remote_session_id = server_sid_;
    return p;
}

void ControlClient::start(uint64_t now_ms, uint32_t) {
    if (state_ != State::Idle) return;
    now_ms_ = now_ms;
    KeyState* ks = add_state(0, /*initial=*/true);
    if (ks == nullptr) { fail("cannot create TLS session"); return; }
    uint32_t id = 0;
    ks->sender.enqueue(op(OvpnOpcode::ControlHardResetClientV2), {}, id);
    state_ = State::ResetSent;
}

bool ControlClient::on_datagram(const uint8_t* data, size_t len, uint64_t now_ms, uint32_t) {
    now_ms_ = now_ms;
    ControlPacket p;
    switch (open_control_packet(channel_, data, len, p)) {
        case OpenControlStatus::NotControl: ++stats_.not_control; return false;
        case OpenControlStatus::AuthFailed: ++stats_.auth_failed; return true;
        case OpenControlStatus::Replay: ++stats_.replays; return true;
        case OpenControlStatus::Malformed: ++stats_.malformed; return true;
        case OpenControlStatus::Ok: break;
    }
    if (state_ == State::Idle || state_ == State::Failed) return true;

    // Session binding: the first accepted packet must be the server's reset (message id 0). If it carries acks they
    // must name OUR session. A retransmitted reset legitimately carries no ack (acks are sent once, so a lost first
    // reply leaves its retransmission without one), hence acks are verified when present, not required.
    if (!have_server_sid_) {
        if (p.opcode != op(OvpnOpcode::ControlHardResetServerV2) || !p.has_message || p.message_id != 0 ||
            (!p.acks.empty() && p.remote_session_id != my_sid_)) {
            ++stats_.wrong_session;
            return true;
        }
        server_sid_ = p.session_id;
        have_server_sid_ = true;
    } else {
        if (p.session_id != server_sid_ || (!p.acks.empty() && p.remote_session_id != my_sid_)) {
            ++stats_.wrong_session;
            return true;
        }
    }

    KeyState* ks = find_state(p.key_id);
    if (ks == nullptr) {
        // Only a SOFT_RESET for exactly the next key_id, once the session is up and no renegotiation is running, may
        // create key state (a peer-initiated renegotiation). Anything else is dropped without allocating anything.
        if (p.opcode == op(OvpnOpcode::ControlSoftResetV1) && state_ == State::Established && !reneg_pending_ &&
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
            KeyState* cur = find_state(key_id);               // a handler may abandon/retire this state
            if (cur == nullptr || state_ == State::Failed) break;
            const uint8_t o = cur->opcodes[m.id];
            cur->opcodes.erase(m.id);
            handle_message(*cur, o, m.payload);
        }
    }
    return true;
}

void ControlClient::handle_message(KeyState& ks, uint8_t opcode, const std::vector<uint8_t>& payload) {
    if (opcode == op(OvpnOpcode::ControlHardResetServerV2)) {
        if (ks.initial && state_ == State::ResetSent) { state_ = State::TlsHandshake; ks.tls_started = true; pump_tls(ks); }
    } else if (opcode == op(OvpnOpcode::ControlSoftResetV1)) {
        if (!ks.initial && !ks.tls_started) { ks.tls_started = true; pump_tls(ks); }   // we are the TLS client: send ClientHello
    } else if (opcode == op(OvpnOpcode::ControlV1)) {
        if (!ks.tls_started) return;                           // TLS data before the reset: nothing to do with it
        ks.tls->feed(payload.data(), payload.size());
        pump_tls(ks);
    }
}

void ControlClient::flush_tls_output(KeyState& ks) {
    std::vector<uint8_t> out = ks.tls->take_output();
    for (size_t i = 0; i < out.size(); i += cfg_.max_payload) {
        const size_t n = std::min(cfg_.max_payload, out.size() - i);
        ks.backlog.emplace_back(out.begin() + static_cast<std::ptrdiff_t>(i), out.begin() + static_cast<std::ptrdiff_t>(i + n));
    }
}

void ControlClient::pump_tls(KeyState& ks) {
    const uint8_t key_id = ks.key_id;
    const bool initial = ks.initial;
    ks.tls->step();
    flush_tls_output(ks);                                      // also carries a final alert on failure
    if (ks.tls->state() == TlsSession::State::Failed) {
        const std::string why = "TLS: " + ks.tls->failure_reason();
        if (initial) fail(why); else abandon_reneg(why);
        return;
    }
    if (ks.tls->state() != TlsSession::State::Established) return;

    if (!ks.km_sent) send_key_method(ks);
    const std::vector<uint8_t> in = ks.tls->read();
    if (ks.tls->state() == TlsSession::State::Failed) {
        const std::string why = "TLS: " + ks.tls->failure_reason();
        if (initial) fail(why); else abandon_reneg(why);
        return;
    }
    KeyState* cur = find_state(key_id);
    if (cur == nullptr) return;
    cur->app_in.insert(cur->app_in.end(), in.begin(), in.end());
    process_app_stream(*cur);
}

void ControlClient::send_key_method(KeyState& ks) {
    KeyMethod2Message m;
    cfg_.random(m.pre_master.data(), m.pre_master.size());     // exchanged, unused with tls-ekm
    cfg_.random(m.random1.data(), m.random1.size());
    cfg_.random(m.random2.data(), m.random2.size());
    m.options = cfg_.options_string;
    m.peer_info = cfg_.peer_info;
    m.username = !ks.initial && cfg_.reneg_override_for_test.username ? *cfg_.reneg_override_for_test.username : cfg_.username;
    m.password = cfg_.password;
    std::vector<uint8_t> w;
    const bool built = build_key_method2(m, KeyMethod2From::Client, w);
    secure_zero(m.password.data(), m.password.size());
    if (!built) {
        if (ks.initial) fail("cannot build key-method 2 message"); else abandon_reneg("cannot build key-method 2 message");
        return;
    }
    ks.tls->write(w.data(), w.size());
    secure_zero(m.pre_master.data(), m.pre_master.size());
    secure_zero(w.data(), w.size());
    flush_tls_output(ks);
    ks.km_sent = true;
    if (ks.initial) state_ = State::KeyExchange;
}

void ControlClient::send_control_string(KeyState& ks, const std::string& s) {
    std::vector<uint8_t> b(s.begin(), s.end());
    b.push_back(0);
    ks.tls->write(b.data(), b.size());
    flush_tls_output(ks);
}

void ControlClient::process_app_stream(KeyState& ks) {
    const uint8_t key_id = ks.key_id;
    const bool initial = ks.initial;
    for (;;) {
        if (state_ == State::Failed) return;
        KeyState* cur = find_state(key_id);
        if (cur == nullptr) return;
        KeyState& k = *cur;
        if (!k.km_done) {
            KeyMethod2Message m;
            size_t used = 0;
            const KeyMethod2Status st =
                parse_key_method2(k.app_in.data(), k.app_in.size(), KeyMethod2From::Server, m, used, cfg_.server_km2_optional_fields);
            if (st == KeyMethod2Status::Truncated) return;
            if (st != KeyMethod2Status::Ok) {
                if (initial) fail("invalid key-method 2 message from server"); else abandon_reneg("invalid key-method 2 message from server");
                return;
            }
            k.app_in.erase(k.app_in.begin(), k.app_in.begin() + static_cast<std::ptrdiff_t>(used));
            k.km_done = true;
            if (!initial) { finish_reneg(k); return; }        // a renegotiation carries no PUSH
            server_options_ = m.options;
            std::string expect = cfg_.options_string;
            const size_t pos = expect.rfind("tls-client");
            if (pos != std::string::npos) expect.replace(pos, 10, "tls-server");
            if (m.options != expect) warnings_.push_back("server options differ from the expected string: " + m.options);
            state_ = State::WaitPush;
            push_request_at_ = now_ms_ + cfg_.push_request_delay_ms;
            push_fail_at_ = now_ms_ + cfg_.push_timeout_ms;
            continue;
        }
        const auto nul = std::find(k.app_in.begin(), k.app_in.end(), uint8_t(0));
        if (nul == k.app_in.end()) return;
        const std::string msg(k.app_in.begin(), nul);
        k.app_in.erase(k.app_in.begin(), nul + 1);
        handle_control_message(k, msg);
    }
}

void ControlClient::handle_control_message(KeyState& ks, const std::string& msg) {
    switch (classify_control_message(msg)) {
        case ControlMessageKind::PushReply: {
            if (!ks.initial || state_ == State::Established) return;   // duplicate, or not on the initial key
            PushReply r;
            if (parse_push_reply(msg, r) != PushStatus::Ok) { fail("malformed PUSH_REPLY"); return; }
            if (!r.supported_by_mvp()) { fail("server push is outside the supported profile (need AES-256-GCM, tls-ekm, subnet, ifconfig, peer-id)"); return; }
            push_ = std::move(r);
            if (!install_keys(ks)) { fail("data key derivation failed"); return; }
            tx_key_id_ = ks.key_id;
            last_key_at_ms_ = now_ms_;
            state_ = State::Established;
            return;
        }
        case ControlMessageKind::AuthFailed: fail("AUTH_FAILED: " + msg); return;
        case ControlMessageKind::Restart: fail("server sent RESTART: " + msg); return;
        case ControlMessageKind::Halt: fail("server sent HALT: " + msg); return;
        default: ++stats_.ignored_control_messages; return;    // INFO, PUSH_REQUEST from a server, unknown: ignore
    }
}

bool ControlClient::install_keys(KeyState& ks) {
    DataKey tx, rx;
    if (!derive_data_keys_ekm(*ks.tls, cfg_.ekm, TlsRole::Client, tx, rx)) return false;
    if (cfg_.keys == nullptr) return true;                     // caller only wants the control channel
    const KeyRef tr = cfg_.keys->add(tx), rr = cfg_.keys->add(rx);
    if (!cfg_.keys->bind_tx(ks.key_id, tr) || !cfg_.keys->bind_rx(ks.key_id, rr)) {
        cfg_.keys->remove(tr);
        cfg_.keys->remove(rr);
        return false;
    }
    ks.tx_ref = tr;
    ks.rx_ref = rr;
    return true;
}

bool ControlClient::begin_reneg(uint8_t key_id) {
    if (state_ != State::Established || reneg_pending_) return false;
    KeyState* ks = add_state(key_id, /*initial=*/false);
    if (ks == nullptr) return false;
    uint32_t id = 0;
    ks->sender.enqueue(op(OvpnOpcode::ControlSoftResetV1), {}, id);   // message 0 of this key_id; the peer's reset answers it
    reneg_pending_ = key_id;
    return true;
}

void ControlClient::finish_reneg(KeyState& ks) {
    const uint8_t id = ks.key_id;
    if (!install_keys(ks)) { abandon_reneg("data key derivation failed"); return; }

    // The previous key keeps working for RECEIVING (packets already in flight) until the grace period ends. A key that
    // was still retiring from an earlier renegotiation goes right now: at most one old key is ever kept.
    if (retiring_) retire_key(retiring_->key_id);
    const uint8_t previous = tx_key_id_;
    tx_key_id_ = id;
    retiring_ = Retiring{previous, now_ms_ + cfg_.old_key_grace_ms};
    reneg_pending_.reset();
    last_key_at_ms_ = now_ms_;
    ++stats_.renegotiations;
}

void ControlClient::abandon_reneg(const std::string&) {
    if (!reneg_pending_) return;
    states_.erase(*reneg_pending_);
    reneg_pending_.reset();
    ++stats_.reneg_failures;
    last_key_at_ms_ = now_ms_;                                 // back off a full interval before we start another ourselves
}

void ControlClient::retire_key(uint8_t key_id) {
    KeyState* ks = find_state(key_id);
    if (ks != nullptr) {
        if (cfg_.keys != nullptr) {
            if (ks->tx_ref.valid()) cfg_.keys->remove(ks->tx_ref);
            if (ks->rx_ref.valid()) cfg_.keys->remove(ks->rx_ref);
        }
        states_.erase(key_id);
    }
    if (retiring_ && retiring_->key_id == key_id) retiring_.reset();
}

std::vector<std::vector<uint8_t>> ControlClient::poll(uint64_t now_ms, uint32_t unix_s) {
    std::vector<std::vector<uint8_t>> out;
    now_ms_ = now_ms;
    if (state_ == State::Idle || state_ == State::Failed) return out;

    if (state_ == State::WaitPush) {
        if (now_ms >= push_fail_at_) { fail("timed out waiting for PUSH_REPLY", FailureKind::Unreachable); return out; }
        if (!push_requested_ && now_ms >= push_request_at_) {
            if (KeyState* init = find_state(0)) { push_requested_ = true; send_control_string(*init, "PUSH_REQUEST"); }
        }
    }

    // Key lifecycle timers.
    if (retiring_ && now_ms >= retiring_->at_ms) retire_key(retiring_->key_id);
    if (reneg_pending_) {
        const KeyState* r = find_state(*reneg_pending_);
        if (r == nullptr || now_ms >= r->started_ms + cfg_.reneg_timeout_ms) abandon_reneg("renegotiation timed out");
    } else if (state_ == State::Established && cfg_.reneg_interval_ms != 0 && now_ms >= last_key_at_ms_ + cfg_.reneg_interval_ms) {
        if (!begin_reneg(next_key_id(tx_key_id_))) last_key_at_ms_ = now_ms;   // could not start: try again later
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
            if (ks->initial) { fail("control channel timeout: no acknowledgement from the server", FailureKind::Unreachable); return out; }
            if (reneg_pending_ && *reneg_pending_ == id) abandon_reneg("renegotiation timed out");
            continue;                                          // a retiring key's state just stops sending
        }
        for (const auto& o : due) {
            ControlPacket p = base_packet(*ks);
            p.opcode = o.opcode;
            p.has_message = true;
            p.message_id = o.id;
            p.payload = o.payload;
            if (have_server_sid_) p.acks = ks->receiver.take_acks(kMaxAcksPerPacket);
            std::vector<uint8_t> dg;
            if (seal_control_packet(channel_, p, unix_s, dg)) {
                out.push_back(std::move(dg));
                ++stats_.datagrams_out;
                if (o.attempt > 1) ++stats_.retransmits;
            }
        }
        while (have_server_sid_ && ks->receiver.has_pending_acks()) {
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

std::optional<uint64_t> ControlClient::next_wakeup_ms() const {
    if (state_ == State::Idle || state_ == State::Failed) return std::nullopt;
    std::optional<uint64_t> best;
    auto consider = [&](uint64_t t) { if (!best || t < *best) best = t; };
    for (const auto& kv : states_) {
        const KeyState& ks = *kv.second;
        if (!ks.backlog.empty() || ks.receiver.has_pending_acks()) return 0;
        if (auto d = ks.sender.next_deadline_ms()) consider(*d);
    }
    if (state_ == State::WaitPush) consider(push_requested_ ? push_fail_at_ : std::min(push_request_at_, push_fail_at_));
    if (retiring_) consider(retiring_->at_ms);
    if (reneg_pending_) {
        if (const auto it = states_.find(*reneg_pending_); it != states_.end()) consider(it->second->started_ms + cfg_.reneg_timeout_ms);
    } else if (state_ == State::Established && cfg_.reneg_interval_ms != 0) {
        consider(last_key_at_ms_ + cfg_.reneg_interval_ms);
    }
    return best;
}

bool ControlClient::export_ekm_for_probe(bool empty_context, uint8_t* out, size_t n) const {
    static const uint8_t kEmpty = 0;
    const auto it = states_.find(tx_key_id_);
    if (it == states_.end()) return false;
    return it->second->tls->export_keying_material(kOpenVpnEkmLabel, empty_context ? &kEmpty : nullptr, 0, out, n);
}

}  // namespace pf

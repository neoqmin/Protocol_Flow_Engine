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
    : cfg_(std::move(cfg)),
      channel_(derive_tls_crypt_keys(cfg_.tls_crypt_key, TlsCryptRole::Client)),
      sender_(cfg_.reliable),
      receiver_(cfg_.reliable) {
    secure_zero(cfg_.tls_crypt_key.data(), cfg_.tls_crypt_key.size());   // channel_ holds what it needs
}

std::unique_ptr<ControlClient> ControlClient::create(ControlClientConfig cfg, std::string& error) {
    if (cfg.tls.role != TlsRole::Client) { error = "ControlClient needs a TLS client configuration"; return nullptr; }
    if (cfg.max_payload < 16) { error = "max_payload too small"; return nullptr; }
    if (!cfg.random) cfg.random = default_random;
    std::unique_ptr<ControlClient> c(new ControlClient(std::move(cfg)));
    c->tls_ = TlsSession::create(c->cfg_.tls, error);
    if (!c->tls_) return nullptr;
    c->cfg_.random(c->my_sid_.data(), c->my_sid_.size());
    if (all_zero(c->my_sid_.data(), c->my_sid_.size())) { error = "random source failed"; return nullptr; }
    return c;
}

void ControlClient::fail(const std::string& why) {
    if (state_ == State::Failed) return;
    state_ = State::Failed;
    reason_ = why;
}

ControlPacket ControlClient::base_packet() const {
    ControlPacket p;
    p.key_id = 0;
    p.session_id = my_sid_;
    p.remote_session_id = server_sid_;
    return p;
}

void ControlClient::start(uint64_t now_ms, uint32_t) {
    if (state_ != State::Idle) return;
    now_ms_ = now_ms;
    uint32_t id = 0;
    sender_.enqueue(op(OvpnOpcode::ControlHardResetClientV2), {}, id);
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

    if (!p.acks.empty()) sender_.on_ack(p.acks.data(), p.acks.size());
    if (p.has_message) {
        opcodes_[p.message_id] = p.opcode;
        std::vector<ReliableReceiver::Delivered> delivered;
        receiver_.on_message(p.message_id, p.payload, delivered);
        for (const auto& m : delivered) {
            const uint8_t o = opcodes_[m.id];
            opcodes_.erase(m.id);
            handle_message(o, m.payload);
            if (state_ == State::Failed) break;
        }
    }
    return true;
}

void ControlClient::handle_message(uint8_t opcode, const std::vector<uint8_t>& payload) {
    if (opcode == op(OvpnOpcode::ControlHardResetServerV2)) {
        if (state_ == State::ResetSent) { state_ = State::TlsHandshake; pump_tls(); }
    } else if (opcode == op(OvpnOpcode::ControlV1)) {
        if (state_ == State::ResetSent) return;               // TLS data before the server's reset: nothing to do with it
        tls_->feed(payload.data(), payload.size());
        pump_tls();
    } else if (opcode == op(OvpnOpcode::ControlSoftResetV1)) {
        ++stats_.ignored_soft_resets;                          // renegotiation is handled in a later step
    }
}

void ControlClient::flush_tls_output() {
    std::vector<uint8_t> out = tls_->take_output();
    for (size_t i = 0; i < out.size(); i += cfg_.max_payload) {
        const size_t n = std::min(cfg_.max_payload, out.size() - i);
        tx_backlog_.emplace_back(out.begin() + static_cast<std::ptrdiff_t>(i), out.begin() + static_cast<std::ptrdiff_t>(i + n));
    }
}

void ControlClient::pump_tls() {
    tls_->step();
    flush_tls_output();                                        // also carries a final alert on failure
    if (tls_->state() == TlsSession::State::Failed) { fail("TLS: " + tls_->failure_reason()); return; }
    if (tls_->state() != TlsSession::State::Established) return;

    if (!km_sent_) send_key_method();
    const std::vector<uint8_t> in = tls_->read();
    if (tls_->state() == TlsSession::State::Failed) { fail("TLS: " + tls_->failure_reason()); return; }
    app_in_.insert(app_in_.end(), in.begin(), in.end());
    process_app_stream();
}

void ControlClient::send_key_method() {
    KeyMethod2Message m;
    cfg_.random(m.pre_master.data(), m.pre_master.size());     // exchanged, unused with tls-ekm
    cfg_.random(m.random1.data(), m.random1.size());
    cfg_.random(m.random2.data(), m.random2.size());
    m.options = cfg_.options_string;
    m.peer_info = cfg_.peer_info;
    std::vector<uint8_t> w;
    if (!build_key_method2(m, KeyMethod2From::Client, w)) { fail("cannot build key-method 2 message"); return; }
    tls_->write(w.data(), w.size());
    secure_zero(m.pre_master.data(), m.pre_master.size());
    secure_zero(w.data(), w.size());
    flush_tls_output();
    km_sent_ = true;
    state_ = State::KeyExchange;
}

void ControlClient::send_control_string(const std::string& s) {
    std::vector<uint8_t> b(s.begin(), s.end());
    b.push_back(0);
    tls_->write(b.data(), b.size());
    flush_tls_output();
}

void ControlClient::process_app_stream() {
    for (;;) {
        if (state_ == State::Failed) return;
        if (!km_done_) {
            KeyMethod2Message m;
            size_t used = 0;
            const KeyMethod2Status st =
                parse_key_method2(app_in_.data(), app_in_.size(), KeyMethod2From::Server, m, used, cfg_.server_km2_optional_fields);
            if (st == KeyMethod2Status::Truncated) return;
            if (st != KeyMethod2Status::Ok) { fail("invalid key-method 2 message from server"); return; }
            app_in_.erase(app_in_.begin(), app_in_.begin() + static_cast<std::ptrdiff_t>(used));
            km_done_ = true;
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
        const auto nul = std::find(app_in_.begin(), app_in_.end(), uint8_t(0));
        if (nul == app_in_.end()) return;
        const std::string msg(app_in_.begin(), nul);
        app_in_.erase(app_in_.begin(), nul + 1);
        handle_control_message(msg);
    }
}

void ControlClient::handle_control_message(const std::string& msg) {
    switch (classify_control_message(msg)) {
        case ControlMessageKind::PushReply: {
            if (state_ == State::Established) return;          // duplicate
            PushReply r;
            if (parse_push_reply(msg, r) != PushStatus::Ok) { fail("malformed PUSH_REPLY"); return; }
            if (!r.supported_by_mvp()) { fail("server push is outside the supported profile (need AES-256-GCM, tls-ekm, subnet, ifconfig, peer-id)"); return; }
            push_ = std::move(r);
            if (!install_keys()) { fail("data key derivation failed"); return; }
            state_ = State::Established;
            return;
        }
        case ControlMessageKind::AuthFailed: fail("AUTH_FAILED: " + msg); return;
        case ControlMessageKind::Restart: fail("server sent RESTART: " + msg); return;
        case ControlMessageKind::Halt: fail("server sent HALT: " + msg); return;
        default: return;                                       // INFO, PUSH_REQUEST from a server, unknown: ignore
    }
}

bool ControlClient::install_keys() {
    DataKey tx, rx;
    if (!derive_data_keys_ekm(*tls_, cfg_.ekm, TlsRole::Client, tx, rx)) return false;
    if (cfg_.keys == nullptr) return true;                     // caller only wants the control channel
    const KeyRef tr = cfg_.keys->add(tx), rr = cfg_.keys->add(rx);
    return cfg_.keys->bind_tx(0, tr) && cfg_.keys->bind_rx(0, rr);
}

std::vector<std::vector<uint8_t>> ControlClient::poll(uint64_t now_ms, uint32_t unix_s) {
    std::vector<std::vector<uint8_t>> out;
    now_ms_ = now_ms;
    if (state_ == State::Idle || state_ == State::Failed) return out;

    if (state_ == State::WaitPush) {
        if (now_ms >= push_fail_at_) { fail("timed out waiting for PUSH_REPLY"); return out; }
        if (!push_requested_ && now_ms >= push_request_at_) { push_requested_ = true; send_control_string("PUSH_REQUEST"); }
    }

    while (!tx_backlog_.empty() && sender_.can_send()) {
        uint32_t id = 0;
        sender_.enqueue(op(OvpnOpcode::ControlV1), std::move(tx_backlog_.front()), id);
        tx_backlog_.erase(tx_backlog_.begin());
    }

    const auto due = sender_.due(now_ms);
    if (sender_.failed()) { fail("control channel timeout: no acknowledgement from the server"); return out; }
    for (const auto& o : due) {
        ControlPacket p = base_packet();
        p.opcode = o.opcode;
        p.has_message = true;
        p.message_id = o.id;
        p.payload = o.payload;
        if (have_server_sid_) p.acks = receiver_.take_acks(kMaxAcksPerPacket);
        std::vector<uint8_t> dg;
        if (seal_control_packet(channel_, p, unix_s, dg)) {
            out.push_back(std::move(dg));
            ++stats_.datagrams_out;
            if (o.attempt > 1) ++stats_.retransmits;
        }
    }
    while (have_server_sid_ && receiver_.has_pending_acks()) {
        ControlPacket p = base_packet();
        p.opcode = op(OvpnOpcode::AckV1);
        p.acks = receiver_.take_acks(kMaxAcksPerPacket);
        std::vector<uint8_t> dg;
        if (seal_control_packet(channel_, p, unix_s, dg)) {
            out.push_back(std::move(dg));
            ++stats_.datagrams_out;
        }
    }
    return out;
}

std::optional<uint64_t> ControlClient::next_wakeup_ms() const {
    if (state_ == State::Idle || state_ == State::Failed) return std::nullopt;
    if (!tx_backlog_.empty() || receiver_.has_pending_acks()) return 0;
    std::optional<uint64_t> best = sender_.next_deadline_ms();
    if (state_ == State::WaitPush) {
        const uint64_t t = push_requested_ ? push_fail_at_ : std::min(push_request_at_, push_fail_at_);
        if (!best || t < *best) best = t;
    }
    return best;
}

}  // namespace pf

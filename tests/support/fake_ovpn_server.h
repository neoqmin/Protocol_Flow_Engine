// A minimal, deterministic stand-in for an OpenVPN 2.6 server's CONTROL plane, built from the same verified pieces
// (tls-crypt, control packets, reliability, TLS, key-method 2). It lets ControlClient be tested hermetically in CI.
// It proves internal consistency, NOT compatibility: compatibility is established against the real server
// (tools/interop, tests/protocol). Needs OpenSSL.
#pragma once
#include <array>
#include <algorithm>
#include <cstring>
#include <map>
#include <stdexcept>
#include <memory>
#include <string>
#include <vector>

#include "pf/control_packet.h"
#include "pf/crypto/control_wire.h"
#include "pf/crypto/data_key_derivation.h"
#include "pf/crypto/tls_session.h"
#include "pf/key_method2.h"
#include "pf/key_store.h"
#include "pf/reliable.h"

namespace pf_test {

struct FakeServerConfig {
    std::array<uint8_t, pf::kTlsCryptStaticKeyLen> static_key{};
    pf::TlsConfig tls;                                   // server role
    std::string push_reply =
        "PUSH_REPLY,route-gateway 10.77.0.1,topology subnet,ping 2,ping-restart 8,"
        "ifconfig 10.77.0.2 255.255.255.0,peer-id 7,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm,tun-mtu 1500";
    bool push_without_request = true;                    // REQUEST_PUSH semantics: reply right after key exchange
    bool send_push = true;                               // false: never reply (client must give up / ask)
    size_t km2_optional_fields = 2;                      // username+password (peer info omitted), like the real server (assumed)
    pf::EkmLayout layout;
    pf::ReliableConfig reliable;
    std::string send_instead_of_push;                    // if set, send this control message instead (e.g. AUTH_FAILED)
    bool corrupt_key_method = false;                     // send a key-method 2 message with a bad literal-zero header
};

class FakeServer {
public:
    explicit FakeServer(FakeServerConfig cfg)
        : cfg_(std::move(cfg)),
          channel_(pf::derive_tls_crypt_keys(cfg_.static_key, pf::TlsCryptRole::Server)),
          sender_(cfg_.reliable), receiver_(cfg_.reliable) {
        std::string err;
        tls_ = pf::TlsSession::create(cfg_.tls, err);
        if (!tls_) throw std::runtime_error("FakeServer: " + err);
        server_sid_ = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};
    }

    std::vector<std::vector<uint8_t>> on_datagram(const uint8_t* d, size_t n, uint64_t now_ms, uint32_t unix_s) {
        pf::ControlPacket p;
        switch (pf::open_control_packet(channel_, d, n, p)) {
            case pf::OpenControlStatus::Ok: break;
            case pf::OpenControlStatus::AuthFailed: ++auth_failed; return poll(now_ms, unix_s);
            case pf::OpenControlStatus::Replay: ++replays; return poll(now_ms, unix_s);
            default: return poll(now_ms, unix_s);
        }
        if (!have_client_sid_) {
            if (p.opcode != static_cast<uint8_t>(pf::OvpnOpcode::ControlHardResetClientV2)) return poll(now_ms, unix_s);
            client_sid_ = p.session_id; have_client_sid_ = true;
            uint32_t id; sender_.enqueue(static_cast<uint8_t>(pf::OvpnOpcode::ControlHardResetServerV2), {}, id);
        } else if (p.session_id != client_sid_) {
            return poll(now_ms, unix_s);
        }
        if (!p.acks.empty()) {
            if (p.remote_session_id != server_sid_) { ++wrong_remote_sid; return poll(now_ms, unix_s); }
            sender_.on_ack(p.acks.data(), p.acks.size());
        }
        if (p.has_message) {
            std::vector<pf::ReliableReceiver::Delivered> out;
            opcodes_[p.message_id] = p.opcode;
            receiver_.on_message(p.message_id, p.payload, out);
            for (auto& m : out) {
                const uint8_t op = opcodes_[m.id]; opcodes_.erase(m.id);
                if (op == static_cast<uint8_t>(pf::OvpnOpcode::ControlV1)) {
                    control_payload_sizes.push_back(m.payload.size());
                    tls_->feed(m.payload.data(), m.payload.size());
                    pump_tls();
                }
            }
        }
        return poll(now_ms, unix_s);
    }

    std::vector<std::vector<uint8_t>> poll(uint64_t now_ms, uint32_t unix_s) {
        std::vector<std::vector<uint8_t>> out;
        while (!backlog_.empty() && sender_.can_send()) {
            uint32_t id; sender_.enqueue(static_cast<uint8_t>(pf::OvpnOpcode::ControlV1), std::move(backlog_.front()), id);
            backlog_.erase(backlog_.begin());
        }
        for (auto& o : sender_.due(now_ms)) {
            pf::ControlPacket p = base();
            p.opcode = o.opcode; p.has_message = true; p.message_id = o.id; p.payload = o.payload;
            attach_acks(p);
            std::vector<uint8_t> dg;
            if (pf::seal_control_packet(channel_, p, unix_s, dg)) out.push_back(std::move(dg));
        }
        while (have_client_sid_ && receiver_.has_pending_acks()) {
            pf::ControlPacket p = base();
            p.opcode = static_cast<uint8_t>(pf::OvpnOpcode::AckV1);
            attach_acks(p);
            std::vector<uint8_t> dg;
            if (pf::seal_control_packet(channel_, p, unix_s, dg)) out.push_back(std::move(dg));
        }
        return out;
    }

    // ---- observations for assertions ----
    uint32_t auth_failed = 0, replays = 0, wrong_remote_sid = 0;
    std::vector<size_t> control_payload_sizes;
    bool got_key_method = false, got_push_request = false, push_sent = false;
    std::string client_options, client_peer_info;
    pf::DataKey tx_key, rx_key;      // server-side data keys (valid once derived)
    bool keys_derived = false;
    pf::TlsSession& tls() { return *tls_; }

private:
    pf::ControlPacket base() {
        pf::ControlPacket p;
        p.key_id = 0; p.session_id = server_sid_; p.remote_session_id = client_sid_;
        return p;
    }
    void attach_acks(pf::ControlPacket& p) { if (have_client_sid_) p.acks = receiver_.take_acks(pf::kMaxAcksPerPacket); }

    void flush_tls() {
        auto b = tls_->take_output();
        for (size_t i = 0; i < b.size(); i += 1100) {
            const size_t n = std::min<size_t>(1100, b.size() - i);
            backlog_.emplace_back(b.begin() + i, b.begin() + i + n);
        }
    }
    void send_app(const std::vector<uint8_t>& b) { tls_->write(b.data(), b.size()); flush_tls(); }
    void send_str(const std::string& s) { std::vector<uint8_t> b(s.begin(), s.end()); b.push_back(0); send_app(b); }

    void pump_tls() {
        tls_->step();
        flush_tls();
        if (tls_->state() != pf::TlsSession::State::Established) return;
        auto in = tls_->read();
        app_in_.insert(app_in_.end(), in.begin(), in.end());
        if (!got_key_method) {
            pf::KeyMethod2Message m; size_t used = 0;
            if (pf::parse_key_method2(app_in_.data(), app_in_.size(), pf::KeyMethod2From::Client, m, used) != pf::KeyMethod2Status::Ok) return;
            app_in_.erase(app_in_.begin(), app_in_.begin() + used);
            got_key_method = true; client_options = m.options; client_peer_info = m.peer_info;

            pf::KeyMethod2Message reply;
            for (size_t i = 0; i < 32; ++i) { reply.random1[i] = static_cast<uint8_t>(0x51 + i); reply.random2[i] = static_cast<uint8_t>(0x91 + i); }
            reply.options = m.options;
            const size_t pos = reply.options.rfind("tls-client");
            if (pos != std::string::npos) reply.options.replace(pos, 10, "tls-server");
            std::vector<uint8_t> w;
            pf::build_key_method2(reply, pf::KeyMethod2From::Server, w);
            w.resize(w.size() - 2 * (3 - cfg_.km2_optional_fields));        // drop trailing empty optional fields
            if (cfg_.corrupt_key_method) w[2] = 1;
            send_app(w);
            keys_derived = pf::derive_data_keys_ekm(*tls_, cfg_.layout, pf::TlsRole::Server, tx_key, rx_key);
            if (cfg_.send_push && cfg_.push_without_request) push_now();
        }
        // After key exchange: NUL-terminated control messages.
        for (;;) {
            auto nul = std::find(app_in_.begin(), app_in_.end(), uint8_t(0));
            if (nul == app_in_.end()) break;
            std::string msg(app_in_.begin(), nul);
            app_in_.erase(app_in_.begin(), nul + 1);
            if (msg == "PUSH_REQUEST") { got_push_request = true; if (cfg_.send_push) push_now(); }
        }
    }
    void push_now() {
        if (push_sent) return;
        push_sent = true;
        send_str(cfg_.send_instead_of_push.empty() ? cfg_.push_reply : cfg_.send_instead_of_push);
    }

    FakeServerConfig cfg_;
    pf::TlsCryptChannel channel_;
    pf::ReliableSender sender_;
    pf::ReliableReceiver receiver_;
    std::unique_ptr<pf::TlsSession> tls_;
    std::array<uint8_t, 8> server_sid_{}, client_sid_{};
    bool have_client_sid_ = false;
    std::map<uint32_t, uint8_t> opcodes_;
    std::vector<std::vector<uint8_t>> backlog_;
    std::vector<uint8_t> app_in_;
};

}  // namespace pf_test

// A minimal, deterministic stand-in for an OpenVPN 2.6 server's CONTROL plane, built from the same verified pieces
// (tls-crypt, control packets, reliability, TLS, key-method 2). It lets ControlClient be tested hermetically in CI.
// It proves internal consistency, NOT compatibility: compatibility is established against the real server
// (tools/interop, tests/protocol). Needs OpenSSL.
//
// Like OpenVPN, every key_id has its own key state: its own reliable message-id sequence (restarting at 0) and its own
// TLS session; the tls-crypt channel and the two session ids are shared by all key states.
#pragma once
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
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
    size_t km2_optional_fields = 3;                      // username, password, peer info (empty): what the real server sends (observed)
    pf::EkmLayout layout;
    pf::ReliableConfig reliable;
    std::string send_instead_of_push;                    // if set, send this control message instead (e.g. AUTH_FAILED)
    bool corrupt_key_method = false;                     // initial key exchange: bad literal-zero header

    // Renegotiation behavior.
    uint64_t reneg_after_ms = 0;                         // server starts a renegotiation this long after the previous key (0 = never)
    bool reneg_silent = false;                           // after SOFT_RESET, ignore everything on the new key_id
    bool reneg_corrupt_km = false;                       // renegotiation key exchange answered with a bad header
};

class FakeServer {
public:
    explicit FakeServer(FakeServerConfig cfg)
        : cfg_(std::move(cfg)), channel_(pf::derive_tls_crypt_keys(cfg_.static_key, pf::TlsCryptRole::Server)) {
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
        now_ = now_ms;
        if (!have_client_sid_) {
            if (p.opcode != static_cast<uint8_t>(pf::OvpnOpcode::ControlHardResetClientV2)) return poll(now_ms, unix_s);
            client_sid_ = p.session_id; have_client_sid_ = true;
            KS& k = add_state(0, /*initial=*/true);
            uint32_t id; k.sender.enqueue(static_cast<uint8_t>(pf::OvpnOpcode::ControlHardResetServerV2), {}, id);
        } else if (p.session_id != client_sid_) {
            return poll(now_ms, unix_s);
        }

        KS* k = find(p.key_id);
        if (!k) {
            // Client-initiated renegotiation: SOFT_RESET for the next key_id once the first key exchange is done.
            if (p.opcode == static_cast<uint8_t>(pf::OvpnOpcode::ControlSoftResetV1) && established_ && !pending_reneg_ &&
                p.key_id == next_key_id(current_key_id_)) {
                k = &begin_reneg(p.key_id);
                uint32_t id; k->sender.enqueue(static_cast<uint8_t>(pf::OvpnOpcode::ControlSoftResetV1), {}, id);
            } else {
                return poll(now_ms, unix_s);
            }
        }
        if (k->silent) return poll(now_ms, unix_s);

        if (!p.acks.empty()) {
            if (p.remote_session_id != server_sid_) { ++wrong_remote_sid; return poll(now_ms, unix_s); }
            k->sender.on_ack(p.acks.data(), p.acks.size());
        }
        if (p.has_message) {
            std::vector<pf::ReliableReceiver::Delivered> out;
            k->opcodes[p.message_id] = p.opcode;
            k->receiver.on_message(p.message_id, p.payload, out);
            for (auto& m : out) {
                const uint8_t op = k->opcodes[m.id]; k->opcodes.erase(m.id);
                if (op == static_cast<uint8_t>(pf::OvpnOpcode::ControlV1)) {
                    control_payload_sizes.push_back(m.payload.size());
                    k->tls->feed(m.payload.data(), m.payload.size());
                    pump_tls(*k);
                }
            }
        }
        return poll(now_ms, unix_s);
    }

    std::vector<std::vector<uint8_t>> poll(uint64_t now_ms, uint32_t unix_s) {
        now_ = now_ms;
        std::vector<std::vector<uint8_t>> out;

        // Server-initiated renegotiation.
        if (cfg_.reneg_after_ms != 0 && established_ && !pending_reneg_ && now_ms >= next_reneg_at_) {
            KS& k = begin_reneg(next_key_id(current_key_id_));
            ++renegotiations_started;
            uint32_t id; k.sender.enqueue(static_cast<uint8_t>(pf::OvpnOpcode::ControlSoftResetV1), {}, id);
            if (cfg_.reneg_silent) k.silent = true;
        }

        for (auto& [kid, up] : states_) {
            KS& k = *up;
            while (!k.backlog.empty() && k.sender.can_send()) {
                uint32_t id; k.sender.enqueue(static_cast<uint8_t>(pf::OvpnOpcode::ControlV1), std::move(k.backlog.front()), id);
                k.backlog.erase(k.backlog.begin());
            }
            for (auto& o : k.sender.due(now_ms)) {
                pf::ControlPacket p = base(k);
                p.opcode = o.opcode; p.has_message = true; p.message_id = o.id; p.payload = o.payload;
                attach_acks(k, p);
                std::vector<uint8_t> dg;
                if (pf::seal_control_packet(channel_, p, unix_s, dg)) out.push_back(std::move(dg));
            }
            while (have_client_sid_ && k.receiver.has_pending_acks()) {
                pf::ControlPacket p = base(k);
                p.opcode = static_cast<uint8_t>(pf::OvpnOpcode::AckV1);
                attach_acks(k, p);
                std::vector<uint8_t> dg;
                if (pf::seal_control_packet(channel_, p, unix_s, dg)) out.push_back(std::move(dg));
            }
        }
        return out;
    }

    // ---- observations for assertions ----
    uint32_t auth_failed = 0, replays = 0, wrong_remote_sid = 0;
    uint32_t renegotiations_started = 0, renegotiations_completed = 0;
    std::vector<size_t> control_payload_sizes;
    bool got_key_method = false, got_push_request = false, push_sent = false;
    std::string client_options, client_peer_info;
    pf::DataKey tx_key, rx_key;      // server-side data keys of the INITIAL key (valid once derived)
    bool keys_derived = false;
    struct KeyPair { pf::DataKey tx, rx; };
    std::map<uint8_t, KeyPair> keys_by_id;     // server-side data keys for every completed key exchange
    uint8_t current_key_id() const { return current_key_id_; }
    pf::TlsSession& tls() { return *find(0)->tls; }

    static uint8_t next_key_id(uint8_t k) { return k >= 7 ? 1 : static_cast<uint8_t>(k + 1); }   // 0,1,..,7,1,2,..

private:
    struct KS {
        uint8_t id;
        bool initial;
        pf::ReliableSender sender;
        pf::ReliableReceiver receiver;
        std::unique_ptr<pf::TlsSession> tls;
        std::vector<std::vector<uint8_t>> backlog;
        std::vector<uint8_t> app_in;
        std::map<uint32_t, uint8_t> opcodes;
        bool got_km = false;
        bool silent = false;
        KS(uint8_t i, bool init, const pf::ReliableConfig& rc) : id(i), initial(init), sender(rc), receiver(rc) {}
    };

    KS* find(uint8_t id) { auto it = states_.find(id); return it == states_.end() ? nullptr : it->second.get(); }

    KS& add_state(uint8_t id, bool initial) {
        auto k = std::make_unique<KS>(id, initial, cfg_.reliable);
        std::string err;
        k->tls = pf::TlsSession::create(cfg_.tls, err);
        if (!k->tls) throw std::runtime_error("FakeServer: " + err);
        KS& ref = *k;
        states_[id] = std::move(k);
        return ref;
    }
    KS& begin_reneg(uint8_t id) { pending_reneg_ = true; return add_state(id, false); }

    pf::ControlPacket base(const KS& k) {
        pf::ControlPacket p;
        p.key_id = k.id; p.session_id = server_sid_; p.remote_session_id = client_sid_;
        return p;
    }
    void attach_acks(KS& k, pf::ControlPacket& p) { if (have_client_sid_) p.acks = k.receiver.take_acks(pf::kMaxAcksPerPacket); }

    void flush_tls(KS& k) {
        auto b = k.tls->take_output();
        for (size_t i = 0; i < b.size(); i += 1100) {
            const size_t n = std::min<size_t>(1100, b.size() - i);
            k.backlog.emplace_back(b.begin() + i, b.begin() + i + n);
        }
    }
    void send_app(KS& k, const std::vector<uint8_t>& b) { k.tls->write(b.data(), b.size()); flush_tls(k); }
    void send_str(KS& k, const std::string& s) { std::vector<uint8_t> b(s.begin(), s.end()); b.push_back(0); send_app(k, b); }

    void pump_tls(KS& k) {
        k.tls->step();
        flush_tls(k);
        if (k.tls->state() != pf::TlsSession::State::Established) return;
        auto in = k.tls->read();
        k.app_in.insert(k.app_in.end(), in.begin(), in.end());
        if (!k.got_km) {
            pf::KeyMethod2Message m; size_t used = 0;
            if (pf::parse_key_method2(k.app_in.data(), k.app_in.size(), pf::KeyMethod2From::Client, m, used) != pf::KeyMethod2Status::Ok) return;
            k.app_in.erase(k.app_in.begin(), k.app_in.begin() + used);
            k.got_km = true;
            if (k.initial) { got_key_method = true; client_options = m.options; client_peer_info = m.peer_info; }

            pf::KeyMethod2Message reply;
            for (size_t i = 0; i < 32; ++i) { reply.random1[i] = static_cast<uint8_t>(0x51 + i); reply.random2[i] = static_cast<uint8_t>(0x91 + i); }
            reply.options = m.options;
            const size_t pos = reply.options.rfind("tls-client");
            if (pos != std::string::npos) reply.options.replace(pos, 10, "tls-server");
            std::vector<uint8_t> w;
            pf::build_key_method2(reply, pf::KeyMethod2From::Server, w);
            w.resize(w.size() - 2 * (3 - cfg_.km2_optional_fields));        // drop trailing empty optional fields
            if (k.initial ? cfg_.corrupt_key_method : cfg_.reneg_corrupt_km) w[2] = 1;
            send_app(k, w);

            KeyPair kp;
            if (pf::derive_data_keys_ekm(*k.tls, cfg_.layout, pf::TlsRole::Server, kp.tx, kp.rx)) keys_by_id[k.id] = kp;
            if (k.initial) {
                tx_key = kp.tx; rx_key = kp.rx; keys_derived = keys_by_id.count(k.id) != 0;
                established_ = true; current_key_id_ = k.id; next_reneg_at_ = now_ + cfg_.reneg_after_ms;
                if (cfg_.send_push && cfg_.push_without_request) push_now(k);
            } else {
                current_key_id_ = k.id; pending_reneg_ = false; ++renegotiations_completed;
                next_reneg_at_ = now_ + cfg_.reneg_after_ms;
            }
        }
        // After key exchange: NUL-terminated control messages.
        for (;;) {
            auto nul = std::find(k.app_in.begin(), k.app_in.end(), uint8_t(0));
            if (nul == k.app_in.end()) break;
            std::string msg(k.app_in.begin(), nul);
            k.app_in.erase(k.app_in.begin(), nul + 1);
            if (msg == "PUSH_REQUEST" && k.initial) { got_push_request = true; if (cfg_.send_push) push_now(k); }
        }
    }
    void push_now(KS& k) {
        if (push_sent) return;
        push_sent = true;
        send_str(k, cfg_.send_instead_of_push.empty() ? cfg_.push_reply : cfg_.send_instead_of_push);
    }

    FakeServerConfig cfg_;
    pf::TlsCryptChannel channel_;
    std::array<uint8_t, 8> server_sid_{}, client_sid_{};
    bool have_client_sid_ = false;
    std::map<uint8_t, std::unique_ptr<KS>> states_;
    bool established_ = false, pending_reneg_ = false;
    uint8_t current_key_id_ = 0;
    uint64_t now_ = 0, next_reneg_at_ = 0;
};

}  // namespace pf_test

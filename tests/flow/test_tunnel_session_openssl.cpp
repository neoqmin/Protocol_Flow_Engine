// TunnelSession (data plane + keepalive on top of ControlClient) against the deterministic fake server. Needs OpenSSL.
#include <set>

#include "control_rig.h"
#include "pf/blocks/data_plane_blocks.h"
#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/flow.h"
#include "pf/tunnel_session.h"

using namespace pf;
using namespace pf_test;

namespace {

// The server's side of the data channel. One persistent KeyStore, so packet-ids count up and replay windows are real.
struct ServerPeer {
    FakeServer& srv;
    KeyStore ks;
    BlockRegistry reg;
    Flow rx, tx;
    std::unique_ptr<AeadProvider> aead = make_openssl_aes256gcm();
    std::set<uint8_t> bound;

    explicit ServerPeer(FakeServer& s) : srv(s) {
        PF_REQUIRE(register_data_plane_blocks(reg));
        FlowBuilder r("rx");
        r.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
         .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
        auto rr = r.build(reg); PF_REQUIRE(rr.ok()); rx = std::move(rr.flow);
        FlowBuilder t("tx");
        t.add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
        auto tt = t.build(reg); PF_REQUIRE(tt.ok()); tx = std::move(tt.flow);
    }
    void sync() {                                            // pick up keys of completed key exchanges
        for (const auto& [id, kp] : srv.keys_by_id) {
            if (!bound.insert(id).second) continue;
            ks.bind_tx(id, ks.add(kp.tx));
            ks.bind_rx(id, ks.add(kp.rx));
        }
    }
    std::vector<uint8_t> seal(uint8_t key_id, const std::vector<uint8_t>& payload) {      // server -> client wire packet
        sync();
        PacketBuffer pkt = PacketBuffer::from_bytes(payload.data(), payload.size());
        FlowContext c; c.packet = &pkt; c.keys = &ks; c.aead = aead.get();
        c.header = OvpnHeader{OvpnOpcode::DataV2, key_id, 7}; c.header_valid = true;
        PF_REQUIRE(run_flow(tx, c).outcome == FlowOutcome::Completed);
        return std::vector<uint8_t>(pkt.data(), pkt.data() + pkt.size());
    }
    // client -> server wire packet; empty if the server could not authenticate it
    std::vector<uint8_t> open(const std::vector<uint8_t>& wire) {
        sync();
        PacketBuffer pkt = PacketBuffer::from_bytes(wire.data(), wire.size());
        FlowContext c; c.packet = &pkt; c.keys = &ks; c.aead = aead.get();
        if (run_flow(rx, c).outcome != FlowOutcome::Completed) return {};
        return std::vector<uint8_t>(pkt.data(), pkt.data() + pkt.size());
    }
};

// A plausible IPv4 packet (version nibble 4), `n` bytes.
std::vector<uint8_t> ip_packet(size_t n, uint8_t fill = 0x11) {
    std::vector<uint8_t> p(n, fill);
    p[0] = 0x45;
    return p;
}

struct Fixture {
    Rig r;
    Net n;
    std::unique_ptr<TunnelSession> s;
    ServerPeer peer;
    Fixture() : r(), n{*r.client, *r.server}, peer(*r.server) {
        std::string err;
        s = TunnelSession::create(*r.client, r.keys, err);
        PF_REQUIRE(s != nullptr);
    }
    Fixture(ControlClientConfig cc, FakeServerConfig sc) : r(std::move(cc), std::move(sc)), n{*r.client, *r.server}, peer(*r.server) {
        std::string err;
        s = TunnelSession::create(*r.client, r.keys, err);
        PF_REQUIRE(s != nullptr);
    }
    void establish() {
        r.client->start(n.now, n.unix_s);
        n.run(3000);
        PF_REQUIRE(r.client->state() == ControlClient::State::Established);
        s->poll(n.now, n.unix_s);                                  // the session notices Established and arms the keepalive
        PF_REQUIRE(s->established());
    }
    TunnelSession::RxKind rx(const std::vector<uint8_t>& wire, PacketBuffer& out) {
        return s->on_datagram(wire.data(), wire.size(), n.now, n.unix_s, out);
    }
};

}  // namespace

PF_TEST(tunnel_not_established_refuses_traffic) {
    Fixture f;
    std::vector<uint8_t> wire;
    const auto p = ip_packet(60);
    PF_CHECK(!f.s->encapsulate(p.data(), p.size(), f.n.now, wire));
    PF_CHECK(wire.empty());
    PF_CHECK_EQ(f.s->stats().tx_before_established, 1u);
    PF_CHECK(!f.s->established());
}

PF_TEST(tunnel_ip_packets_flow_both_ways) {
    Fixture f; f.establish();
    // client -> server: encrypted with the client's tx key, header carries key_id and the pushed peer-id
    const auto p = ip_packet(84, 0x22);
    std::vector<uint8_t> wire;
    PF_REQUIRE(f.s->encapsulate(p.data(), p.size(), f.n.now, wire));
    PF_CHECK_EQ(wire.size(), p.size() + kDataV2Overhead);
    PF_CHECK_EQ(wire[0] >> 3, static_cast<unsigned>(OvpnOpcode::DataV2));
    PF_CHECK_EQ(wire[0] & 7, 0);
    PF_CHECK_EQ((wire[1] << 16) | (wire[2] << 8) | wire[3], 7);          // peer-id from PUSH_REPLY
    PF_CHECK(f.peer.open(wire) == p);
    // server -> client
    const auto q = ip_packet(100, 0x33);
    PacketBuffer out;
    PF_CHECK(f.rx(f.peer.seal(0, q), out) == TunnelSession::RxKind::Packet);
    PF_CHECK(std::vector<uint8_t>(out.data(), out.data() + out.size()) == q);
    PF_CHECK_EQ(f.s->stats().tx_packets, 1u);
    PF_CHECK_EQ(f.s->stats().rx_packets, 1u);
    PF_CHECK_EQ(f.s->stats().rx_bytes, 100u);
}

PF_TEST(tunnel_packet_ids_increase_and_each_packet_is_unique) {
    Fixture f; f.establish();
    const auto p = ip_packet(60);
    std::set<std::vector<uint8_t>> seen;
    for (int i = 0; i < 20; ++i) {
        std::vector<uint8_t> wire;
        PF_REQUIRE(f.s->encapsulate(p.data(), p.size(), f.n.now, wire));
        PF_CHECK(f.peer.open(wire) == p);                              // server's replay window accepts them in order
        PF_CHECK(seen.insert(wire).second);                            // same plaintext, never the same ciphertext
    }
}

PF_TEST(tunnel_rejects_tampered_replayed_and_unknown_key_packets) {
    Fixture f; f.establish();
    PacketBuffer out;
    const auto good = f.peer.seal(0, ip_packet(80));
    auto bad = good; bad[bad.size() - 1] ^= 1;                          // flipped bit in the ciphertext
    PF_CHECK(f.rx(bad, out) == TunnelSession::RxKind::Dropped);
    PF_CHECK(f.rx(good, out) == TunnelSession::RxKind::Packet);        // the forged copy did not poison the window
    PF_CHECK(f.rx(good, out) == TunnelSession::RxKind::Dropped);       // replay
    auto other_key = f.peer.seal(0, ip_packet(80)); other_key[0] = static_cast<uint8_t>((other_key[0] & ~7) | 5);   // key_id 5: never negotiated
    PF_CHECK(f.rx(other_key, out) == TunnelSession::RxKind::Dropped);
    PF_CHECK_EQ(f.s->stats().rx_dropped, 3u);
    PF_CHECK_EQ(f.s->stats().rx_packets, 1u);
}

PF_TEST(tunnel_keepalive_ping_is_recognised_and_not_delivered) {
    Fixture f; f.establish();
    PacketBuffer out;
    const std::vector<uint8_t> ping(kPingPayload, kPingPayload + kPingPayloadLen);
    PF_CHECK(f.rx(f.peer.seal(0, ping), out) == TunnelSession::RxKind::Keepalive);
    PF_CHECK_EQ(f.s->stats().rx_pings, 1u);
    PF_CHECK_EQ(f.s->stats().rx_packets, 0u);
    // authenticated but neither ping nor IP (e.g. an OCC message): counted, never written to the TUN device
    PF_CHECK(f.rx(f.peer.seal(0, {0x00, 0x01, 0x02, 0x03, 0x04}), out) == TunnelSession::RxKind::Dropped);
    PF_CHECK_EQ(f.s->stats().rx_not_ip, 1u);
}

PF_TEST(tunnel_sends_a_keepalive_ping_after_the_pushed_interval_of_silence) {
    Fixture f; f.establish();                                           // push: ping 2, ping-restart 8
    f.n.now += 1500;
    auto none = f.s->poll(f.n.now, f.n.unix_s);
    PF_CHECK_EQ(f.s->stats().tx_pings, 0u);
    f.n.now += 1000;                                                    // 2.5 s since the last transmission
    const auto out = f.s->poll(f.n.now, f.n.unix_s);
    PF_REQUIRE(f.s->stats().tx_pings == 1u);
    bool found = false;
    for (const auto& d : out) {
        const auto plain = f.peer.open(d);
        if (plain.size() == kPingPayloadLen && is_ping_payload(plain.data(), plain.size())) found = true;
    }
    PF_CHECK(found);                                                    // the server decrypts our ping to the OpenVPN keepalive payload
    (void)none;
}

PF_TEST(tunnel_data_traffic_defers_the_keepalive_ping) {
    Fixture f; f.establish();
    const auto p = ip_packet(60);
    std::vector<uint8_t> wire;
    for (int i = 0; i < 5; ++i) {                                       // a packet every 1 s keeps the 2 s timer from firing
        f.n.now += 1000;
        PF_REQUIRE(f.s->encapsulate(p.data(), p.size(), f.n.now, wire));
        f.s->poll(f.n.now, f.n.unix_s);
    }
    PF_CHECK_EQ(f.s->stats().tx_pings, 0u);
}

PF_TEST(tunnel_declares_the_peer_dead_after_ping_restart_seconds_of_silence) {
    Fixture f; f.establish();
    PF_CHECK(!f.s->timed_out());
    for (int i = 0; i < 7; ++i) { f.n.now += 1000; f.s->poll(f.n.now, f.n.unix_s); }
    PF_CHECK(!f.s->timed_out());                                        // 7 s < 8 s
    f.n.now += 1500;
    f.s->poll(f.n.now, f.n.unix_s);
    PF_CHECK(f.s->timed_out());
}

PF_TEST(tunnel_inbound_traffic_keeps_the_session_alive) {
    Fixture f; f.establish();
    PacketBuffer out;
    for (int i = 0; i < 20; ++i) {                                      // 20 s of one inbound packet per 1 s, no other signs of life
        f.n.now += 1000;
        PF_CHECK(f.rx(f.peer.seal(0, ip_packet(70)), out) == TunnelSession::RxKind::Packet);
        f.s->poll(f.n.now, f.n.unix_s);
    }
    PF_CHECK(!f.s->timed_out());
}

PF_TEST(tunnel_switches_to_the_new_key_id_after_renegotiation) {
    FakeServerConfig sc = server_cfg();
    sc.reneg_after_ms = 8000;
    Fixture f(client_cfg(nullptr), sc);
    f.establish();
    const auto p = ip_packet(60);
    std::vector<uint8_t> wire;
    PF_REQUIRE(f.s->encapsulate(p.data(), p.size(), f.n.now, wire));
    PF_CHECK_EQ(wire[0] & 7, 0);
    // Drive the pair until the renegotiation completes (the session's poll replaces ControlClient::poll here).
    for (int i = 0; i < 400 && f.r.client->stats().renegotiations == 0; ++i) {
        f.n.deliver_to_server(f.s->poll(f.n.now, f.n.unix_s));
        f.n.deliver_to_client(f.r.server->poll(f.n.now, f.n.unix_s));
        f.n.now += 100;
    }
    PF_REQUIRE(f.r.client->stats().renegotiations == 1u);
    PF_REQUIRE(f.s->encapsulate(p.data(), p.size(), f.n.now, wire));
    PF_CHECK_EQ(wire[0] & 7, 1);
    PF_CHECK(f.peer.open(wire) == p);                                   // the server opens it with the NEW key
    PacketBuffer out;
    PF_CHECK(f.rx(f.peer.seal(0, ip_packet(64)), out) == TunnelSession::RxKind::Packet);   // old key still drains (grace)
    PF_CHECK(f.rx(f.peer.seal(1, ip_packet(64)), out) == TunnelSession::RxKind::Packet);
}

PF_TEST(tunnel_rejects_oversized_and_empty_packets) {
    Fixture f; f.establish();
    std::vector<uint8_t> wire;
    PF_CHECK(!f.s->encapsulate(nullptr, 0, f.n.now, wire));
    const auto huge = ip_packet(70000);
    PF_CHECK(!f.s->encapsulate(huge.data(), huge.size(), f.n.now, wire));
    PF_CHECK_EQ(f.s->stats().tx_failed, 2u);
}

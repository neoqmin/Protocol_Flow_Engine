// Data-plane blocks driven through real flows with a FAKE AEAD (no OpenSSL needed):
// this isolates block/flow logic (ordering, replay commit-after-auth, error mapping).
#include <cstring>
#include "pf/blocks/data_plane_blocks.h"
#include "pf/crypto/aead_provider.h"
#include "pf/flow.h"
#include "pf/key_store.h"
#include "pf_test.h"

using namespace pf;

// Not cryptography: XOR with key[0]; "tag" = 16 copies of (key[0] ^ xor of aad bytes ^ xor of ciphertext).
struct FakeAead : AeadProvider {
    static uint8_t mac(const uint8_t* key, const uint8_t* aad, size_t al, const uint8_t* ct, size_t n) {
        uint8_t m = key[0];
        for (size_t i = 0; i < al; ++i) m ^= aad[i];
        for (size_t i = 0; i < n; ++i) m ^= ct[i];
        return m;
    }
    bool decrypt(const uint8_t* key, const uint8_t*, const uint8_t* aad, size_t al, uint8_t* buf, size_t n, const uint8_t* tag) override {
        uint8_t m = mac(key, aad, al, buf, n);
        for (int i = 0; i < 16; ++i) if (tag[i] != m) { for (size_t j = 0; j < n; ++j) buf[j] = 0; return false; }
        for (size_t i = 0; i < n; ++i) buf[i] ^= key[0];
        return true;
    }
    bool encrypt(const uint8_t* key, const uint8_t*, const uint8_t* aad, size_t al, uint8_t* buf, size_t n, uint8_t* tag) override {
        for (size_t i = 0; i < n; ++i) buf[i] ^= key[0];
        std::memset(tag, mac(key, aad, al, buf, n), 16);
        return true;
    }
};

struct Rig {
    BlockRegistry reg; KeyStore keys; FakeAead aead; KeyRef rx, tx; Flow rx_flow, tx_flow;
    Rig() {
        PF_REQUIRE(register_data_plane_blocks(reg));
        DataKey k; k.key.fill(0x5C); k.nonce_tail.fill(1);
        rx = keys.add(k); tx = keys.add(k);
        keys.bind_rx(1, rx); keys.bind_tx(1, tx);
        FlowBuilder r("dp_rx");
        r.add("parse", kBlockParseDataV2).add("key", kBlockLookupRxKey).add("replay", kBlockReplayCheck)
         .add("decrypt", kBlockAeadDecrypt).add("commit", kBlockReplayCommit);
        auto rr = r.build(reg); PF_REQUIRE(rr.ok()); rx_flow = std::move(rr.flow);
        FlowBuilder t("dp_tx");
        t.input(kFactOvpnHeader).add("key", kBlockLookupTxKey).add("encrypt", kBlockAeadEncrypt);
        auto tt = t.build(reg); PF_REQUIRE(tt.ok()); tx_flow = std::move(tt.flow);
    }
    // Encrypts `payload` for key_id 1 through the TX flow and returns the wire bytes.
    std::vector<uint8_t> seal(const std::vector<uint8_t>& payload, uint32_t peer = 0) {
        PacketBuffer p = PacketBuffer::from_bytes(payload.data(), payload.size());
        FlowContext c; c.packet = &p; c.keys = &keys; c.aead = &aead;
        set_ovpn_header(c, OvpnHeader{OvpnOpcode::DataV2, 1, peer});
        FlowResult r = run_flow(tx_flow, c);
        PF_REQUIRE(r.outcome == FlowOutcome::Completed);
        return std::vector<uint8_t>(p.data(), p.data() + p.size());
    }
    FlowResult open(std::vector<uint8_t> wire, PacketBuffer& p, FlowContext& c) {
        p = PacketBuffer::from_bytes(wire.data(), wire.size());
        c = FlowContext{}; c.packet = &p; c.keys = &keys; c.aead = &aead;
        return run_flow(rx_flow, c);
    }
};

PF_TEST(tx_then_rx_round_trip_restores_payload_without_copying_headers) {
    Rig g; const std::vector<uint8_t> payload = {1, 2, 3, 4, 5, 6, 7};
    auto wire = g.seal(payload, 0x0A0B0C);
    PF_CHECK_EQ(wire.size(), payload.size() + kDataV2Overhead);
    PF_CHECK_EQ(wire[0], 0x49);                      // DATA_V2, key_id 1
    PF_CHECK_EQ(wire[3], 0x0C);                      // peer-id low byte
    PacketBuffer p; FlowContext c;
    FlowResult r = g.open(wire, p, c);
    PF_CHECK(r.outcome == FlowOutcome::Completed);
    PF_REQUIRE(p.size() == payload.size());
    PF_CHECK(std::memcmp(p.data(), payload.data(), payload.size()) == 0);
}

PF_TEST(tx_packet_ids_increase_and_are_written_big_endian) {
    Rig g;
    auto a = g.seal({9}), b = g.seal({9});
    PF_CHECK_EQ(a[7], 1); PF_CHECK_EQ(b[7], 2);
}

PF_TEST(rx_rejects_replayed_packet_with_replay_reason) {
    Rig g; auto wire = g.seal({1, 2, 3});
    PacketBuffer p; FlowContext c;
    PF_CHECK(g.open(wire, p, c).outcome == FlowOutcome::Completed);
    FlowResult r = g.open(wire, p, c);
    PF_CHECK(r.outcome == FlowOutcome::Dropped);
    PF_CHECK(r.error == Error::ReplayDetected);
}

PF_TEST(rx_forged_packet_does_not_advance_replay_window) {
    Rig g; auto good = g.seal({1, 2, 3});             // packet-id 1
    auto forged = good; forged[7] = 0xFF;             // claims packet-id 255 but fails authentication
    PacketBuffer p; FlowContext c;
    FlowResult r = g.open(forged, p, c);
    PF_CHECK(r.outcome == FlowOutcome::Dropped);
    PF_CHECK(r.error == Error::AuthFailed);
    PF_CHECK(g.open(good, p, c).outcome == FlowOutcome::Completed);   // genuine packet still accepted
}

PF_TEST(rx_tampered_ciphertext_is_dropped_as_auth_failure) {
    Rig g; auto wire = g.seal({1, 2, 3, 4});
    wire.back() ^= 1;
    PacketBuffer p; FlowContext c;
    FlowResult r = g.open(wire, p, c);
    PF_CHECK(r.outcome == FlowOutcome::Dropped);
    PF_CHECK(r.error == Error::AuthFailed);
}

PF_TEST(rx_unknown_key_id_is_dropped) {
    Rig g; auto wire = g.seal({1});
    wire[0] = static_cast<uint8_t>((9 << 3) | 4);     // key_id 4 has no binding
    PacketBuffer p; FlowContext c;
    FlowResult r = g.open(wire, p, c);
    PF_CHECK(r.outcome == FlowOutcome::Dropped);
    PF_CHECK(r.error == Error::UnknownKey);
}

PF_TEST(rx_truncated_and_wrong_opcode_are_dropped) {
    Rig g; PacketBuffer p; FlowContext c;
    FlowResult r = g.open({0x48, 0, 0, 0, 0, 0, 0, 1}, p, c);     // shorter than 24
    PF_CHECK(r.outcome == FlowOutcome::Dropped); PF_CHECK(r.error == Error::Truncated);
    r = g.open(std::vector<uint8_t>(40, 0x20), p, c);             // CONTROL_V1
    PF_CHECK(r.outcome == FlowOutcome::Dropped); PF_CHECK(r.error == Error::InvalidOpcode);
}

PF_TEST(rx_packet_id_zero_is_dropped_as_invalid) {
    Rig g; auto wire = g.seal({1, 2});
    wire[4] = wire[5] = wire[6] = wire[7] = 0;
    PacketBuffer p; FlowContext c;
    FlowResult r = g.open(wire, p, c);
    PF_CHECK(r.outcome == FlowOutcome::Dropped);
    PF_CHECK(r.error == Error::InvalidPacketId);
}

PF_TEST(missing_keystore_or_provider_is_an_internal_error_not_a_drop) {
    Rig g; auto wire = g.seal({1});
    PacketBuffer p = PacketBuffer::from_bytes(wire.data(), wire.size());
    FlowContext c; c.packet = &p;                     // keys/aead not provided: our wiring bug
    FlowResult r = run_flow(g.rx_flow, c);
    PF_CHECK(r.outcome == FlowOutcome::Errored);
    PF_CHECK(r.error == Error::Internal);
}

PF_TEST(tx_without_bound_key_is_an_error) {
    Rig g;
    PacketBuffer p = PacketBuffer::from_bytes(nullptr, 0);
    FlowContext c; c.packet = &p; c.keys = &g.keys; c.aead = &g.aead;
    set_ovpn_header(c, OvpnHeader{OvpnOpcode::DataV2, 6, 0});   // key_id 6 unbound
    FlowResult r = run_flow(g.tx_flow, c);
    PF_CHECK(r.outcome == FlowOutcome::Errored);
    PF_CHECK(r.error == Error::UnknownKey);
}

PF_TEST(tx_stops_with_nonce_exhausted_instead_of_wrapping) {
    Rig g;
    g.keys.get(g.tx)->tx_next = 0xFFFFFFFFu;
    g.seal({1});                                      // uses the last id
    PacketBuffer p = PacketBuffer::from_bytes(nullptr, 0);
    FlowContext c; c.packet = &p; c.keys = &g.keys; c.aead = &g.aead;
    set_ovpn_header(c, OvpnHeader{OvpnOpcode::DataV2, 1, 0});
    FlowResult r = run_flow(g.tx_flow, c);
    PF_CHECK(r.outcome == FlowOutcome::Errored);
    PF_CHECK(r.error == Error::NonceExhausted);
}

PF_TEST(tx_without_headroom_reports_buffer_too_small) {
    Rig g;
    PacketBuffer p(/*headroom=*/8, /*capacity=*/16, 0);   // needs 24 bytes of headroom
    FlowContext c; c.packet = &p; c.keys = &g.keys; c.aead = &g.aead;
    set_ovpn_header(c, OvpnHeader{OvpnOpcode::DataV2, 1, 0});
    FlowResult r = run_flow(g.tx_flow, c);
    PF_CHECK(r.outcome == FlowOutcome::Errored);
    PF_CHECK(r.error == Error::BufferTooSmall);
}

PF_TEST(register_data_plane_blocks_is_all_or_nothing) {
    BlockRegistry r;
    PF_CHECK(register_data_plane_blocks(r));
    PF_CHECK_EQ(r.size(), size_t(7));
    PF_CHECK(!register_data_plane_blocks(r));
    PF_CHECK_EQ(r.size(), size_t(7));
}

// DataPath (TX/RX flows behind one API) with the real AES-256-GCM provider and mirrored keys.
#include <cstring>
#include <vector>

#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/data_path.h"
#include "pf_test.h"

using namespace pf;

namespace {
struct Pair {
    KeyStore a_keys, b_keys;
    std::unique_ptr<AeadProvider> aead = make_openssl_aes256gcm();
    DataPath a, b;
    Pair() {
        DataKey ab, ba;            // a->b and b->a directions
        ab.key.fill(0x11); ab.nonce_tail.fill(0x21);
        ba.key.fill(0x12); ba.nonce_tail.fill(0x22);
        a_keys.bind_tx(1, a_keys.add(ab)); a_keys.bind_rx(1, a_keys.add(ba));
        b_keys.bind_tx(1, b_keys.add(ba)); b_keys.bind_rx(1, b_keys.add(ab));
        PF_REQUIRE(a.init(&a_keys, aead.get()));
        PF_REQUIRE(b.init(&b_keys, aead.get()));
    }
    static std::vector<uint8_t> ipv4(size_t total) {
        std::vector<uint8_t> p(total, 0xAB);
        p[0] = 0x45;
        return p;
    }
    std::vector<uint8_t> seal_from_a(const std::vector<uint8_t>& plain) {
        PacketBuffer pkt = DataPath::make_tx_buffer(2048);
        uint8_t* room = pkt.put(plain.size());
        PF_REQUIRE(room != nullptr);
        std::memcpy(room, plain.data(), plain.size());
        PF_REQUIRE(a.seal(pkt, 1, 7) == Error::None);
        return std::vector<uint8_t>(pkt.data(), pkt.data() + pkt.size());
    }
};
}  // namespace

PF_TEST(data_path_ip_packet_round_trips_and_is_classified_ip) {
    Pair g;
    const auto plain = Pair::ipv4(100);
    auto wire = g.seal_from_a(plain);
    PF_CHECK_EQ(wire.size(), plain.size() + kDataV2Overhead);
    PacketBuffer rx = PacketBuffer::from_bytes(wire.data(), wire.size());
    auto o = g.b.open(rx);
    PF_CHECK(o.error == Error::None);
    PF_CHECK(o.kind == PayloadKind::Ip);
    PF_REQUIRE(rx.size() == plain.size());
    PF_CHECK(std::memcmp(rx.data(), plain.data(), plain.size()) == 0);
}

PF_TEST(data_path_ping_is_recognised_and_not_ip) {
    Pair g;
    auto wire = g.seal_from_a(std::vector<uint8_t>(kPingPayload, kPingPayload + kPingPayloadLen));
    PacketBuffer rx = PacketBuffer::from_bytes(wire.data(), wire.size());
    auto o = g.b.open(rx);
    PF_CHECK(o.error == Error::None);
    PF_CHECK(o.kind == PayloadKind::Ping);
}

PF_TEST(data_path_authenticated_non_ip_is_other_and_short_ip_is_not_ip) {
    Pair g;
    for (const auto& plain : {std::vector<uint8_t>{0x28, 0x7f, 0x34, 0x6b, 0x01}, std::vector<uint8_t>(10, 0x45), std::vector<uint8_t>(30, 0x60)}) {
        auto wire = g.seal_from_a(plain);
        PacketBuffer rx = PacketBuffer::from_bytes(wire.data(), wire.size());
        auto o = g.b.open(rx);
        PF_CHECK(o.error == Error::None);
        PF_CHECK(o.kind == PayloadKind::Other);       // never handed to the TUN
    }
}

PF_TEST(data_path_rejects_tamper_replay_and_wrong_key_id) {
    Pair g;
    auto wire = g.seal_from_a(Pair::ipv4(60));
    {
        auto bad = wire;
        bad[bad.size() / 2] ^= 1;
        PacketBuffer rx = PacketBuffer::from_bytes(bad.data(), bad.size());
        PF_CHECK(g.b.open(rx).error == Error::AuthFailed);
    }
    PacketBuffer ok = PacketBuffer::from_bytes(wire.data(), wire.size());
    PF_CHECK(g.b.open(ok).error == Error::None);
    PacketBuffer again = PacketBuffer::from_bytes(wire.data(), wire.size());
    PF_CHECK(g.b.open(again).error == Error::ReplayDetected);
    auto other_id = g.seal_from_a(Pair::ipv4(60));
    other_id[0] = static_cast<uint8_t>((other_id[0] & 0xF8) | 5);          // key_id 5: no such key
    PacketBuffer rx5 = PacketBuffer::from_bytes(other_id.data(), other_id.size());
    PF_CHECK(g.b.open(rx5).error == Error::UnknownKey);
}

PF_TEST(data_path_seal_without_tx_key_reports_error) {
    KeyStore keys;
    auto aead = make_openssl_aes256gcm();
    DataPath dp;
    PF_REQUIRE(dp.init(&keys, aead.get()));
    PacketBuffer pkt = DataPath::make_tx_buffer(64);
    uint8_t* room = pkt.put(20);
    PF_REQUIRE(room != nullptr);
    std::memset(room, 0x45, 20);
    PF_CHECK(dp.seal(pkt, 1, 0) != Error::None);
}

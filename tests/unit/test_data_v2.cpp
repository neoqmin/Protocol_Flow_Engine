#include <cstring>
#include "pf/data_v2.h"
#include "pf_test.h"

using namespace pf;

static std::vector<uint8_t> make_pkt(uint8_t key_id, uint32_t peer, uint32_t pid, size_t ct_len) {
    std::vector<uint8_t> p(kDataV2Overhead + ct_len, 0xEE);
    uint8_t aad[kDataV2AadLen];
    PF_REQUIRE(build_data_v2_aad(key_id, peer, pid, aad));
    std::memcpy(p.data(), aad, sizeof aad);
    for (size_t i = 0; i < kDataV2TagLen; ++i) p[kDataV2AadLen + i] = static_cast<uint8_t>(0xA0 + i);
    return p;
}

PF_TEST(data_v2_layout_constants_match_observed_wire_format) {
    PF_CHECK_EQ(kDataV2HeaderLen, size_t(4));
    PF_CHECK_EQ(kDataV2PacketIdLen, size_t(4));
    PF_CHECK_EQ(kDataV2TagLen, size_t(16));
    PF_CHECK_EQ(kDataV2AadLen, size_t(8));        // header4 || packet_id4
    PF_CHECK_EQ(kDataV2Overhead, size_t(24));     // keepalive: 24 + 16 = 40 bytes on the wire
}

PF_TEST(build_aad_encodes_opcode_keyid_peer_and_packet_id_big_endian) {
    uint8_t aad[kDataV2AadLen];
    PF_CHECK(build_data_v2_aad(5, 0x010203, 0x0A0B0C0D, aad));
    const uint8_t want[] = {0x4D, 0x01, 0x02, 0x03, 0x0A, 0x0B, 0x0C, 0x0D};
    PF_CHECK(std::memcmp(aad, want, 8) == 0);
}

PF_TEST(build_aad_rejects_out_of_range_fields) {
    uint8_t aad[kDataV2AadLen];
    PF_CHECK(!build_data_v2_aad(8, 0, 1, aad));            // key_id is 3 bits
    PF_CHECK(!build_data_v2_aad(0, 0x1000000, 1, aad));    // peer-id is 24 bits
    PF_CHECK(build_data_v2_aad(7, 0xFFFFFF, 0xFFFFFFFFu, aad));
}

PF_TEST(parse_extracts_fields) {
    auto p = make_pkt(2, 0x00ABCD, 0x01020304, 5);
    DataV2Packet d{};
    PF_CHECK(parse_data_v2(p.data(), p.size(), d) == ParseStatus::Ok);
    PF_CHECK(d.header.opcode == OvpnOpcode::DataV2);
    PF_CHECK_EQ(d.header.key_id, 2);
    PF_CHECK_EQ(d.header.peer_id, 0x00ABCDu);
    PF_CHECK_EQ(d.packet_id, 0x01020304u);
    PF_CHECK_EQ(d.tag[0], 0xA0);
    PF_CHECK_EQ(d.tag[15], 0xAF);
    PF_CHECK_EQ(d.ciphertext_len, size_t(5));
}

PF_TEST(parse_accepts_empty_ciphertext) {
    auto p = make_pkt(0, 0, 1, 0);
    DataV2Packet d{};
    PF_CHECK(parse_data_v2(p.data(), p.size(), d) == ParseStatus::Ok);
    PF_CHECK_EQ(d.ciphertext_len, size_t(0));
}

PF_TEST(parse_rejects_truncated_packets) {
    auto p = make_pkt(0, 0, 1, 4);
    DataV2Packet d{};
    for (size_t len = 0; len < kDataV2Overhead; ++len)
        PF_CHECK(parse_data_v2(p.data(), len, d) == ParseStatus::Truncated);
    PF_CHECK(parse_data_v2(nullptr, 0, d) == ParseStatus::Truncated);
}

PF_TEST(parse_rejects_non_data_v2_opcodes) {
    auto p = make_pkt(0, 0, 1, 4);
    p[0] = static_cast<uint8_t>(4 << 3);          // CONTROL_V1
    DataV2Packet d{};
    PF_CHECK(parse_data_v2(p.data(), p.size(), d) == ParseStatus::InvalidOpcode);
}

PF_TEST(parse_sweep_never_reads_out_of_bounds) {  // meaningful under ASan
    for (int first = 0; first < 256; ++first)
        for (size_t len = 0; len <= 40; ++len) {
            std::vector<uint8_t> p(len, static_cast<uint8_t>(first));
            DataV2Packet d{};
            (void)parse_data_v2(p.data(), p.size(), d);
        }
}

PF_TEST(parse_matches_observed_wire_packet) {
    // Keepalive from unmodified OpenVPN 2.6.19 (key_id 0, packet-id 1, 16-byte ciphertext).
    const uint8_t wire[] = {
        0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xf9, 0x58, 0xdd, 0x33, 0xc3, 0xe0, 0x31, 0x99, 0x0e, 0xd8, 0x51, 0x20, 0xfa, 0x84, 0x19, 0xcb,
        0x37, 0xa2, 0xe3, 0x7f, 0x05, 0x2d, 0xfe, 0xc0, 0x96, 0x4c, 0x9b, 0xdb, 0x01, 0xd4, 0x61, 0xd0};
    DataV2Packet d{};
    PF_CHECK(parse_data_v2(wire, sizeof wire, d) == ParseStatus::Ok);
    PF_CHECK_EQ(d.packet_id, 1u);
    PF_CHECK_EQ(d.ciphertext_len, size_t(16));
}

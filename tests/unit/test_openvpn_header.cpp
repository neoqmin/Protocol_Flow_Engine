#include "pf/openvpn_header.h"
#include "pf_test.h"

using namespace pf;

PF_TEST(header_control_hard_reset_client_v2) {
    const uint8_t pkt[] = {0x38};  // opcode 7 << 3 | key_id 0
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::Ok);
    PF_CHECK(h.opcode == OvpnOpcode::ControlHardResetClientV2);
    PF_CHECK_EQ(h.key_id, 0);
}

PF_TEST(header_key_id_extracted) {
    const uint8_t pkt[] = {static_cast<uint8_t>((4 << 3) | 5)};  // CONTROL_V1, key 5
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::Ok);
    PF_CHECK_EQ(h.key_id, 5);
}

PF_TEST(header_data_v2_peer_id) {
    const uint8_t pkt[] = {static_cast<uint8_t>((9 << 3) | 1), 0x01, 0x02, 0x03};
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::Ok);
    PF_CHECK(h.opcode == OvpnOpcode::DataV2);
    PF_CHECK_EQ(h.peer_id, 0x010203u);
}

PF_TEST(header_empty_is_truncated) {
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(nullptr, 0, h) == ParseStatus::Truncated);
}

PF_TEST(header_data_v2_short_is_truncated) {
    const uint8_t pkt[] = {static_cast<uint8_t>(9 << 3), 0x01};
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::Truncated);
}

PF_TEST(header_unknown_opcode_rejected) {
    const uint8_t pkt[] = {static_cast<uint8_t>(31 << 3)};
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::InvalidOpcode);
}

PF_TEST(header_wkc_v1_opcode_11_accepted) {  // tls-crypt-v2 client key wrapping
    const uint8_t pkt[] = {static_cast<uint8_t>(11 << 3)};
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::Ok);
    PF_CHECK(h.opcode == OvpnOpcode::ControlWkcV1);
}

PF_TEST(header_opcode_12_rejected) {
    const uint8_t pkt[] = {static_cast<uint8_t>(12 << 3)};
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::InvalidOpcode);
}

PF_TEST(header_opcode_0_rejected) {
    const uint8_t pkt[] = {0x00};
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::InvalidOpcode);
}

PF_TEST(legacy_opcodes_flagged_for_policy) {
    // Parser is wire-level; rejecting legacy opcodes is a policy decision.
    PF_CHECK(is_legacy_opcode(OvpnOpcode::ControlHardResetClientV1));
    PF_CHECK(is_legacy_opcode(OvpnOpcode::ControlHardResetServerV1));
    PF_CHECK(is_legacy_opcode(OvpnOpcode::DataV1));
    PF_CHECK(!is_legacy_opcode(OvpnOpcode::DataV2));
    PF_CHECK(!is_legacy_opcode(OvpnOpcode::ControlHardResetClientV2));
    PF_CHECK(!is_legacy_opcode(OvpnOpcode::ControlV1));
}

PF_TEST(header_ignores_trailing_payload) {
    const uint8_t pkt[] = {0x38, 0xAA, 0xBB, 0xCC, 0xDD};
    OvpnHeader h{};
    PF_CHECK(parse_ovpn_header(pkt, sizeof pkt, h) == ParseStatus::Ok);
    PF_CHECK(h.opcode == OvpnOpcode::ControlHardResetClientV2);
}

// Exhaustive robustness sweep (runs everywhere, incl. under ASan/UBSan):
// every first byte x every length 0..5 must classify without UB, and the
// result must agree with the documented rules.
PF_TEST(header_exhaustive_small_inputs) {
    uint8_t buf[5] = {0, 0xAB, 0xCD, 0xEF, 0x11};
    for (int first = 0; first < 256; ++first) {
        buf[0] = static_cast<uint8_t>(first);
        for (size_t len = 0; len <= 5; ++len) {
            OvpnHeader h{};
            ParseStatus st = parse_ovpn_header(buf, len, h);
            const int op = first >> 3;
            if (len == 0) { PF_CHECK(st == ParseStatus::Truncated); continue; }
            if (op < 1 || op > 11) { PF_CHECK(st == ParseStatus::InvalidOpcode); continue; }
            if (op == 9 && len < 4) { PF_CHECK(st == ParseStatus::Truncated); continue; }
            PF_CHECK(st == ParseStatus::Ok);
            PF_CHECK_EQ(h.key_id, first & 7);
        }
    }
}

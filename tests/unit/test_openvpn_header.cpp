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

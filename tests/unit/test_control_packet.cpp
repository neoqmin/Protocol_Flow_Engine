#include <cstring>
#include "pf/control_packet.h"
#include "pf_test.h"

using namespace pf;

static const uint8_t SID[8] = {0x98, 0xa4, 0xc8, 0xad, 0x36, 0x7d, 0x18, 0x28};
static const uint8_t RSID[8] = {0x89, 0x34, 0x01, 0x7e, 0, 0, 0, 1};
static uint8_t op(OvpnOpcode o, uint8_t key = 0) { return static_cast<uint8_t>((static_cast<uint8_t>(o) << 3) | key); }

PF_TEST(parse_client_hard_reset_observed_on_the_wire) {
    const uint8_t pt[] = {0, 0, 0, 0, 0};            // ack_len 0, message id 0 (observed plaintext)
    ControlPacket p;
    PF_REQUIRE(parse_control(op(OvpnOpcode::ControlHardResetClientV2), SID, pt, sizeof pt, p) == ControlParseStatus::Ok);
    PF_CHECK(p.opcode == static_cast<uint8_t>(OvpnOpcode::ControlHardResetClientV2));
    PF_CHECK(p.acks.empty());
    PF_CHECK(p.has_message);
    PF_CHECK_EQ(p.message_id, 0u);
    PF_CHECK(p.payload.empty());
    PF_CHECK(std::memcmp(p.session_id.data(), SID, 8) == 0);
}

PF_TEST(parse_server_hard_reset_with_ack_and_remote_session_id) {
    uint8_t pt[1 + 4 + 8 + 4] = {1, 0, 0, 0, 0};
    std::memcpy(pt + 5, RSID, 8);                     // pt[13..16] = message id 0
    ControlPacket p;
    PF_REQUIRE(parse_control(op(OvpnOpcode::ControlHardResetServerV2), SID, pt, sizeof pt, p) == ControlParseStatus::Ok);
    PF_REQUIRE(p.acks.size() == 1);
    PF_CHECK_EQ(p.acks[0], 0u);
    PF_CHECK(std::memcmp(p.remote_session_id.data(), RSID, 8) == 0);
    PF_CHECK_EQ(p.message_id, 0u);
}

PF_TEST(parse_control_v1_with_multiple_acks_and_tls_payload) {
    std::vector<uint8_t> pt = {3, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0};          // acks [2,1,0]
    pt.insert(pt.end(), RSID, RSID + 8);
    pt.insert(pt.end(), {0, 0, 0, 7, 0x16, 0x03, 0x03, 0x00, 0x7a});            // message id 7 + TLS record head
    ControlPacket p;
    PF_REQUIRE(parse_control(op(OvpnOpcode::ControlV1), SID, pt.data(), pt.size(), p) == ControlParseStatus::Ok);
    PF_CHECK(p.acks == (std::vector<uint32_t>{2, 1, 0}));
    PF_CHECK_EQ(p.message_id, 7u);
    PF_CHECK_EQ(p.payload.size(), size_t(5));
    PF_CHECK_EQ(p.payload[0], 0x16);
}

PF_TEST(parse_ack_v1_has_no_message) {
    std::vector<uint8_t> pt = {2, 0, 0, 0, 1, 0, 0, 0, 0};
    pt.insert(pt.end(), RSID, RSID + 8);
    ControlPacket p;
    PF_REQUIRE(parse_control(op(OvpnOpcode::AckV1), SID, pt.data(), pt.size(), p) == ControlParseStatus::Ok);
    PF_CHECK(!p.has_message);
    PF_CHECK(p.acks == (std::vector<uint32_t>{1, 0}));
}

PF_TEST(parse_keeps_key_id_from_the_opcode_byte) {
    const uint8_t pt[] = {0, 0, 0, 0, 5};
    ControlPacket p;
    PF_REQUIRE(parse_control(op(OvpnOpcode::ControlSoftResetV1, 3), SID, pt, sizeof pt, p) == ControlParseStatus::Ok);
    PF_CHECK_EQ(p.key_id, 3);
    PF_CHECK_EQ(p.message_id, 5u);
}

PF_TEST(parse_rejects_truncated_plaintext) {
    ControlPacket p;
    const uint8_t o = op(OvpnOpcode::ControlV1);
    PF_CHECK(parse_control(o, SID, nullptr, 0, p) == ControlParseStatus::Truncated);
    const uint8_t a[] = {0, 0, 0};                    // no ack, message id cut short
    PF_CHECK(parse_control(o, SID, a, sizeof a, p) == ControlParseStatus::Truncated);
    const uint8_t b[] = {3, 0, 0, 0, 1};              // claims 3 acks, only 1 byte of the first
    PF_CHECK(parse_control(o, SID, b, sizeof b, p) == ControlParseStatus::Truncated);
    uint8_t c[1 + 4 + 7] = {1};                       // ack present but remote session id incomplete
    PF_CHECK(parse_control(o, SID, c, sizeof c, p) == ControlParseStatus::Truncated);
}

PF_TEST(parse_rejects_malformed_ack_packets) {
    ControlPacket p;
    const uint8_t o = op(OvpnOpcode::AckV1);
    const uint8_t none[] = {0};                       // an ACK that acknowledges nothing
    PF_CHECK(parse_control(o, SID, none, sizeof none, p) == ControlParseStatus::Malformed);
    std::vector<uint8_t> trailing = {1, 0, 0, 0, 0};
    trailing.insert(trailing.end(), RSID, RSID + 8);
    trailing.push_back(0xFF);                         // ACK must not carry a message
    PF_CHECK(parse_control(o, SID, trailing.data(), trailing.size(), p) == ControlParseStatus::Malformed);
}

PF_TEST(parse_rejects_non_control_opcodes) {
    ControlPacket p;
    const uint8_t pt[] = {0, 0, 0, 0, 0};
    PF_CHECK(parse_control(op(OvpnOpcode::DataV2), SID, pt, sizeof pt, p) == ControlParseStatus::WrongOpcode);
    PF_CHECK(parse_control(op(OvpnOpcode::DataV1), SID, pt, sizeof pt, p) == ControlParseStatus::WrongOpcode);
    PF_CHECK(parse_control(op(OvpnOpcode::ControlHardResetClientV1), SID, pt, sizeof pt, p) == ControlParseStatus::WrongOpcode);
    PF_CHECK(parse_control(op(OvpnOpcode::ControlWkcV1), SID, pt, sizeof pt, p) == ControlParseStatus::WrongOpcode);
}

PF_TEST(build_then_parse_round_trips) {
    ControlPacket in;
    in.opcode = static_cast<uint8_t>(OvpnOpcode::ControlV1); in.key_id = 2;
    std::memcpy(in.session_id.data(), SID, 8);
    in.acks = {5, 4, 3};
    std::memcpy(in.remote_session_id.data(), RSID, 8);
    in.has_message = true; in.message_id = 9; in.payload = {1, 2, 3, 4};
    std::vector<uint8_t> pt;
    PF_REQUIRE(build_control_plaintext(in, pt));
    ControlPacket out;
    PF_REQUIRE(parse_control(op(OvpnOpcode::ControlV1, 2), SID, pt.data(), pt.size(), out) == ControlParseStatus::Ok);
    PF_CHECK(out.acks == in.acks);
    PF_CHECK_EQ(out.message_id, 9u);
    PF_CHECK(out.payload == in.payload);
    PF_CHECK(std::memcmp(out.remote_session_id.data(), RSID, 8) == 0);
}

PF_TEST(build_without_acks_omits_remote_session_id) {
    ControlPacket in;
    in.opcode = static_cast<uint8_t>(OvpnOpcode::ControlHardResetClientV2);
    in.has_message = true; in.message_id = 0;
    std::vector<uint8_t> pt;
    PF_REQUIRE(build_control_plaintext(in, pt));
    PF_CHECK_EQ(pt.size(), size_t(5));               // exactly what OpenVPN sends: 00 00000000
    for (auto b : pt) PF_CHECK_EQ(b, 0);
}

PF_TEST(build_rejects_inconsistent_packets) {
    std::vector<uint8_t> pt;
    ControlPacket ack; ack.opcode = static_cast<uint8_t>(OvpnOpcode::AckV1);
    PF_CHECK(!build_control_plaintext(ack, pt));                     // ACK without acks
    ack.acks = {1}; ack.has_message = true;
    PF_CHECK(!build_control_plaintext(ack, pt));                     // ACK carrying a message
    ControlPacket c; c.opcode = static_cast<uint8_t>(OvpnOpcode::ControlV1);
    PF_CHECK(!build_control_plaintext(c, pt));                       // CONTROL without message
    c.has_message = true; c.acks.assign(kMaxAcksPerPacket + 1, 1);
    PF_CHECK(!build_control_plaintext(c, pt));                       // too many acks for one packet
    ControlPacket w; w.opcode = static_cast<uint8_t>(OvpnOpcode::DataV2); w.has_message = true;
    PF_CHECK(!build_control_plaintext(w, pt));                       // not a control opcode
}

PF_TEST(control_parse_sweep_never_reads_out_of_bounds) {   // meaningful under ASan
    const OvpnOpcode ops[] = {OvpnOpcode::ControlSoftResetV1, OvpnOpcode::ControlV1, OvpnOpcode::AckV1,
                              OvpnOpcode::ControlHardResetClientV2, OvpnOpcode::ControlHardResetServerV2};
    for (auto o : ops)
        for (int first = 0; first < 12; ++first)
            for (size_t len = 0; len <= 40; ++len) {
                std::vector<uint8_t> pt(len, static_cast<uint8_t>(first));
                if (len) pt[0] = static_cast<uint8_t>(first);
                ControlPacket p;
                (void)parse_control(op(o), SID, pt.data(), pt.size(), p);
            }
}

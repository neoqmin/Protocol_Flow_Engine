#include "pf/peer_info.h"
#include "pf_test.h"

using namespace pf;

// Peer info sent by unmodified OpenVPN 2.6.19 (observed in the interop lab, shortened to the fields we look at).
static const char* kStock = "IV_VER=2.6.19\nIV_PLAT=linux\nIV_TCPNL=1\nIV_MTU=1600\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n"
                            "IV_PROTO=990\nIV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\n";

PF_TEST(peer_info_parses_the_stock_client) {
    PeerInfo p;
    PF_REQUIRE(parse_peer_info(kStock, p) == PeerInfoStatus::Ok);
    PF_CHECK(p.has_proto);
    PF_CHECK_EQ(p.iv_proto, 990u);
    PF_CHECK(p.ciphers == (std::vector<std::string>{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}));
    PF_CHECK(p.version == "2.6.19");
    PF_CHECK(p.platform == "linux");
    PF_CHECK(p.values.at("IV_MTU") == "1600");
    PF_CHECK(peer_info_unsupported_reason(p).empty());
}

PF_TEST(peer_info_parses_our_own_client) {
    PeerInfo p;
    PF_REQUIRE(parse_peer_info("IV_VER=2.6.0\nIV_PLAT=linux\nIV_PROTO=14\nIV_CIPHERS=AES-256-GCM\n", p) == PeerInfoStatus::Ok);
    PF_CHECK_EQ(p.iv_proto, kIvProtoDataV2 | kIvProtoRequestPush | kIvProtoTlsKeyExport);
    PF_CHECK(peer_info_unsupported_reason(p).empty());
}

PF_TEST(peer_info_accepts_empty_lines_and_a_missing_final_newline) {
    PeerInfo p;
    PF_REQUIRE(parse_peer_info("IV_PROTO=14\n\nIV_CIPHERS=AES-256-GCM", p) == PeerInfoStatus::Ok);
    PF_CHECK_EQ(p.iv_proto, 14u);
    PF_REQUIRE(parse_peer_info("", p) == PeerInfoStatus::Ok);
    PF_CHECK(!p.has_proto);
    PF_CHECK(p.values.empty());
}

PF_TEST(peer_info_rejects_malformed_text) {
    const char* bad[] = {
        "IV_PROTO",                     // no '='
        "=14",                          // empty key
        "IV_PROTO=14\nIV_PROTO=990",    // duplicate key: which one would count?
        "IV_PROTO=abc",                 // not a number
        "IV_PROTO=",                    // empty number
        "IV_PROTO=4294967296",          // does not fit 32 bits
        "IV_PROTO=-1",
        "IV_PROTO=+14",
        "IV_PROTO=14\r",                // control character
        "IV_PLAT=li\tnux",
        "IV\x01=1",
    };
    for (const char* b : bad) {
        PeerInfo p;
        PF_CHECK(parse_peer_info(b, p) == PeerInfoStatus::Malformed);
    }
}

PF_TEST(peer_info_bounds_the_number_of_entries) {
    std::string many;
    for (int i = 0; i < kMaxPeerInfoEntries; ++i) many += "UV_K" + std::to_string(i) + "=v\n";
    PeerInfo p;
    PF_CHECK(parse_peer_info(many, p) == PeerInfoStatus::Ok);
    many += "UV_ONE_MORE=v\n";
    PF_CHECK(parse_peer_info(many, p) == PeerInfoStatus::Malformed);
}

PF_TEST(peer_info_says_why_a_client_is_outside_the_profile) {
    auto reason = [](const char* text) {
        PeerInfo p;
        PF_REQUIRE(parse_peer_info(text, p) == PeerInfoStatus::Ok);
        return peer_info_unsupported_reason(p);
    };
    PF_CHECK(!reason("IV_CIPHERS=AES-256-GCM\n").empty());                         // no IV_PROTO at all (pre-2.5)
    PF_CHECK(!reason("IV_PROTO=6\nIV_CIPHERS=AES-256-GCM\n").empty());             // no TLS key export
    PF_CHECK(!reason("IV_PROTO=12\nIV_CIPHERS=AES-256-GCM\n").empty());            // no DATA_V2
    PF_CHECK(!reason("IV_PROTO=14\n").empty());                                    // no cipher list
    PF_CHECK(!reason("IV_PROTO=14\nIV_CIPHERS=AES-128-GCM:CHACHA20-POLY1305\n").empty());   // no shared cipher
    PF_CHECK(!reason("IV_PROTO=14\nIV_CIPHERS=aes-256-gcmX\n").empty());
    PF_CHECK(reason("IV_PROTO=10\nIV_CIPHERS=AES-128-GCM:AES-256-GCM\n").empty()); // REQUEST_PUSH is not required
    PF_CHECK(reason("IV_PROTO=14\nIV_CIPHERS=aes-256-gcm\n").empty());             // cipher names are case-insensitive
}

#include "pf/push.h"
#include "pf_test.h"

using namespace pf;

// Observed from unmodified OpenVPN 2.6.19 (server log "SENT CONTROL ... PUSH_REPLY").
static const char* kObserved = "PUSH_REPLY,route-gateway 10.77.0.1,topology subnet,ping 2,ping-restart 8,"
                               "ifconfig 10.77.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM,"
                               "protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500";

PF_TEST(push_classifies_control_messages) {
    PF_CHECK(classify_control_message("PUSH_REPLY,ping 2") == ControlMessageKind::PushReply);
    PF_CHECK(classify_control_message("PUSH_REPLY") == ControlMessageKind::PushReply);
    PF_CHECK(classify_control_message("PUSH_REQUEST") == ControlMessageKind::PushRequest);
    PF_CHECK(classify_control_message("AUTH_FAILED") == ControlMessageKind::AuthFailed);
    PF_CHECK(classify_control_message("AUTH_FAILED,reason text") == ControlMessageKind::AuthFailed);
    PF_CHECK(classify_control_message("RESTART,[...]") == ControlMessageKind::Restart);
    PF_CHECK(classify_control_message("HALT,bye") == ControlMessageKind::Halt);
    PF_CHECK(classify_control_message("INFO_PRE,something") == ControlMessageKind::Info);
    PF_CHECK(classify_control_message("PUSH_REPLYX,1") == ControlMessageKind::Unknown);   // exact keyword only
    PF_CHECK(classify_control_message("") == ControlMessageKind::Unknown);
}

PF_TEST(push_parses_the_reply_observed_from_openvpn_2_6_19) {
    PushReply r;
    PF_REQUIRE(parse_push_reply(kObserved, r) == PushStatus::Ok);
    PF_CHECK_EQ(r.ifconfig_ip, 0x0A4D0002u);              // 10.77.0.2
    PF_CHECK_EQ(r.ifconfig_netmask, 0xFFFFFF00u);
    PF_CHECK(r.has_ifconfig);
    PF_CHECK_EQ(r.route_gateway, 0x0A4D0001u);
    PF_CHECK(r.topology == "subnet");
    PF_CHECK_EQ(r.ping_seconds, 2u);
    PF_CHECK_EQ(r.ping_restart_seconds, 8u);
    PF_CHECK(r.has_peer_id); PF_CHECK_EQ(r.peer_id, 0u);
    PF_CHECK(r.cipher == "AES-256-GCM");
    PF_CHECK_EQ(r.tun_mtu, 1500u);
    PF_CHECK(r.protocol_flags == (std::vector<std::string>{"cc-exit", "tls-ekm", "dyn-tls-crypt"}));
    PF_CHECK(r.key_derivation_tls_ekm());
    PF_CHECK(r.supported_by_mvp());
}

PF_TEST(push_without_ekm_flag_is_not_supported_by_the_mvp) {
    PushReply r;
    PF_REQUIRE(parse_push_reply("PUSH_REPLY,ifconfig 10.0.0.2 255.255.255.0,peer-id 1,cipher AES-256-GCM", r) == PushStatus::Ok);
    PF_CHECK(!r.key_derivation_tls_ekm());
    PF_CHECK(!r.supported_by_mvp());                      // PRF key derivation is out of MVP scope
}

PF_TEST(push_accepts_key_derivation_option_as_well) {
    PushReply r;
    PF_REQUIRE(parse_push_reply("PUSH_REPLY,key-derivation tls-ekm,ifconfig 10.0.0.2 255.255.255.0,peer-id 1,cipher AES-256-GCM", r) == PushStatus::Ok);
    PF_CHECK(r.key_derivation_tls_ekm());
}

PF_TEST(push_rejects_a_non_aes256gcm_cipher_for_the_mvp) {
    PushReply r;
    PF_REQUIRE(parse_push_reply("PUSH_REPLY,ifconfig 10.0.0.2 255.255.255.0,peer-id 1,cipher AES-128-GCM,protocol-flags tls-ekm", r) == PushStatus::Ok);
    PF_CHECK(!r.supported_by_mvp());
}

PF_TEST(push_collects_routes_and_keeps_unknown_options) {
    PushReply r;
    PF_REQUIRE(parse_push_reply("PUSH_REPLY,route 10.1.0.0 255.255.0.0,route 192.168.5.0 255.255.255.0 10.77.0.1,"
                                "redirect-gateway def1,dhcp-option DNS 10.77.0.1,ifconfig 10.0.0.2 255.255.255.0,peer-id 3", r) == PushStatus::Ok);
    PF_REQUIRE(r.routes.size() == 2);
    PF_CHECK_EQ(r.routes[0].network, 0x0A010000u); PF_CHECK_EQ(r.routes[0].netmask, 0xFFFF0000u); PF_CHECK(!r.routes[0].has_gateway);
    PF_CHECK(r.routes[1].has_gateway); PF_CHECK_EQ(r.routes[1].gateway, 0x0A4D0001u);
    PF_CHECK(r.unknown_options == (std::vector<std::string>{"redirect-gateway def1", "dhcp-option DNS 10.77.0.1"}));
}

PF_TEST(push_rejects_malformed_values_in_options_that_matter) {
    PushReply r;
    PF_CHECK(parse_push_reply("PUSH_REPLY,ifconfig 10.0.0 255.255.255.0", r) == PushStatus::BadOption);
    PF_CHECK(parse_push_reply("PUSH_REPLY,ifconfig 10.0.0.2", r) == PushStatus::BadOption);
    PF_CHECK(parse_push_reply("PUSH_REPLY,ifconfig 300.0.0.2 255.255.255.0", r) == PushStatus::BadOption);
    PF_CHECK(parse_push_reply("PUSH_REPLY,peer-id abc", r) == PushStatus::BadOption);
    PF_CHECK(parse_push_reply("PUSH_REPLY,peer-id 16777216", r) == PushStatus::BadOption);   // peer-id is 24 bits
    PF_CHECK(parse_push_reply("PUSH_REPLY,ping -1", r) == PushStatus::BadOption);
    PF_CHECK(parse_push_reply("PUSH_REPLY,tun-mtu 99999999999", r) == PushStatus::BadOption);
    PF_CHECK(parse_push_reply("PUSH_REPLY,route 10.0.0.0", r) == PushStatus::BadOption);
}

PF_TEST(push_rejects_other_messages_and_tolerates_empty_options) {
    PushReply r;
    PF_CHECK(parse_push_reply("AUTH_FAILED", r) == PushStatus::NotPushReply);
    PF_CHECK(parse_push_reply("", r) == PushStatus::NotPushReply);
    PF_REQUIRE(parse_push_reply("PUSH_REPLY,,ping 2,,", r) == PushStatus::Ok);       // empty items are skipped
    PF_CHECK_EQ(r.ping_seconds, 2u);
    PF_REQUIRE(parse_push_reply("PUSH_REPLY", r) == PushStatus::Ok);
    PF_CHECK(!r.has_ifconfig);
    PF_CHECK(!r.supported_by_mvp());                                                   // nothing usable pushed
}

PF_TEST(push_ipv4_parser_accepts_only_dotted_quads) {
    uint32_t v = 0;
    PF_CHECK(parse_ipv4("0.0.0.0", v)); PF_CHECK_EQ(v, 0u);
    PF_CHECK(parse_ipv4("255.255.255.255", v)); PF_CHECK_EQ(v, 0xFFFFFFFFu);
    PF_CHECK(!parse_ipv4("1.2.3", v));
    PF_CHECK(!parse_ipv4("1.2.3.4.5", v));
    PF_CHECK(!parse_ipv4("1.2.3.256", v));
    PF_CHECK(!parse_ipv4("1..2.3", v));
    PF_CHECK(!parse_ipv4("1.2.3.4 ", v));
    PF_CHECK(!parse_ipv4("a.b.c.d", v));
    PF_CHECK(!parse_ipv4("", v));
    PF_CHECK(parse_ipv4("10.77.0.1", v)); PF_CHECK_EQ(v, 0x0A4D0001u);
    PF_CHECK(!parse_ipv4("01.2.3.4", v));                         // leading zeros are ambiguous (octal in inet_aton): refuse
    PF_CHECK(!parse_ipv4("1.2.3.04", v));
    PF_CHECK(!parse_ipv4("10.077.0.1", v));
}

PF_TEST(push_builds_a_reply_the_parser_reads_back) {
    ServerPush s;
    s.ifconfig_ip = 0x0A080002; s.ifconfig_netmask = 0xFFFFFF00; s.route_gateway = 0x0A080001;
    s.peer_id = 3; s.ping_seconds = 10; s.ping_restart_seconds = 60; s.tun_mtu = 1500;
    s.routes.push_back({0xC0A86400, 0xFFFFFF00, false, 0});
    s.routes.push_back({0xAC100000, 0xFFF00000, true, 0x0A080001});
    std::string msg;
    PF_REQUIRE(build_push_reply(s, msg));
    PF_CHECK(msg == "PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 60,route 192.168.100.0 255.255.255.0,"
                    "route 172.16.0.0 255.240.0.0 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,cipher AES-256-GCM,"
                    "protocol-flags tls-ekm,tun-mtu 1500");
    PushReply r;
    PF_REQUIRE(parse_push_reply(msg, r) == PushStatus::Ok);
    PF_CHECK(r.supported_by_mvp());
    PF_CHECK_EQ(r.ifconfig_ip, s.ifconfig_ip);
    PF_CHECK_EQ(r.ifconfig_netmask, s.ifconfig_netmask);
    PF_CHECK_EQ(r.route_gateway, s.route_gateway);
    PF_CHECK_EQ(r.peer_id, 3u);
    PF_CHECK_EQ(r.ping_seconds, 10u);
    PF_CHECK_EQ(r.ping_restart_seconds, 60u);
    PF_CHECK_EQ(r.routes.size(), size_t{2});
    PF_CHECK(r.routes[1].has_gateway);
    PF_CHECK(r.unknown_options.empty());
}

PF_TEST(push_build_omits_disabled_keepalive_and_rejects_bad_values) {
    ServerPush s;
    s.ifconfig_ip = 0x0A080002; s.ifconfig_netmask = 0xFFFFFF00; s.route_gateway = 0x0A080001;
    s.ping_seconds = 0; s.ping_restart_seconds = 0;
    std::string msg;
    PF_REQUIRE(build_push_reply(s, msg));
    PF_CHECK(msg.find("ping") == std::string::npos);
    s.peer_id = 0xFFFFFF;                         // reserved: "no peer-id" on the wire
    PF_CHECK(!build_push_reply(s, msg));
    s.peer_id = 0;
    s.ifconfig_ip = 0;
    PF_CHECK(!build_push_reply(s, msg));          // a client without an address cannot be served
    s.ifconfig_ip = 0x0A080002;
    for (int i = 0; i < 40; ++i) s.routes.push_back({0x0A000000u + (static_cast<uint32_t>(i) << 8), 0xFFFFFF00, true, 0x0A080001});
    PF_CHECK(!build_push_reply(s, msg));          // longer than kMaxPushReply (no push-continuation yet)
}

PF_TEST(push_formats_ipv4) {
    PF_CHECK(format_ipv4(0) == "0.0.0.0");
    PF_CHECK(format_ipv4(0xFFFFFFFF) == "255.255.255.255");
    PF_CHECK(format_ipv4(0x0A4D0002) == "10.77.0.2");
    uint32_t back = 0;
    for (uint32_t v : {0u, 1u, 0x7F000001u, 0xC0A80101u, 0xFFFFFFFEu}) {
        PF_REQUIRE(parse_ipv4(format_ipv4(v), back));
        PF_CHECK_EQ(back, v);
    }
}

#include <fstream>
#include <sstream>
#include <string>

#include "pf/flow_json.h"
#include "pf_test.h"

using namespace pf;

#ifndef GOLDEN_DIR
#define GOLDEN_DIR "tests/regression/golden"
#endif

namespace {
const char* kMinimal = R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"parse_data_v2"}]})";

bool has(const FlowJsonResult& r, FlowJsonErrorCode c, const std::string& path = "") {
    for (const auto& e : r.errors) if (e.code == c && (path.empty() || e.path == path)) return true;
    return false;
}
// Replaces `from` with `to` in the minimal document to produce a variant.
std::string variant(const std::string& from, const std::string& to) {
    std::string s = kMinimal;
    const size_t at = s.find(from);
    PF_REQUIRE(at != std::string::npos);
    s.replace(at, from.size(), to);
    return s;
}
std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
}  // namespace

PF_TEST(flow_json_minimal_document_loads_with_defaults) {
    auto r = parse_flow_json(kMinimal);
    PF_REQUIRE(r.ok());
    PF_CHECK_EQ(r.doc.version, 1);
    PF_CHECK(r.doc.name == "f");
    PF_CHECK(r.doc.runtime == std::vector<std::string>{"user"});
    PF_REQUIRE(r.doc.nodes.size() == 1);
    PF_CHECK(r.doc.nodes[0].id == "a" && r.doc.nodes[0].block == "parse_data_v2");
    PF_CHECK(r.doc.edges.empty());
    PF_CHECK_EQ(r.migrated_from, 0);
}

PF_TEST(flow_json_golden_files_parse_and_rewrite_to_identical_bytes) {
    for (const char* name : {"flow_openvpn_rx.flow.json", "flow_data_v2_rx.flow.json", "flow_data_v2_tx.flow.json"}) {
        const std::string text = slurp(std::string(GOLDEN_DIR) + "/" + name);
        PF_REQUIRE(!text.empty());
        auto r = parse_flow_json(text);
        if (!r.ok()) std::printf("%s: %s %s\n", name, r.errors[0].path.c_str(), r.errors[0].message.c_str());
        PF_REQUIRE(r.ok());
        PF_CHECK(write_flow_json(r.doc) == text);                 // canonical form is stable: no churn in version control
    }
}

PF_TEST(flow_json_openvpn_rx_golden_content) {
    auto r = parse_flow_json(slurp(std::string(GOLDEN_DIR) + "/flow_openvpn_rx.flow.json"));
    PF_REQUIRE(r.ok());
    PF_CHECK(r.doc.name == "openvpn_rx");
    PF_REQUIRE(r.doc.nodes.size() == 5);
    PF_REQUIRE(r.doc.edges.size() == 3);
    PF_CHECK(r.doc.edges[0].from == "is_data" && r.doc.edges[0].port == "yes" && r.doc.edges[0].to == std::optional<std::string>("strip"));
    PF_CHECK(r.doc.edges[1].port == "no");
    PF_CHECK(r.doc.edges[2].from == "strip" && r.doc.edges[2].port == "continue" && !r.doc.edges[2].to.has_value());   // null = end of flow
}

PF_TEST(flow_json_round_trip_preserves_everything_including_extensions) {
    const std::string text = R"({
      "format":"protocol-flow","version":1,"x-editor":{"zoom":2},
      "flow":{"name":"f","description":"d","runtime":["user","kernel"],"x-flow":true},
      "nodes":[{"id":"n1","block":"aead_decrypt","params":{"algorithm":"AES-256-GCM","keyRef":"session.data_key","window":64,"strict":true,"ratio":0.5},"x-pos":[10,20]},
               {"id":"n2","block":"replay_commit"}],
      "edges":[{"from":"n1","to":"n2","x-label":"ok"},{"from":"n2","to":null}],
      "meta":{"author":"qa","ticket":"PF-1"}})";
    auto r = parse_flow_json(text);
    if (!r.ok()) std::printf("%s %s\n", r.errors[0].path.c_str(), r.errors[0].message.c_str());
    PF_REQUIRE(r.ok());
    PF_CHECK(r.doc.extensions.size() == 1 && r.doc.extensions[0].first == "x-editor");
    PF_CHECK(r.doc.flow_extensions.size() == 1);
    PF_CHECK(r.doc.nodes[0].extensions.size() == 1);
    PF_CHECK(r.doc.edges[0].extensions.size() == 1);
    PF_CHECK(r.doc.nodes[0].params.size() == 5);
    PF_CHECK((r.doc.runtime == std::vector<std::string>{"user", "kernel"}));
    const std::string out = write_flow_json(r.doc);
    auto back = parse_flow_json(out);
    PF_REQUIRE(back.ok());
    PF_CHECK(write_flow_json(back.doc) == out);                  // idempotent
    PF_CHECK(back.doc.nodes[0].params == r.doc.nodes[0].params);
    PF_CHECK(back.doc.extensions == r.doc.extensions);
    PF_CHECK(back.doc.meta == r.doc.meta);
}

PF_TEST(flow_json_reports_structural_errors_with_json_pointer_paths) {
    PF_CHECK(has(parse_flow_json("[]"), FlowJsonErrorCode::NotAnObject));
    PF_CHECK(has(parse_flow_json("{"), FlowJsonErrorCode::BadJson));
    PF_CHECK(has(parse_flow_json(R"({"format":"protocol-flow","flow":{"name":"f"},"nodes":[]})"), FlowJsonErrorCode::MissingField, "/version"));
    PF_CHECK(has(parse_flow_json(variant("\"flow\":{\"name\":\"f\"},", "")), FlowJsonErrorCode::MissingField, "/flow"));
    PF_CHECK(has(parse_flow_json(variant("{\"name\":\"f\"}", "{}")), FlowJsonErrorCode::MissingField, "/flow/name"));
    PF_CHECK(has(parse_flow_json(variant("\"nodes\":[{\"id\":\"a\",\"block\":\"parse_data_v2\"}]", "\"nodes\":[]")), FlowJsonErrorCode::BadValue, "/nodes"));
    PF_CHECK(has(parse_flow_json(variant("\"id\":\"a\"", "\"id\":1")), FlowJsonErrorCode::WrongType, "/nodes/0/id"));
    PF_CHECK(has(parse_flow_json(variant("\"id\":\"a\",", "")), FlowJsonErrorCode::MissingField, "/nodes/0/id"));
    PF_CHECK(has(parse_flow_json(variant("\"protocol-flow\"", "\"other\"")), FlowJsonErrorCode::BadValue, "/format"));
    PF_CHECK(has(parse_flow_json(variant("\"nodes\":[", "\"nodes\":{},\"x\":[")), FlowJsonErrorCode::WrongType));
}

PF_TEST(flow_json_validates_names_and_ports) {
    for (const char* bad : {"\"1a\"", "\"a b\"", "\"a/b\"", "\"\"", "\"-a\"", "\"a.b\"", "\"é\""})
        PF_CHECK(has(parse_flow_json(variant("\"id\":\"a\"", std::string("\"id\":") + bad)), FlowJsonErrorCode::BadValue, "/nodes/0/id"));
    PF_CHECK(parse_flow_json(variant("\"id\":\"a\"", "\"id\":\"_a-b_9\"")).ok());
    PF_CHECK(has(parse_flow_json(variant("\"name\":\"f\"", "\"name\":\"bad name\"")), FlowJsonErrorCode::BadValue, "/flow/name"));
    const std::string long_id(65, 'a');
    PF_CHECK(!parse_flow_json(variant("\"id\":\"a\"", "\"id\":\"" + long_id + "\"")).ok());
    const std::string edge = variant("}]}", "}],\"edges\":[{\"from\":\"a\",\"to\":null,\"port\":\"maybe\"}]}");
    PF_CHECK(has(parse_flow_json(edge), FlowJsonErrorCode::BadValue, "/edges/0/port"));
    PF_CHECK(has(parse_flow_json(variant("}]}", "}],\"edges\":[{\"from\":\"a\"}]}")), FlowJsonErrorCode::MissingField, "/edges/0/to"));
    PF_CHECK(has(parse_flow_json(variant("}]}", "}],\"edges\":[{\"from\":\"a\",\"to\":5}]}")), FlowJsonErrorCode::WrongType, "/edges/0/to"));
    PF_CHECK(has(parse_flow_json(variant("\"flow\":{\"name\":\"f\"}", "\"flow\":{\"name\":\"f\",\"runtime\":[\"gpu\"]}")), FlowJsonErrorCode::BadValue, "/flow/runtime/0"));
    PF_CHECK(has(parse_flow_json(variant("\"flow\":{\"name\":\"f\"}", "\"flow\":{\"name\":\"f\",\"runtime\":[]}")), FlowJsonErrorCode::WrongType, "/flow/runtime"));
}

PF_TEST(flow_json_duplicate_node_ids_are_rejected) {
    auto r = parse_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"x"},{"id":"b","block":"x"},{"id":"a","block":"y"}]})");
    PF_CHECK(has(r, FlowJsonErrorCode::DuplicateId, "/nodes/2/id"));
}

PF_TEST(flow_json_unknown_fields_are_errors_but_x_extensions_are_kept) {
    PF_CHECK(has(parse_flow_json(variant("\"version\":1,", "\"version\":1,\"color\":\"red\",")), FlowJsonErrorCode::UnknownField, "/color"));
    PF_CHECK(has(parse_flow_json(variant("\"block\":\"parse_data_v2\"", "\"block\":\"parse_data_v2\",\"typo\":1")), FlowJsonErrorCode::UnknownField, "/nodes/0/typo"));
    PF_CHECK(has(parse_flow_json(variant("{\"name\":\"f\"}", "{\"name\":\"f\",\"Runtime\":[\"user\"]}")), FlowJsonErrorCode::UnknownField, "/flow/Runtime"));
    auto ok = parse_flow_json(variant("\"version\":1,", "\"version\":1,\"x-anything\":{\"a\":[1,2]},"));
    PF_REQUIRE(ok.ok());
    PF_CHECK(ok.doc.extensions.size() == 1);
    PF_CHECK(!parse_flow_json(variant("\"version\":1,", "\"version\":1,\"x-\":1,")).ok());          // bare "x-" is not an extension
}

PF_TEST(flow_json_never_accepts_secret_literals) {
    auto with_param = [](const std::string& params) {
        return parse_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"aead_decrypt","params":)" + params + "}]}");
    };
    // The plan's forbidden example: a literal key next to the algorithm.
    auto r = with_param(R"({"algorithm":"AES-GCM","key":"actual-secret-key"})");
    PF_CHECK(has(r, FlowJsonErrorCode::SecretLiteral, "/nodes/0/params/key"));
    for (const char* name : {"secret", "Password", "token", "psk", "privateKey", "session_key", "TLSCRYPTKEY", "apiKey"})
        PF_CHECK(has(with_param(std::string("{\"") + name + "\":\"x\"}"), FlowJsonErrorCode::SecretLiteral));
    PF_CHECK(with_param(R"({"keyRef":"session.data_key"})").ok());                                 // references are the supported way
    PF_CHECK(with_param(R"({"algorithm":"AES-GCM","keyRef":"session.data_key","failure":"drop"})").ok());
    PF_CHECK(has(with_param(R"({"keyRef":"Not A Ref"})"), FlowJsonErrorCode::BadValue, "/nodes/0/params/keyRef"));
    PF_CHECK(has(with_param(R"({"keyRef":"a..b"})"), FlowJsonErrorCode::BadValue));
    PF_CHECK(has(with_param(R"({"keyRef":42})"), FlowJsonErrorCode::WrongType));
    PF_CHECK(has(with_param(R"({"keyRef":"-----BEGIN PRIVATE KEY-----"})"), FlowJsonErrorCode::SecretLiteral));
    PF_CHECK(has(with_param(R"({"note":"x -----BEGIN CERTIFICATE----- y"})"), FlowJsonErrorCode::SecretLiteral));
    PF_CHECK(has(parse_flow_json(variant("{\"name\":\"f\"}", "{\"name\":\"f\",\"description\":\"-----BEGIN RSA PRIVATE KEY-----\"}")), FlowJsonErrorCode::SecretLiteral, "/flow/description"));
    PF_CHECK(has(parse_flow_json(variant("}]}", "}],\"meta\":{\"k\":\"-----BEGIN PRIVATE KEY-----\"}}")), FlowJsonErrorCode::SecretLiteral, "/meta/k"));
}

PF_TEST(flow_json_params_accept_only_scalars_with_valid_names) {
    auto with_param = [](const std::string& params) {
        return parse_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"b","params":)" + params + "}]}");
    };
    PF_CHECK(with_param(R"({"a":"s","b":1,"c":2.5,"d":true,"e_f":"x"})").ok());
    PF_CHECK(has(with_param(R"({"a":null})"), FlowJsonErrorCode::WrongType));
    PF_CHECK(has(with_param(R"({"a":[1]})"), FlowJsonErrorCode::WrongType));
    PF_CHECK(has(with_param(R"({"a":{"b":1}})"), FlowJsonErrorCode::WrongType));
    for (const char* bad : {"A", "1a", "a-b", "a b", "", "_a"})
        PF_CHECK(has(with_param(std::string("{\"") + bad + "\":1}"), FlowJsonErrorCode::BadValue));
    PF_CHECK(has(with_param("[]"), FlowJsonErrorCode::WrongType, "/nodes/0/params"));
}

PF_TEST(flow_json_limits) {
    std::string nodes;
    for (int i = 0; i < 4097; ++i) { if (i) nodes += ","; nodes += "{\"id\":\"n" + std::to_string(i) + "\",\"block\":\"b\"}"; }
    PF_CHECK(has(parse_flow_json("{\"format\":\"protocol-flow\",\"version\":1,\"flow\":{\"name\":\"f\"},\"nodes\":[" + nodes + "]}"), FlowJsonErrorCode::TooMany, "/nodes"));
    std::string ok_nodes;
    for (int i = 0; i < 4096; ++i) { if (i) ok_nodes += ","; ok_nodes += "{\"id\":\"n" + std::to_string(i) + "\",\"block\":\"b\"}"; }
    PF_CHECK(parse_flow_json("{\"format\":\"protocol-flow\",\"version\":1,\"flow\":{\"name\":\"f\"},\"nodes\":[" + ok_nodes + "]}").ok());
    std::string params = "{";
    for (int i = 0; i < 65; ++i) { if (i) params += ","; params += "\"p" + std::to_string(i) + "\":1"; }
    params += "}";
    PF_CHECK(has(parse_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"b","params":)" + params + "}]}"), FlowJsonErrorCode::TooMany));
}

PF_TEST(flow_json_collects_many_errors_in_one_pass_and_caps_them) {
    auto r = parse_flow_json(R"({"format":"protocol-flow","version":1,"flow":{"name":"bad name"},"nodes":[{"id":"1","block":"x y"},{"id":"a"},{"id":"a","block":"b","extra":1}],"edges":[{"from":"q"}]})");
    PF_CHECK(r.errors.size() >= 5);                              // an editor can show all problems at once
    std::string many = R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[)";
    for (int i = 0; i < 300; ++i) { if (i) many += ","; many += "{}"; }
    many += "]}";
    PF_CHECK(parse_flow_json(many).errors.size() <= 100);
}

PF_TEST(flow_json_version_rules_without_migrations) {
    PF_CHECK(has(parse_flow_json(variant("\"version\":1", "\"version\":2")), FlowJsonErrorCode::UnsupportedVersion, "/version"));     // newer: never guess
    PF_CHECK(has(parse_flow_json(variant("\"version\":1", "\"version\":0")), FlowJsonErrorCode::WrongType, "/version"));
    PF_CHECK(has(parse_flow_json(variant("\"version\":1", "\"version\":-3")), FlowJsonErrorCode::WrongType, "/version"));
    PF_CHECK(has(parse_flow_json(variant("\"version\":1", "\"version\":\"1\"")), FlowJsonErrorCode::WrongType, "/version"));
    PF_CHECK(has(parse_flow_json(variant("\"version\":1", "\"version\":1.5")), FlowJsonErrorCode::WrongType, "/version"));
    PF_CHECK(has(parse_flow_json(variant("\"version\":1", "\"version\":1.0")), FlowJsonErrorCode::WrongType, "/version"));    // must be an integer literal
}

PF_TEST(flow_json_migrates_old_versions_step_by_step_before_validating) {
    // Pretend the current format is v3. v1 used "kind" instead of "block"; v2 used "ports" instead of "port".
    FlowMigrations m;
    int calls = 0;
    m.add(1, [&](JsonValue& doc, std::string&) {
        ++calls;
        if (JsonValue* nodes = doc.find("nodes"))
            for (auto& n : nodes->items())
                for (auto& mem : n.members()) if (mem.first == "kind") mem.first = "block";
        return true;
    });
    m.add(2, [&](JsonValue& doc, std::string&) {
        ++calls;
        if (JsonValue* edges = doc.find("edges"))
            for (auto& e : edges->items())
                for (auto& mem : e.members()) if (mem.first == "ports") mem.first = "port";
        return true;
    });
    const std::string v1 = R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","kind":"is_data_v2"},{"id":"b","kind":"x"}],"edges":[{"from":"a","ports":"yes","to":"b"}]})";
    auto r = parse_flow_json(v1, &m, /*current*/ 3, /*min*/ 1);
    if (!r.ok()) std::printf("%s %s\n", r.errors[0].path.c_str(), r.errors[0].message.c_str());
    PF_REQUIRE(r.ok());
    PF_CHECK_EQ(calls, 2);
    PF_CHECK_EQ(r.migrated_from, 1);
    PF_CHECK_EQ(r.doc.version, 3);
    PF_CHECK(r.doc.nodes[0].block == "is_data_v2");
    PF_CHECK(r.doc.edges[0].port == "yes");
    // A v2 file only runs the second step.
    calls = 0;
    const std::string v2 = R"({"format":"protocol-flow","version":2,"flow":{"name":"f"},"nodes":[{"id":"a","block":"x"}],"edges":[{"from":"a","ports":"no","to":null}]})";
    r = parse_flow_json(v2, &m, 3, 1);
    PF_REQUIRE(r.ok());
    PF_CHECK_EQ(calls, 1);
    PF_CHECK_EQ(r.migrated_from, 2);
    // A file already at the current version is not touched.
    calls = 0;
    PF_CHECK(parse_flow_json(R"({"format":"protocol-flow","version":3,"flow":{"name":"f"},"nodes":[{"id":"a","block":"x"}]})", &m, 3, 1).ok());
    PF_CHECK_EQ(calls, 0);
}

PF_TEST(flow_json_migration_failures_are_reported_not_hidden) {
    FlowMigrations broken;
    broken.add(1, [](JsonValue&, std::string& why) { why = "cannot convert"; return false; });
    const std::string v1 = R"({"format":"protocol-flow","version":1,"flow":{"name":"f"},"nodes":[{"id":"a","block":"x"}]})";
    PF_CHECK(has(parse_flow_json(v1, &broken, 2, 1), FlowJsonErrorCode::MigrationFailed));
    PF_CHECK(has(parse_flow_json(v1, nullptr, 2, 1), FlowJsonErrorCode::UnsupportedVersion));               // no path 1 -> 2
    FlowMigrations gap;
    gap.add(2, [](JsonValue&, std::string&) { return true; });
    PF_CHECK(has(parse_flow_json(v1, &gap, 3, 1), FlowJsonErrorCode::UnsupportedVersion));                  // 1 -> 2 missing
    PF_CHECK(has(parse_flow_json(v1, &gap, 3, 2), FlowJsonErrorCode::UnsupportedVersion));                  // below the oldest supported
    // A migrator that leaves the document invalid for the new schema is still caught by validation.
    FlowMigrations sloppy;
    sloppy.add(1, [](JsonValue& d, std::string&) { d.set("surprise", JsonValue::integer(1)); return true; });
    PF_CHECK(has(parse_flow_json(v1, &sloppy, 2, 1), FlowJsonErrorCode::UnknownField, "/surprise"));
    // The engine, not the migrator, sets the version: a migrator cannot lie about it.
    FlowMigrations liar;
    liar.add(1, [](JsonValue& d, std::string&) { *d.find("version") = JsonValue::integer(99); return true; });
    auto r = parse_flow_json(v1, &liar, 2, 1);
    PF_CHECK(r.ok());
    PF_CHECK_EQ(r.doc.version, 2);
}

PF_TEST(flow_json_writer_emits_current_version_and_omits_defaults) {
    FlowDocument d;
    d.name = "w";
    d.version = 7;                                               // ignored: writers always emit the current version
    d.nodes.push_back({"a", "parse_data_v2", {}, {}});
    d.edges.push_back({"a", std::nullopt, "continue", {}});
    const std::string out = write_flow_json(d);
    PF_CHECK(out.find("\"version\": 1") != std::string::npos);
    PF_CHECK(out.find("\"port\"") == std::string::npos);
    PF_CHECK(out.find("\"description\"") == std::string::npos);
    PF_CHECK(out.find("\"meta\"") == std::string::npos);
    PF_CHECK(out.find("\"to\": null") != std::string::npos);
    PF_CHECK(parse_flow_json(out).ok());
}

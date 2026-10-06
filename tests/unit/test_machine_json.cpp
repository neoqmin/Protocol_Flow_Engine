#include <fstream>
#include <sstream>
#include <string>

#include "pf/keepalive_machine.h"
#include "pf/machine_json.h"
#include "pf_test.h"

using namespace pf;

#ifndef GOLDEN_DIR
#define GOLDEN_DIR "tests/regression/golden"
#endif

namespace {

std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool has(const std::vector<FlowJsonError>& es, FlowJsonErrorCode c, const std::string& path = "") {
    for (const auto& e : es) if (e.code == c && (path.empty() || e.path == path)) return true;
    return false;
}

const char* kStun = R"({
  "format": "protocol-machine",
  "version": 1,
  "machine": { "name": "stun_binding", "description": "RFC 8489 binding transaction", "x-editor": { "zoom": 2 } },
  "flows": ["send", "accept"],
  "events": ["command:start", "packet:response"],
  "counters": [ { "name": "tries", "max": 7 } ],
  "timers": [ { "name": "rto", "param": "rtoMs" } ],
  "states": [
    { "id": "idle", "initial": true, "x-pos": [10, 20] },
    { "id": "waiting" },
    { "id": "done", "final": "ok" },
    { "id": "failed", "final": "failed" }
  ],
  "transitions": [
    { "from": "idle", "on": "command:start", "run": "send", "actions": ["arm:rto", "inc:tries"], "to": "waiting" },
    { "from": "waiting", "on": "packet:response", "run": "accept", "actions": ["cancel:rto"], "to": "done" },
    { "from": "waiting", "on": "timer:rto", "guard": { "counter": "tries", "op": "<", "value": 7 }, "run": "send", "actions": ["arm:rto", "inc:tries"], "to": "waiting" },
    { "from": "waiting", "on": "timer:rto", "guard": { "counter": "tries", "op": ">=", "value": 7 }, "to": "failed" }
  ],
  "meta": { "author": "qa" }
})";

FlowLibrary library() {
    FlowLibrary lib;
    lib.emplace("send", Flow());
    lib.emplace("accept", Flow());
    return lib;
}

}  // namespace

PF_TEST(machine_json_parses_and_round_trips) {
    const auto r = parse_machine_json(kStun);
    PF_REQUIRE(r.ok());
    const MachineDocument& d = r.doc;
    PF_CHECK_EQ(d.name, std::string("stun_binding"));
    PF_CHECK_EQ(d.flows.size(), size_t{2});
    PF_CHECK_EQ(d.timers.at(0).param, std::string("rtoMs"));
    PF_CHECK(d.states.at(0).initial);
    PF_CHECK_EQ(d.states.at(3).final, std::string("failed"));
    PF_REQUIRE(d.transitions.at(2).guard.has_value());
    PF_CHECK_EQ(d.transitions.at(2).guard->value, int64_t{7});
    PF_CHECK_EQ(d.machine_extensions.size(), size_t{1});
    PF_CHECK_EQ(d.states.at(0).extensions.size(), size_t{1});

    const std::string once = write_machine_json(d);
    const auto again = parse_machine_json(once);
    PF_REQUIRE(again.ok());
    PF_CHECK_EQ(write_machine_json(again.doc), once);          // canonical output is a fixed point
    PF_CHECK(once.find("\"x-editor\"") != std::string::npos);  // extensions survive
    PF_CHECK(once.find("\"initial\": false") == std::string::npos);   // defaults omitted

    const auto loaded = load_machine_json(kStun, library());
    PF_CHECK(loaded.ok());
    PF_CHECK_EQ(loaded.machine.state_count(), size_t{4});
}

PF_TEST(machine_json_structure_errors) {
    const auto r = parse_machine_json(R"({"format":"protocol-flow","version":1,"machine":{"name":"9bad","colour":1},
        "flows":"send","counters":[{"name":"c","max":"7"}],"timers":[{"name":"t","ms":0},{"name":"u","allowDisabled":"yes"}],
        "states":[{"id":"a","initial":1,"final":"maybe"}],
        "transitions":[{"from":"a","on":5,"guard":{"counter":"c","op":"<","value":1,"x-note":"no"},"to":"a","unbounded":""},{"on":"auto"}],
        "extra":true})");
    PF_CHECK(!r.ok());
    const auto& e = r.errors;
    PF_CHECK(has(e, FlowJsonErrorCode::BadValue, "/format"));
    PF_CHECK(has(e, FlowJsonErrorCode::BadValue, "/machine/name"));
    PF_CHECK(has(e, FlowJsonErrorCode::UnknownField, "/machine/colour"));
    PF_CHECK(has(e, FlowJsonErrorCode::UnknownField, "/extra"));
    PF_CHECK(has(e, FlowJsonErrorCode::WrongType, "/flows"));
    PF_CHECK(has(e, FlowJsonErrorCode::WrongType, "/counters/0/max"));
    PF_CHECK(has(e, FlowJsonErrorCode::BadValue, "/timers/0/ms"));
    PF_CHECK(has(e, FlowJsonErrorCode::WrongType, "/timers/1/allowDisabled"));
    PF_CHECK(has(e, FlowJsonErrorCode::WrongType, "/states/0/initial"));
    PF_CHECK(has(e, FlowJsonErrorCode::BadValue, "/states/0/final"));
    PF_CHECK(has(e, FlowJsonErrorCode::WrongType, "/transitions/0/on"));
    PF_CHECK(has(e, FlowJsonErrorCode::UnknownField, "/transitions/0/guard/x-note"));
    PF_CHECK(has(e, FlowJsonErrorCode::BadValue, "/transitions/0/unbounded"));
    PF_CHECK(has(e, FlowJsonErrorCode::MissingField, "/transitions/1/from"));
    PF_CHECK(has(e, FlowJsonErrorCode::MissingField, "/transitions/1/to"));

    PF_CHECK(has(parse_machine_json("[1]").errors, FlowJsonErrorCode::NotAnObject));
    PF_CHECK(has(parse_machine_json("{\"version\":1,").errors, FlowJsonErrorCode::BadJson));
    PF_CHECK(has(parse_machine_json(R"({"format":"protocol-machine","version":1})").errors, FlowJsonErrorCode::MissingField, "/machine"));
}

PF_TEST(machine_json_rejects_secrets) {
    const auto r = parse_machine_json(R"({"format":"protocol-machine","version":1,
        "machine":{"name":"m","description":"-----BEGIN PRIVATE KEY-----"},
        "states":[{"id":"a","initial":true},{"id":"b","final":"ok"}],
        "transitions":[{"from":"a","on":"timer:t","to":"b","unbounded":"-----BEGIN CERTIFICATE-----"}],
        "meta":{"k":"-----BEGIN RSA PRIVATE KEY-----"}})");
    PF_CHECK(has(r.errors, FlowJsonErrorCode::SecretLiteral, "/machine/description"));
    PF_CHECK(has(r.errors, FlowJsonErrorCode::SecretLiteral, "/transitions/0/unbounded"));
    PF_CHECK(has(r.errors, FlowJsonErrorCode::SecretLiteral, "/meta/k"));
}

PF_TEST(machine_json_versions_and_migration) {
    std::string newer = kStun;
    newer.replace(newer.find("\"version\": 1"), 12, "\"version\": 2");
    PF_CHECK(has(parse_machine_json(newer).errors, FlowJsonErrorCode::UnsupportedVersion, "/version"));

    // Synthetic v1 -> v2 migration (exercised through current_version before a real v2 exists): the migrator's
    // rewrite must be what the loader sees.
    std::string v1 = kStun;
    FlowMigrations m;
    m.add(1, [](JsonValue& doc, std::string&) { doc.set("x-migrated", JsonValue::boolean(true)); return true; });
    const auto up = parse_machine_json(v1, &m, 2, 1);
    PF_CHECK(up.ok());
    PF_CHECK_EQ(up.migrated_from, int64_t{1});
    PF_CHECK_EQ(up.doc.version, int64_t{2});
    bool marked = false;
    for (const auto& x : up.doc.extensions) if (x.first == "x-migrated") marked = true;
    PF_CHECK(marked);
    PF_CHECK(has(parse_machine_json(v1, nullptr, 2, 1).errors, FlowJsonErrorCode::UnsupportedVersion));
    FlowMigrations broken;
    broken.add(1, [](JsonValue&, std::string& why) { why = "nope"; return false; });
    PF_CHECK(has(parse_machine_json(v1, &broken, 2, 1).errors, FlowJsonErrorCode::MigrationFailed));
}

PF_TEST(machine_json_load_reports_semantic_issues_with_paths) {
    std::string bad = kStun;
    bad.replace(bad.find("\"to\": \"done\""), 12, "\"to\": \"dome\"");
    const auto l = load_machine_json(bad, library());
    PF_CHECK(!l.ok());
    bool found = false;
    for (const auto& i : l.issues) if (i.code == "UnknownState" && i.path == "/transitions/1/to") found = true;
    PF_CHECK(found);
    PF_CHECK_EQ(l.machine.state_count(), size_t{0});

    const auto syntax = load_machine_json("{", library());
    PF_REQUIRE(!syntax.issues.empty());
    PF_CHECK_EQ(syntax.issues[0].code, std::string("BadJson"));

    FlowLibrary partial;
    partial.emplace("send", Flow());
    const auto missing = load_machine_json(kStun, partial);
    PF_REQUIRE(!missing.issues.empty());
    PF_CHECK_EQ(missing.issues[0].code, std::string("MissingFlow"));
}

PF_TEST(machine_json_keepalive_golden_is_canonical) {
    const std::string golden = slurp(std::string(GOLDEN_DIR) + "/machine_keepalive.machine.json");
    PF_REQUIRE(!golden.empty());
    PF_CHECK_EQ(write_machine_json(keepalive_machine_document()), golden);   // file == the built-in definition
    const auto l = load_machine_json(golden, {});
    PF_CHECK(l.ok());
    for (const auto& i : l.issues) std::fprintf(stderr, "%s %s %s\n", i.code.c_str(), i.path.c_str(), i.message.c_str());
}

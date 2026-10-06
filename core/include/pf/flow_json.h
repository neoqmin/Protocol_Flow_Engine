#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "pf/json.h"

namespace pf {

// Flow JSON v1 (docs/Flow_JSON_Schema_v1.md): the file format a Flow is stored and exchanged in.
// This layer is SYNTAX + STRUCTURE only: shapes, types, names, limits, unique ids, and the "no secrets in Flow files"
// rule. Whether blocks exist, ports fit the block type, ids resolve and the graph is acyclic is the Validator's job (C2).
inline constexpr const char* kFlowFormat = "protocol-flow";
inline constexpr int64_t kFlowVersionCurrent = 1;
inline constexpr int64_t kFlowVersionMin = 1;        // oldest version a reader still migrates

enum class FlowJsonErrorCode {
    BadJson,                // not (strict) JSON
    NotAnObject,
    MissingField,
    WrongType,
    BadValue,               // right type, value not allowed (format string, id syntax, port name, runtime name ...)
    UnknownField,           // not in the schema and not an "x-" extension
    DuplicateId,
    TooMany,                // node/edge/param/string limits
    SecretLiteral,          // key material or secret-looking literal in a Flow file (use a keyRef)
    UnsupportedVersion,     // newer than this build, older than the oldest migration, or no migration path
    MigrationFailed,
};
const char* flow_json_error_name(FlowJsonErrorCode c);

struct FlowJsonError {
    FlowJsonErrorCode code;
    std::string path;       // JSON Pointer (RFC 6901) to the offending value, e.g. "/nodes/2/block"
    std::string message;
};

using Extensions = std::vector<std::pair<std::string, JsonValue>>;     // "x-..." members, preserved verbatim

struct FlowNodeDef {
    std::string id;
    std::string block;                                  // BlockRegistry name (e.g. "parse_data_v2")
    std::vector<std::pair<std::string, JsonValue>> params;   // scalar values only (string / bool / number)
    Extensions extensions;
};

// Edge port: which exit of the node this edge is. "continue" = Action exit (default), "yes"/"no" = Decision exits.
// `to` empty = the flow ends here (JSON null).
struct FlowEdgeDef {
    std::string from;
    std::optional<std::string> to;
    std::string port = "continue";
    Extensions extensions;
};

struct FlowDocument {
    int64_t version = kFlowVersionCurrent;
    std::string name;
    std::string description;
    std::vector<std::string> runtime{"user"};           // "user" | "kernel" (kernel: Post-MVP, accepted as data)
    std::vector<FlowNodeDef> nodes;
    std::vector<FlowEdgeDef> edges;
    std::vector<std::pair<std::string, std::string>> meta;   // free-form string labels (author, ticket ...)
    Extensions flow_extensions;
    Extensions extensions;                              // top-level "x-..." members
};

// Version upgrades. A migrator rewrites the parsed JSON of version `from` into version `from + 1` (whatever it
// writes into "version" is ignored: the engine tracks the version itself). Rules (docs/Flow_JSON_Schema_v1.md section 7): readers accept kFlowVersionMin..current,
// migrate step by step, and never guess about newer files; writers always emit the current version.
class FlowMigrations {
public:
    using Migrator = std::function<bool(JsonValue& doc, std::string& error)>;
    void add(int64_t from_version, Migrator fn) { steps_[from_version] = std::move(fn); }
    const Migrator* find(int64_t from_version) const {
        auto it = steps_.find(from_version);
        return it == steps_.end() ? nullptr : &it->second;
    }
private:
    std::map<int64_t, Migrator> steps_;
};

struct FlowJsonResult {
    bool ok() const { return errors.empty(); }
    FlowDocument doc;
    std::vector<FlowJsonError> errors;                  // all problems found (capped), not just the first
    int64_t migrated_from = 0;                          // != 0: the file was version N and has been upgraded in memory
};

// Shared by every versioned document format (protocol-flow, protocol-machine): checks "version" and applies the
// migrators step by step (rules above). false = the document cannot be brought to `current_version` (errors say why).
bool upgrade_document(JsonValue& root, const FlowMigrations* migrations, int64_t current_version, int64_t min_version,
                      std::vector<FlowJsonError>& errors, int64_t& migrated_from);

// `current_version` / `min_version` exist so the upgrade machinery is testable before a v2 exists; production callers
// use the defaults.
FlowJsonResult parse_flow_json(std::string_view text, const FlowMigrations* migrations = nullptr,
                               int64_t current_version = kFlowVersionCurrent, int64_t min_version = kFlowVersionMin);

// Canonical text of the CURRENT version: fixed member order, 2-space indent, trailing newline, defaults omitted
// ("port":"continue", empty description/meta). parse(write(x)) == x.
std::string write_flow_json(const FlowDocument& doc);

bool is_valid_flow_id(std::string_view s);              // [A-Za-z_][A-Za-z0-9_-]{0,63}

}  // namespace pf

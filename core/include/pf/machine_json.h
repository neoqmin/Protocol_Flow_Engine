#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pf/flow_json.h"
#include "pf/machine.h"

namespace pf {

// protocol-machine JSON v1 (docs/Machine_JSON_Schema_v1.md): the file format of a State Machine (F-1, D-041).
// Same rules as Flow JSON v1: strict JSON, unknown fields are errors ("x-" extensions preserved), no secrets, all errors
// at once with JSON Pointer paths, versions migrated step by step (upgrade_document), canonical output.
// Handler Flows are separate protocol-flow files referenced by name.
inline constexpr const char* kMachineFormat = "protocol-machine";
inline constexpr int64_t kMachineVersionCurrent = 1;
inline constexpr int64_t kMachineVersionMin = 1;

struct MachineJsonResult {
    bool ok() const { return errors.empty(); }
    MachineDocument doc;
    std::vector<FlowJsonError> errors;
    int64_t migrated_from = 0;
};

MachineJsonResult parse_machine_json(std::string_view text, const FlowMigrations* migrations = nullptr,
                                     int64_t current_version = kMachineVersionCurrent, int64_t min_version = kMachineVersionMin);

// Canonical text: fixed member order, 2-space indent, defaults omitted. parse(write(x)) == x.
std::string write_machine_json(const MachineDocument& doc);

struct LoadedMachine {
    bool ok() const { return issues.empty(); }
    Machine machine;
    MachineDocument doc;
    int64_t migrated_from = 0;
    std::vector<FlowIssue> issues;      // syntax (loader) or semantic (validator) issues, same shape
};

// text -> parse (+ migrate) -> validate against the flow library -> executable Machine.
LoadedMachine load_machine_json(std::string_view text, const FlowLibrary& flows, const FlowMigrations* migrations = nullptr);

}  // namespace pf

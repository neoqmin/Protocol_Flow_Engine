#pragma once
#include <cstddef>
#include <cstdint>

namespace pf {

// Reason codes carried in FlowContext::error and used to index drop counters.
// Result contract (see docs/Block_API.md):
//   BlockResult::Drop  - bad/unwanted INPUT, an expected event. error = the reason.
//   BlockResult::Error - OUR failure (bug, resource). error = Internal or similar.
enum class Error : uint16_t {
    None = 0,
    Truncated,        // input shorter than the format requires
    InvalidOpcode,
    LegacyOpcode,     // deprecated opcode rejected by profile policy
    ReplayDetected,
    AuthFailed,       // AEAD tag / HMAC verification failed
    UnknownSession,
    UnknownKey,
    PolicyDenied,
    NoRoute,
    BufferTooSmall,
    Internal,         // contract violation or unexpected internal failure
    FlowInvalid,      // flow was not built/validated
    StepLimit,        // runner step budget exceeded
    Count             // keep last
};

inline constexpr size_t kErrorCount = static_cast<size_t>(Error::Count);

constexpr bool is_error(Error e) { return e != Error::None; }

constexpr const char* error_name(Error e) {
    switch (e) {
        case Error::None: return "None";
        case Error::Truncated: return "Truncated";
        case Error::InvalidOpcode: return "InvalidOpcode";
        case Error::LegacyOpcode: return "LegacyOpcode";
        case Error::ReplayDetected: return "ReplayDetected";
        case Error::AuthFailed: return "AuthFailed";
        case Error::UnknownSession: return "UnknownSession";
        case Error::UnknownKey: return "UnknownKey";
        case Error::PolicyDenied: return "PolicyDenied";
        case Error::NoRoute: return "NoRoute";
        case Error::BufferTooSmall: return "BufferTooSmall";
        case Error::Internal: return "Internal";
        case Error::FlowInvalid: return "FlowInvalid";
        case Error::StepLimit: return "StepLimit";
        case Error::Count: break;
    }
    return "Unknown";
}

}  // namespace pf

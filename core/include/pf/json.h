#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pf {

// Minimal STRICT JSON (RFC 8259) for Flow files: no comments, no trailing commas, no NaN/Infinity, no duplicate
// object keys (ambiguous: two readers could pick different values), valid UTF-8 only, no lone surrogates, no raw
// control characters in strings, bounded depth and size. Objects keep insertion order so files round-trip stably.
class JsonValue {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    using Member = std::pair<std::string, JsonValue>;

    JsonValue() = default;
    static JsonValue null() { return JsonValue(); }
    static JsonValue boolean(bool b) { JsonValue v; v.type_ = Type::Bool; v.bool_ = b; return v; }
    static JsonValue integer(int64_t i) { JsonValue v; v.type_ = Type::Number; v.is_int_ = true; v.int_ = i; v.num_ = static_cast<double>(i); return v; }
    static JsonValue number(double d) { JsonValue v; v.type_ = Type::Number; v.num_ = d; return v; }
    static JsonValue string(std::string s) { JsonValue v; v.type_ = Type::String; v.str_ = std::move(s); return v; }
    static JsonValue array() { JsonValue v; v.type_ = Type::Array; return v; }
    static JsonValue object() { JsonValue v; v.type_ = Type::Object; return v; }

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Bool; }
    bool is_number() const { return type_ == Type::Number; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }
    // True for numbers written without fraction/exponent that fit int64 (so version numbers etc. are exact).
    bool is_integer() const { return type_ == Type::Number && is_int_; }

    bool as_bool() const { return bool_; }
    int64_t as_int() const { return int_; }
    double as_double() const { return num_; }
    const std::string& as_string() const { return str_; }
    const std::vector<JsonValue>& items() const { return arr_; }
    std::vector<JsonValue>& items() { return arr_; }
    const std::vector<Member>& members() const { return obj_; }
    std::vector<Member>& members() { return obj_; }

    // Object lookup (nullptr if absent or not an object).
    const JsonValue* find(std::string_view key) const;
    JsonValue* find(std::string_view key);
    // Appends a member / element (no duplicate check: parsers reject duplicates, builders are trusted).
    JsonValue& set(std::string key, JsonValue v);
    JsonValue& push(JsonValue v);

    bool operator==(const JsonValue& o) const;
    bool operator!=(const JsonValue& o) const { return !(*this == o); }

private:
    Type type_ = Type::Null;
    bool bool_ = false, is_int_ = false;
    int64_t int_ = 0;
    double num_ = 0;
    std::string str_;
    std::vector<JsonValue> arr_;
    std::vector<Member> obj_;
};

struct JsonLimits {
    size_t max_bytes = 4u * 1024 * 1024;
    size_t max_depth = 64;
    size_t max_string_bytes = 1u * 1024 * 1024;
};

struct JsonError {
    std::string message;
    size_t offset = 0, line = 1, column = 1;       // 1-based line/column of the offending byte
};

struct JsonParseResult {
    bool ok = false;
    JsonValue value;
    JsonError error;
};

JsonParseResult parse_json(std::string_view text, const JsonLimits& limits = {});

// pretty = 2-space indent with one member/element per line (stable, diff-friendly); otherwise compact.
// Non-finite numbers are written as null (they cannot be represented).
std::string write_json(const JsonValue& v, bool pretty = true);

}  // namespace pf

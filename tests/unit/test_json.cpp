#include <string>
#include <vector>

#include "pf/json.h"
#include "pf_test.h"

using namespace pf;

namespace {
bool accepts(const std::string& s) { return parse_json(s).ok; }
}

PF_TEST(json_parses_all_value_types_and_keeps_object_order) {
    auto r = parse_json(R"({"z":1,"a":[true,false,null,"x",-2.5e1],"m":{"k":"v"}})");
    PF_REQUIRE(r.ok);
    const auto& m = r.value.members();
    PF_REQUIRE(m.size() == 3);
    PF_CHECK(m[0].first == "z" && m[1].first == "a" && m[2].first == "m");     // insertion order, not sorted
    PF_CHECK(r.value.find("z")->is_integer());
    PF_CHECK_EQ(r.value.find("z")->as_int(), 1);
    const auto& a = r.value.find("a")->items();
    PF_REQUIRE(a.size() == 5);
    PF_CHECK(a[0].as_bool() && !a[1].as_bool() && a[2].is_null());
    PF_CHECK(a[3].as_string() == "x");
    PF_CHECK(a[4].is_number() && !a[4].is_integer());
    PF_CHECK(a[4].as_double() == -25.0);
}

PF_TEST(json_integers_are_exact_and_big_ones_fall_back_to_double) {
    auto r = parse_json("[9223372036854775807,-9223372036854775808,9223372036854775808,1e2,1.0,0,-0]");
    PF_REQUIRE(r.ok);
    const auto& a = r.value.items();
    PF_CHECK(a[0].is_integer() && a[0].as_int() == INT64_MAX);
    PF_CHECK(a[1].is_integer() && a[1].as_int() == INT64_MIN);
    PF_CHECK(!a[2].is_integer());                                              // does not fit int64: never silently wraps
    PF_CHECK(!a[3].is_integer() && !a[4].is_integer());                        // "1e2" / "1.0" are not integer literals
    PF_CHECK(a[5].is_integer() && a[5].as_int() == 0);
}

PF_TEST(json_string_escapes_and_unicode) {
    auto r = parse_json(R"(["a\"b\\c\/d\b\f\n\r\t","\u00e9","\ud83d\ude00","é 日本 😀"])");
    PF_REQUIRE(r.ok);
    const auto& a = r.value.items();
    PF_CHECK(a[0].as_string() == "a\"b\\c/d\b\f\n\r\t");
    PF_CHECK(a[1].as_string() == "\xC3\xA9");
    PF_CHECK(a[2].as_string() == "\xF0\x9F\x98\x80");                         // surrogate pair -> one 4-byte sequence
    PF_CHECK(a[3].as_string() == "é 日本 😀");
}

PF_TEST(json_rejects_malformed_documents) {
    const std::vector<std::string> bad = {
        "", " ", "{", "}", "[", "]", "[1,]", "[,1]", "{\"a\":1,}", "{\"a\"}", "{\"a\":}", "{a:1}", "{'a':1}", "['a']",
        "[1 2]", "{\"a\":1 \"b\":2}", "nul", "tru", "falsE", "NaN", "Infinity", "-Infinity", "+1", "01", "-01", "1.", ".5", "1e", "1e+", "--1", "0x10",
        "\"abc", "\"a\nb\"", "\"a\tb\"", "\"\\x41\"", "\"\\u12\"", "\"\\u12g4\"", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800\\u0041\"", "\"\\u0000\"",
        "[1] x", "[1][2]", "{} {}", "// c\n[1]", "/* c */[1]", "[1, // c\n 2]", "\xEF\xBB\xBF[1]",
        "\"\xC0\xAF\"", "\"\xE0\x80\xAF\"", "\"\xED\xA0\x80\"", "\"\xF4\x90\x80\x80\"", "\"\xC3\"", "\"\x80\"", "\"\xFF\"",
        "1e999", "-1e999",
    };
    for (const auto& s : bad) {
        const auto r = parse_json(s);
        if (r.ok) std::printf("accepted but must be rejected: %s\n", s.c_str());
        PF_CHECK(!r.ok);
        PF_CHECK(!r.error.message.empty());
    }
}

PF_TEST(json_accepts_valid_edge_documents) {
    for (const char* s : {"0", "-0", "1", "\"\"", "[]", "{}", " \t\r\n[ 1 , 2 ]\n", "{\"\":1}", "[[],[[]],{}]", "1E5", "1e-5", "-1.5E+3", "true", "null", "\"\\u0041\"", "\"\\u00e9\""})
        PF_CHECK(accepts(s));
}

PF_TEST(json_rejects_duplicate_keys_anywhere) {
    PF_CHECK(!accepts(R"({"a":1,"a":2})"));
    PF_CHECK(!accepts(R"({"o":{"k":1,"k":1}})"));
    PF_CHECK(!accepts(R"([{"a":1,"a":1}])"));
    PF_CHECK(accepts(R"({"a":1,"b":{"a":2}})"));                               // same key at different levels is fine
}

PF_TEST(json_reports_line_and_column_of_the_error) {
    auto r = parse_json("{\n  \"a\": 1,\n  \"b\": ?\n}");
    PF_REQUIRE(!r.ok);
    PF_CHECK_EQ(r.error.line, 3u);
    PF_CHECK_EQ(r.error.column, 8u);
    auto d = parse_json("{\"a\":1,\n \"a\":2}");
    PF_REQUIRE(!d.ok);
    PF_CHECK(d.error.message.find("duplicate") != std::string::npos);
    PF_CHECK_EQ(d.error.line, 2u);
}

PF_TEST(json_limits_depth_size_and_string_length) {
    std::string deep(1000, '[');
    deep += std::string(1000, ']');
    PF_CHECK(!accepts(deep));                                                  // no stack overflow, clean error
    JsonLimits lim;
    lim.max_depth = 3;
    PF_CHECK(parse_json("[[[1]]]", lim).ok);
    PF_CHECK(!parse_json("[[[[1]]]]", lim).ok);
    lim = {};
    lim.max_bytes = 8;
    PF_CHECK(!parse_json("[1,2,3,4,5]", lim).ok);
    lim = {};
    lim.max_string_bytes = 4;
    PF_CHECK(!parse_json("\"abcdefgh\"", lim).ok);
}

PF_TEST(json_write_round_trips_pretty_and_compact) {
    const std::string src = R"({"s":"a\"\\\n\u0001é😀","n":-12,"d":0.1,"b":[true,null,[]],"o":{"x":{}}})";
    auto r = parse_json(src);
    PF_REQUIRE(r.ok);
    for (const bool pretty : {true, false}) {
        const std::string out = write_json(r.value, pretty);
        auto back = parse_json(out);
        PF_REQUIRE(back.ok);
        PF_CHECK(back.value == r.value);
        PF_CHECK(write_json(back.value, pretty) == out);                       // writing is stable (idempotent)
    }
    PF_CHECK(write_json(r.value, false) == R"({"s":"a\"\\\n\u0001é😀","n":-12,"d":0.1,"b":[true,null,[]],"o":{"x":{}}})");
}

PF_TEST(json_pretty_format_is_exactly_two_space_indented) {
    auto r = parse_json(R"({"a":[1,2],"b":{}})");
    PF_REQUIRE(r.ok);
    PF_CHECK(write_json(r.value) == "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": {}\n}\n");
}

PF_TEST(json_double_round_trips_exactly) {
    for (const double d : {0.1, 1.0 / 3.0, 1e-300, 1.7976931348623157e308, 123456789.123456789, -0.5}) {
        const std::string s = write_json(JsonValue::number(d), false);
        auto r = parse_json(s);
        PF_REQUIRE(r.ok);
        PF_CHECK(r.value.as_double() == d);
    }
}

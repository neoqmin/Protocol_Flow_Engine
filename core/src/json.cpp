#include "pf/json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

namespace pf {

const JsonValue* JsonValue::find(std::string_view key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& m : obj_) if (m.first == key) return &m.second;
    return nullptr;
}
JsonValue* JsonValue::find(std::string_view key) {
    return const_cast<JsonValue*>(static_cast<const JsonValue*>(this)->find(key));
}
JsonValue& JsonValue::set(std::string key, JsonValue v) {
    type_ = Type::Object;
    obj_.emplace_back(std::move(key), std::move(v));
    return obj_.back().second;
}
JsonValue& JsonValue::push(JsonValue v) {
    type_ = Type::Array;
    arr_.push_back(std::move(v));
    return arr_.back();
}
bool JsonValue::operator==(const JsonValue& o) const {
    if (type_ != o.type_) return false;
    switch (type_) {
        case Type::Null: return true;
        case Type::Bool: return bool_ == o.bool_;
        case Type::Number: return is_int_ && o.is_int_ ? int_ == o.int_ : num_ == o.num_;
        case Type::String: return str_ == o.str_;
        case Type::Array: return arr_ == o.arr_;
        case Type::Object: return obj_ == o.obj_;
    }
    return false;
}

namespace {

class Parser {
public:
    Parser(std::string_view t, const JsonLimits& l) : t_(t), lim_(l) {}

    bool run(JsonValue& out, JsonError& err) {
        if (t_.size() > lim_.max_bytes) { fail("document too large", 0); err = err_; return false; }
        // A UTF-8 BOM is not valid JSON text; reject instead of guessing.
        skip_ws();
        if (!value(out, 0)) { err = err_; return false; }
        skip_ws();
        if (pos_ != t_.size()) { fail("unexpected data after the JSON value"); err = err_; return false; }
        return true;
    }

private:
    bool fail(const char* msg) { return fail(msg, pos_); }
    bool fail(const char* msg, size_t at) {
        if (!failed_) {
            failed_ = true;
            err_.message = msg;
            err_.offset = at;
            size_t line = 1, col = 1;
            for (size_t i = 0; i < at && i < t_.size(); ++i) { if (t_[i] == '\n') { ++line; col = 1; } else ++col; }
            err_.line = line;
            err_.column = col;
        }
        return false;
    }
    bool eof() const { return pos_ >= t_.size(); }
    char cur() const { return t_[pos_]; }
    void skip_ws() { while (!eof() && (cur() == ' ' || cur() == '\t' || cur() == '\n' || cur() == '\r')) ++pos_; }

    bool literal(const char* word, JsonValue& out, JsonValue v) {
        const size_t n = std::strlen(word);
        if (t_.size() - pos_ < n || t_.compare(pos_, n, word) != 0) return fail("invalid literal");
        pos_ += n;
        out = std::move(v);
        return true;
    }

    bool value(JsonValue& out, size_t depth) {
        if (eof()) return fail("unexpected end of input");
        if (depth > lim_.max_depth) return fail("nesting too deep");
        switch (cur()) {
            case '{': return object(out, depth);
            case '[': return array(out, depth);
            case '"': { std::string s; if (!string(s)) return false; out = JsonValue::string(std::move(s)); return true; }
            case 't': return literal("true", out, JsonValue::boolean(true));
            case 'f': return literal("false", out, JsonValue::boolean(false));
            case 'n': return literal("null", out, JsonValue::null());
            default: return number(out);
        }
    }

    bool object(JsonValue& out, size_t depth) {
        ++pos_;
        out = JsonValue::object();
        skip_ws();
        if (!eof() && cur() == '}') { ++pos_; return true; }
        for (;;) {
            skip_ws();
            if (eof() || cur() != '"') return fail("expected a string key");
            const size_t key_at = pos_;
            std::string key;
            if (!string(key)) return false;
            for (const auto& m : out.members()) if (m.first == key) return fail("duplicate object key", key_at);
            skip_ws();
            if (eof() || cur() != ':') return fail("expected ':'");
            ++pos_;
            skip_ws();
            JsonValue v;
            if (!value(v, depth + 1)) return false;
            out.set(std::move(key), std::move(v));
            skip_ws();
            if (eof()) return fail("unterminated object");
            if (cur() == ',') { ++pos_; continue; }
            if (cur() == '}') { ++pos_; return true; }
            return fail("expected ',' or '}'");
        }
    }

    bool array(JsonValue& out, size_t depth) {
        ++pos_;
        out = JsonValue::array();
        skip_ws();
        if (!eof() && cur() == ']') { ++pos_; return true; }
        for (;;) {
            skip_ws();
            JsonValue v;
            if (!value(v, depth + 1)) return false;
            out.push(std::move(v));
            skip_ws();
            if (eof()) return fail("unterminated array");
            if (cur() == ',') { ++pos_; continue; }
            if (cur() == ']') { ++pos_; return true; }
            return fail("expected ',' or ']'");
        }
    }

    bool number(JsonValue& out) {
        const size_t start = pos_;
        size_t p = pos_;
        bool integral = true;
        auto digit = [&](size_t i) { return i < t_.size() && t_[i] >= '0' && t_[i] <= '9'; };
        if (p < t_.size() && t_[p] == '-') ++p;
        if (!digit(p)) return fail("invalid number");
        if (t_[p] == '0') { ++p; if (digit(p)) return fail("leading zeros are not allowed"); }
        else while (digit(p)) ++p;
        if (p < t_.size() && t_[p] == '.') { integral = false; ++p; if (!digit(p)) return fail("digits expected after '.'"); while (digit(p)) ++p; }
        if (p < t_.size() && (t_[p] == 'e' || t_[p] == 'E')) {
            integral = false; ++p;
            if (p < t_.size() && (t_[p] == '+' || t_[p] == '-')) ++p;
            if (!digit(p)) return fail("digits expected in exponent");
            while (digit(p)) ++p;
        }
        const std::string text(t_.substr(start, p - start));
        pos_ = p;
        if (integral) {
            errno = 0;
            char* end = nullptr;
            const long long v = std::strtoll(text.c_str(), &end, 10);
            if (errno == 0 && end && *end == 0) { out = JsonValue::integer(v); return true; }
        }
        const double d = std::strtod(text.c_str(), nullptr);
        if (!std::isfinite(d)) return fail("number out of range", start);
        out = JsonValue::number(d);
        return true;
    }

    static bool hex4(std::string_view s, size_t at, uint32_t& v) {
        if (s.size() < at + 4) return false;
        v = 0;
        for (size_t i = 0; i < 4; ++i) {
            const char c = s[at + i];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else return false;
        }
        return true;
    }
    static void put_utf8(std::string& s, uint32_t cp) {
        if (cp < 0x80) s += static_cast<char>(cp);
        else if (cp < 0x800) { s += static_cast<char>(0xC0 | (cp >> 6)); s += static_cast<char>(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { s += static_cast<char>(0xE0 | (cp >> 12)); s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); s += static_cast<char>(0x80 | (cp & 0x3F)); }
        else { s += static_cast<char>(0xF0 | (cp >> 18)); s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F)); s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); s += static_cast<char>(0x80 | (cp & 0x3F)); }
    }

    // Validates one UTF-8 sequence starting at pos_ (lead byte >= 0x80), appends it. Rejects overlongs, surrogates, > U+10FFFF.
    bool utf8(std::string& out) {
        const unsigned char b0 = static_cast<unsigned char>(cur());
        size_t n; uint32_t cp;
        if (b0 >= 0xC2 && b0 <= 0xDF) { n = 2; cp = b0 & 0x1F; }
        else if (b0 >= 0xE0 && b0 <= 0xEF) { n = 3; cp = b0 & 0x0F; }
        else if (b0 >= 0xF0 && b0 <= 0xF4) { n = 4; cp = b0 & 0x07; }
        else return fail("invalid UTF-8");
        if (t_.size() - pos_ < n) return fail("truncated UTF-8 sequence");
        for (size_t i = 1; i < n; ++i) {
            const unsigned char b = static_cast<unsigned char>(t_[pos_ + i]);
            if ((b & 0xC0) != 0x80) return fail("invalid UTF-8");
            cp = (cp << 6) | (b & 0x3F);
        }
        if ((n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return fail("invalid UTF-8 (overlong, surrogate or out of range)");
        out.append(t_.substr(pos_, n));
        pos_ += n;
        return true;
    }

    bool string(std::string& out) {
        ++pos_;                                                            // opening quote
        for (;;) {
            if (eof()) return fail("unterminated string");
            const unsigned char c = static_cast<unsigned char>(cur());
            if (out.size() > lim_.max_string_bytes) return fail("string too long");
            if (c == '"') { ++pos_; return true; }
            if (c < 0x20) return fail("raw control character in string");
            if (c >= 0x80) { if (!utf8(out)) return false; continue; }
            if (c != '\\') { out += static_cast<char>(c); ++pos_; continue; }
            ++pos_;
            if (eof()) return fail("unterminated escape");
            const char e = cur();
            ++pos_;
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp;
                    if (!hex4(t_, pos_, cp)) return fail("invalid \\u escape");
                    pos_ += 4;
                    if (cp >= 0xDC00 && cp <= 0xDFFF) return fail("lone low surrogate");
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        uint32_t lo;
                        if (t_.size() - pos_ < 6 || t_[pos_] != '\\' || t_[pos_ + 1] != 'u' || !hex4(t_, pos_ + 2, lo) || lo < 0xDC00 || lo > 0xDFFF)
                            return fail("lone high surrogate");
                        pos_ += 6;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    if (cp == 0) return fail("NUL (\\u0000) is not allowed in strings");     // C-string consumers would truncate
                    put_utf8(out, cp);
                    break;
                }
                default: return fail("invalid escape");
            }
        }
    }

    std::string_view t_;
    JsonLimits lim_;
    size_t pos_ = 0;
    bool failed_ = false;
    JsonError err_;
};

void write_string(std::string& o, const std::string& s) {
    o += '"';
    for (const unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o += static_cast<char>(c);
        }
    }
    o += '"';
}

void write_value(std::string& o, const JsonValue& v, bool pretty, size_t indent) {
    auto nl = [&](size_t level) { if (pretty) { o += '\n'; o.append(level * 2, ' '); } };
    switch (v.type()) {
        case JsonValue::Type::Null: o += "null"; break;
        case JsonValue::Type::Bool: o += v.as_bool() ? "true" : "false"; break;
        case JsonValue::Type::Number: {
            if (v.is_integer()) { o += std::to_string(v.as_int()); break; }
            if (!std::isfinite(v.as_double())) { o += "null"; break; }
            char b[40];
            for (int prec = 15; prec <= 17; ++prec) {                       // shortest form that reads back exactly
                std::snprintf(b, sizeof b, "%.*g", prec, v.as_double());
                if (std::strtod(b, nullptr) == v.as_double()) break;
            }
            o += b;
            break;
        }
        case JsonValue::Type::String: write_string(o, v.as_string()); break;
        case JsonValue::Type::Array:
            if (v.items().empty()) { o += "[]"; break; }
            o += '[';
            for (size_t i = 0; i < v.items().size(); ++i) {
                if (i) o += ',';
                nl(indent + 1);
                write_value(o, v.items()[i], pretty, indent + 1);
            }
            nl(indent);
            o += ']';
            break;
        case JsonValue::Type::Object:
            if (v.members().empty()) { o += "{}"; break; }
            o += '{';
            for (size_t i = 0; i < v.members().size(); ++i) {
                if (i) o += ',';
                nl(indent + 1);
                write_string(o, v.members()[i].first);
                o += pretty ? ": " : ":";
                write_value(o, v.members()[i].second, pretty, indent + 1);
            }
            nl(indent);
            o += '}';
            break;
    }
}

}  // namespace

JsonParseResult parse_json(std::string_view text, const JsonLimits& limits) {
    JsonParseResult r;
    Parser p(text, limits);
    r.ok = p.run(r.value, r.error);
    if (!r.ok) r.value = JsonValue();
    return r;
}

std::string write_json(const JsonValue& v, bool pretty) {
    std::string o;
    write_value(o, v, pretty, 0);
    if (pretty) o += '\n';
    return o;
}

}  // namespace pf

// Minimal dependency-free test harness (portable to all target platforms,
// including Android/iOS where fetching third-party frameworks is awkward).
//
//   PF_CHECK(cond)      non-fatal: records the failure and keeps running the case
//   PF_CHECK_EQ(a, b)   non-fatal, prints both values on mismatch
//   PF_REQUIRE(cond)    fatal: aborts the current case (use before dereferencing etc.)
#pragma once
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace pf_test {

struct Case { std::string name; std::function<void()> fn; };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }

struct Registrar {
    Registrar(const char* n, std::function<void()> f) {
        for (auto& c : registry())
            if (c.name == n) {
                std::fprintf(stderr, "duplicate test name: %s\n", n);
                std::abort();
            }
        registry().push_back({n, std::move(f)});
    }
};

struct Fatal {};  // thrown by PF_REQUIRE

inline std::vector<std::string>& failures() { static std::vector<std::string> f; return f; }
inline void record(const char* file, int line, const std::string& what) {
    failures().push_back(std::string(file) + ":" + std::to_string(line) + ": " + what);
}

template <typename T>
std::string show(const T& v) {
    if constexpr (std::is_enum_v<T>) {
        return std::to_string(static_cast<long long>(static_cast<std::underlying_type_t<T>>(v)));
    } else if constexpr (std::is_same_v<T, bool>) {
        return v ? "true" : "false";
    } else if constexpr (std::is_integral_v<T>) {
        return std::to_string(+v);  // unary + prints uint8_t/char as numbers
    } else {
        std::ostringstream os; os << v; return os.str();
    }
}

}  // namespace pf_test

#define PF_TEST(name)                                                        \
    static void name();                                                      \
    static pf_test::Registrar reg_##name(#name, name);                       \
    static void name()

#define PF_CHECK(cond)                                                       \
    do { if (!(cond)) pf_test::record(__FILE__, __LINE__, "CHECK(" #cond ") failed"); } while (0)

#define PF_CHECK_EQ(a, b)                                                    \
    do { const auto& _a = (a); const auto& _b = (b);                         \
         if (!(_a == _b))                                                    \
             pf_test::record(__FILE__, __LINE__, "CHECK_EQ(" #a ", " #b ") failed: " + \
                             pf_test::show(_a) + " != " + pf_test::show(_b)); } while (0)

#define PF_REQUIRE(cond)                                                     \
    do { if (!(cond)) { pf_test::record(__FILE__, __LINE__, "REQUIRE(" #cond ") failed"); \
                        throw pf_test::Fatal{}; } } while (0)

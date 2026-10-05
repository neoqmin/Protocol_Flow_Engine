// Minimal dependency-free test harness (portable to all target platforms,
// including Android/iOS where fetching third-party frameworks is awkward).
#pragma once
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace pf_test {

struct Case { std::string name; std::function<void()> fn; };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }
struct Registrar {
    Registrar(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};
struct Failure { std::string msg; };

}  // namespace pf_test

#define PF_TEST(name)                                                        \
    static void name();                                                      \
    static pf_test::Registrar reg_##name(#name, name);                       \
    static void name()

#define PF_CHECK(cond)                                                       \
    do { if (!(cond)) throw pf_test::Failure{std::string(__FILE__) + ":" +   \
         std::to_string(__LINE__) + ": CHECK(" #cond ") failed"}; } while (0)

#define PF_CHECK_EQ(a, b)                                                    \
    do { auto _a = (a); auto _b = (b); if (!(_a == _b))                      \
         throw pf_test::Failure{std::string(__FILE__) + ":" +                \
         std::to_string(__LINE__) + ": CHECK_EQ(" #a ", " #b ") failed"}; } while (0)

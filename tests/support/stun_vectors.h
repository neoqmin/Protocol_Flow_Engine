// Loader for tests/regression/golden/stun_rfc5769.golden (RFC 5769 section 2 vectors).
#pragma once
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "pf_test.h"

namespace pf_test {

struct StunVector {
    std::string name;
    bool long_term = false;
    std::string password;              // short-term password, or the prepared long-term password
    std::string username, realm;       // long-term only
    std::vector<uint8_t> bytes;
};

inline std::vector<uint8_t> stun_unhex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
    return v;
}

inline std::vector<StunVector> load_stun_vectors(const std::string& golden_dir) {
    std::vector<StunVector> out;
    std::ifstream f(golden_dir + "/stun_rfc5769.golden");
    PF_REQUIRE(f.good());
    auto trim = [](const std::string& s) {
        const size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t\r");
        return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
    };
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> c;
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, '|')) c.push_back(trim(cell));
        PF_REQUIRE(c.size() == 3);
        StunVector v;
        v.name = c[0];
        v.bytes = stun_unhex(c[2]);
        if (c[1].rfind("short:", 0) == 0) {
            v.password = c[1].substr(6);
        } else {
            PF_REQUIRE(c[1].rfind("long:", 0) == 0);
            v.long_term = true;
            std::stringstream cs(c[1].substr(5));
            std::string user_hex;
            std::getline(cs, user_hex, ':');
            std::getline(cs, v.realm, ':');
            std::getline(cs, v.password);
            const auto u = stun_unhex(user_hex);
            v.username.assign(u.begin(), u.end());
        }
        out.push_back(std::move(v));
    }
    PF_REQUIRE(out.size() == 4);
    return out;
}

}  // namespace pf_test

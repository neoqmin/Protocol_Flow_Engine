#include "pf_test.h"

int main(int argc, char** argv) {
    std::string filter = argc > 1 ? argv[1] : "";
    int failed = 0, ran = 0;
    for (auto& c : pf_test::registry()) {
        if (!filter.empty() && c.name.find(filter) == std::string::npos) continue;
        ++ran;
        try { c.fn(); std::cout << "[ OK ] " << c.name << "\n"; }
        catch (const pf_test::Failure& f) { ++failed; std::cout << "[FAIL] " << c.name << "\n       " << f.msg << "\n"; }
        catch (const std::exception& e) { ++failed; std::cout << "[FAIL] " << c.name << "\n       exception: " << e.what() << "\n"; }
    }
    std::cout << ran - failed << "/" << ran << " passed\n";
    return failed ? 1 : 0;
}

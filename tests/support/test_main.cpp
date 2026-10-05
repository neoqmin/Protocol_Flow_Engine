#include "pf_test.h"

int main(int argc, char** argv) {
    std::string filter = argc > 1 ? argv[1] : "";
    int failed = 0, ran = 0;
    for (auto& c : pf_test::registry()) {
        if (!filter.empty() && c.name.find(filter) == std::string::npos) continue;
        ++ran;
        pf_test::failures().clear();
        try { c.fn(); }
        catch (const pf_test::Fatal&) {}
        catch (const std::exception& e) { pf_test::failures().push_back(std::string("exception: ") + e.what()); }
        catch (...) { pf_test::failures().push_back("unknown exception"); }

        if (pf_test::failures().empty()) {
            std::cout << "[ OK ] " << c.name << "\n";
        } else {
            ++failed;
            std::cout << "[FAIL] " << c.name << "\n";
            for (auto& f : pf_test::failures()) std::cout << "       " << f << "\n";
        }
    }
    std::cout << ran - failed << "/" << ran << " passed\n";
    return failed ? 1 : 0;
}

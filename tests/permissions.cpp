#include "core.h"
#include <windows.h>
#include <array>
#include <iostream>

int main() {
    try {
        std::array<BYTE, SECURITY_MAX_SID_SIZE> admin{};
        DWORD bytes = static_cast<DWORD>(admin.size());
        if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin.data(), &bytes)) return 1;
        BOOL member = TRUE;
        if (!CheckTokenMembership(nullptr, admin.data(), &member)) return 1;
        if (member) { std::cout << "Run this test under an ordinary user account to validate permissions.\n"; return 77; }
        for (const auto* mode : {"summary", "distributions", "configuration", "prerequisites"}) {
            const auto json = wd::collect(mode).json(mode).dump();
            if (json.empty() || json.front() != '{') return 1;
        }
        std::cout << "All collectors succeeded without enabled Administrators membership.\n";
        return 0;
    } catch (...) { return 1; }
}

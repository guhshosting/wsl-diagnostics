#include "core.h"
#include <windows.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace {
void output(const std::string& text, bool error = false) {
    const HANDLE stream = GetStdHandle(error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (stream != INVALID_HANDLE_VALUE && GetConsoleMode(stream, &mode)) {
        const auto unicode = wd::wide(text);
        DWORD written = 0;
        std::size_t offset = 0;
        while (offset < unicode.size()) {
            auto chunk = static_cast<DWORD>((std::min)(unicode.size() - offset, std::size_t{16384}));
            if (offset + chunk < unicode.size() && unicode[offset + chunk - 1] >= 0xd800 && unicode[offset + chunk - 1] <= 0xdbff) --chunk;
            if (!WriteConsoleW(stream, unicode.data() + offset, chunk, &written, nullptr) || !written) throw std::runtime_error("Console output failed");
            offset += written;
        }
    } else {
        auto& target = error ? std::cerr : std::cout;
        target << text;
        target.flush();
        if (!target) throw std::runtime_error("Output failed");
    }
}
}
int wmain(int argc, wchar_t* argv[]) {
    try {
        std::string mode = "summary";
        bool json = false, command = false;
        for (int i = 1; i < argc; ++i) {
            const auto arg = wd::utf8(argv[i]);
            if (arg == "--help" || arg == "-h") {
                output("wsl-diagnostics 1.0.0 — Windows read-only WSL diagnostics\nUsage: wsl-diagnostics [--json] [summary|distributions|configuration|prerequisites]\n       wsl-diagnostics --help | --version\nNo WSL processes, Linux commands, changes, telemetry, or network probes.\nUnavailable evidence is distinct from absence. Exit: 0 report, 1 failure, 2 usage.\n"); return 0;
            }
            if (arg == "--version") { output("wsl-diagnostics 1.0.0\n"); return 0; }
            if (arg == "--json" && !json) { json = true; continue; }
            if (!command && (arg == "summary" || arg == "distributions" || arg == "configuration" || arg == "prerequisites")) { mode = arg; command = true; continue; }
            output("Invalid argument: " + arg + "\nUse --help for usage.\n", true); return 2;
        }
        const auto report = wd::collect(mode).json(mode);
        output(json ? report.dump() + '\n' : wd::render_text(report));
        return 0;
    } catch (const std::exception& e) {
        try { output(std::string("Diagnostic failed: ") + e.what() + '\n', true); } catch (...) { return 1; }
        return 1;
    }
}

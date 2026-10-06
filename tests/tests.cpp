#include "core.h"
#include <algorithm>
#include <windows.h>
#include <iostream>
#include <stdexcept>

namespace {
void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
bool finding(const wd::Report& r, const char* code) {
    return std::any_of(r.findings.begin(), r.findings.end(), [code](const wd::Json& f) { return std::get<std::string>(std::get<wd::Json::Object>(f.data).at("code").data) == code; });
}
struct FixtureFile {
    std::wstring path;
    FixtureFile() {
        std::vector<wchar_t> directory(32768, L'\0');
        const DWORD length = GetCurrentDirectoryW(32768, directory.data());
        check(length && length < 32768, "fixture directory");
        path = std::wstring(directory.data()) + L"\\config-fixture-" + std::to_wstring(GetCurrentProcessId()) + L"-\u65e5\u672c.ini";
    }
    ~FixtureFile() { DeleteFileW(path.c_str()); }
    FixtureFile(const FixtureFile&) = delete;
    FixtureFile& operator=(const FixtureFile&) = delete;
    void write(const std::string& bytes) const {
        const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        check(file != INVALID_HANDLE_VALUE, "create isolated fixture");
        DWORD written = 0;
        const BOOL ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
        CloseHandle(file);
        check(ok && written == bytes.size(), "write fixture");
    }
    void remove() const { check(DeleteFileW(path.c_str()) != 0, "remove fixture"); }
};
void file_tests() {
    FixtureFile fixture;
    check(wd::read_configuration_file(fixture.path).file.state == "absent", "missing configuration file acquisition");
    fixture.write("[wsl2]\nprocessors=2\nfuture=value\n");
    auto config = wd::read_configuration_file(fixture.path);
    check(config.file.state == "present" && !config.malformed && config.entries.size() == 3, "real bounded configuration read");
    const HANDLE held = CreateFileW(fixture.path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    check(held != INVALID_HANDLE_VALUE, "hold fixture");
    config = wd::read_configuration_file(fixture.path);
    CloseHandle(held);
    check(config.file.state == "unavailable" && config.file.error == ERROR_SHARING_VIOLATION, "file acquisition failure");
    fixture.remove();
    std::string utf16("\xff\xfe", 2);
    for (wchar_t c : std::wstring(L"[wsl2]\nprocessors=3\n")) {
        const auto unit = static_cast<unsigned>(c);
        utf16 += static_cast<char>(unit & 255U); utf16 += static_cast<char>(unit >> 8U);
    }
    fixture.write(utf16);
    config = wd::read_configuration_file(fixture.path);
    check(!config.malformed && config.entries.back().value == "3", "UTF-16LE acquisition");
    fixture.remove(); fixture.write("\xff");
    config = wd::read_configuration_file(fixture.path);
    check(config.file.state == "present" && config.malformed, "malformed encoding acquisition");
    fixture.remove(); fixture.write(std::string(1024 * 1024 + 1, 'x'));
    check(wd::read_configuration_file(fixture.path).file.state == "unsupported", "bounded input");
    check(wd::read_configuration_file(L"\\\\example.invalid\\share\\config").file.state == "unsupported", "UNC rejected before access");
    check(wd::read_configuration_file(L"relative.ini").file.state == "unsupported", "relative rejected");
}
}
int main() {
    try {
        file_tests();
        check(wd::Json("a\n\t\"\\\x01").dump() == "\"a\\n\\t\\\"\\\\\\u0001\"", "JSON escaping");
        check(wd::Json(nullptr).dump() == "null", "explicit JSON null");
        check(wd::Json(wd::Json::Object{{"z", nullptr}, {"a", false}}).dump() == "{\"a\":false,\"z\":null}", "JSON deterministic order/null");
        auto config = wd::parse_config("\xef\xbb\xbf[wsl2]\r\nmemory=4GB\r\nprocessors=2\r\nswap=0\r\nlocalhostForwarding=true\r\nnetworkingMode=mirrored\r\nvmIdleTimeout=-1\r\nkernel=C:\\\\kernel\r\nkernelCommandLine=a=b # retained\r\n");
        check(!config.malformed && config.entries.size() == 9, "recognized config");
        check(config.entries.back().value == "a=b # retained", "preserve value");
        config = wd::parse_config("[wsl2]\nfutureKey=abc\n[future]\nfoo=bar\n[experimental]\nautoMemoryReclaim=gradual\n");
        check(!config.malformed && config.entries[1].status == "unknown" && config.entries[1].raw == "futureKey=abc", "unknown preservation");
        config = wd::parse_config("orphan=x\n[bad\n[wsl2]\nprocessors=0\nmemory=lots\nfirewall=1\nmissing_equals\nswap=1GB\nSwap=2GB\n");
        check(config.malformed && config.entries.back().status == "duplicate", "malformed and duplicate");
        constexpr char embedded[] = "[wsl2]\nkey=\0bad";
        check(wd::parse_config(std::string(embedded, sizeof(embedded) - 1)).malformed, "embedded NUL");
        check(!wd::parse_config("").malformed, "empty config");
        check(wd::parse_config("[wsl2]\nprocessors=4294967296\n").malformed, "integer overflow");
        check(wd::parse_config("[wsl2]\nkernel=\\\\server\\kernel\n").malformed, "nonlocal path syntax");
        check(wd::parse_config("[wsl2]\nmemory=0GB\n").malformed, "zero memory");
        const std::wstring unicode = L"distribution-\u65e5\u672c-\U0001f427";
        check(wd::wide(wd::utf8(unicode)) == unicode, "Unicode roundtrip");
        bool rejected = false;
        try { (void)wd::wide("\xff"); } catch (const std::exception&) { rejected = true; }
        check(rejected, "invalid UTF-8");
        wd::Report report;
        report.registrations = {"available", 0, "fixture", ""};
        report.configuration.file = {"absent", nullptr, "fixture", "Missing file."};
        report.summary["wsl_detection"] = {"absent", nullptr, "fixture", "Absent system fixture."};
        report.summary["runtime_version"] = {"unavailable", nullptr, "fixture", ""};
        report.prerequisites["virtual_machine_platform_feature"] = {"unavailable", nullptr, "fixture", ""};
        wd::derive_findings(report);
        check(finding(report, "no_registered_distributions"), "zero distribution fixture");
        const auto absent = report.json("summary").dump();
        check(absent.find("\"state\":\"absent\"") != std::string::npos && absent.find("\"state\":\"unavailable\"") != std::string::npos, "absent/unavailable fixtures");
        check(absent.find("\"effective_settings_verified\":false") != std::string::npos, "configuration effectiveness");
        wd::Distribution one, two;
        one.id = "{one}"; one.name = {"available", "Ubuntu \u65e5\u672c", "fixture", ""}; one.generation = {"available", 1, "fixture", ""};
        two.id = "{two}"; two.generation = {"available", 2, "fixture", ""};
        report.distributions = {one, two}; report.registrations.value = 2;
        const auto rendered = wd::render_text(report.json("summary"));
        check(rendered.find("distributions[0].generation: available (1)") != std::string::npos, "text renderer handles nonempty distributions");
        check(rendered.find("distributions[1].state: unavailable") != std::string::npos, "nested state observation renders");
        wd::derive_findings(report);
        check(finding(report, "mixed_generations") && finding(report, "wsl2_prerequisites_unverified"), "mixed generations fixture");
        check(!finding(report, "no_registered_distributions"), "no stale finding");
        report.configuration = wd::parse_config("[wsl2]\nprocessors=-2\n");
        wd::derive_findings(report); check(finding(report, "configuration_malformed"), "malformed finding");
        report.registrations.state = "access_denied"; report.distributions.clear();
        wd::derive_findings(report); check(!finding(report, "no_registered_distributions"), "incomplete enumeration is not zero");
        for (const auto* state : {"present", "absent", "enabled", "disabled", "available", "unavailable", "access_denied", "unsupported", "not_applicable", "unknown"}) {
            const wd::Observation o{state, nullptr, "fixture", "", 5};
            check(o.json().dump().find("\"value\":null") != std::string::npos, "states preserve null");
        }
        check(report.json("configuration").dump().find("\"summary\"") == std::string::npos, "mode projection");
        std::cout << "All unit fixtures passed\n";
        return 0;
    } catch (const std::exception& e) {
        try { std::cerr << e.what() << '\n'; } catch (...) { return 1; }
        return 1;
    } catch (...) { return 1; }
}

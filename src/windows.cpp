#include "core.h"
#include <windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <intrin.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <type_traits>

namespace wd {
namespace {
constexpr DWORD max_bytes = 1024 * 1024;
constexpr const wchar_t* lxss = L"Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";
struct RegCloser { void operator()(HKEY h) const noexcept { if (h) RegCloseKey(h); } };
using Reg = std::unique_ptr<std::remove_pointer_t<HKEY>, RegCloser>;
struct HandleCloser { void operator()(HANDLE h) const noexcept { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); } };
using Handle = std::unique_ptr<void, HandleCloser>;
struct ServiceCloser { void operator()(SC_HANDLE h) const noexcept { if (h) CloseServiceHandle(h); } };
using Service = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, ServiceCloser>;
Observation error_observation(DWORD code, const std::string& source) {
    std::string state = "unavailable";
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND || code == ERROR_SERVICE_DOES_NOT_EXIST) state = "absent";
    else if (code == ERROR_ACCESS_DENIED) state = "access_denied";
    return {state, nullptr, source, "Win32 result; absence describes only this source.", code};
}
Reg open_key(HKEY parent, const wchar_t* name, Observation& status) {
    HKEY raw = nullptr;
    const LSTATUS result = RegOpenKeyExW(parent, name, 0, KEY_READ | KEY_WOW64_64KEY, &raw);
    if (result != ERROR_SUCCESS) status = error_observation(static_cast<DWORD>(result), "registry");
    else status = {"available", nullptr, "registry", "Read-only native registry view."};
    return Reg(raw);
}
Observation reg_value(HKEY key, const wchar_t* name, bool number = false) {
    const std::string source = "HKCU\\" + utf8(lxss) + " / " + utf8(name);
    DWORD type = 0, bytes = 0;
    LSTATUS result = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
    if (result != ERROR_SUCCESS) return error_observation(static_cast<DWORD>(result), source);
    if (number) {
        DWORD value = 0; bytes = sizeof(value);
        result = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &bytes);
        if (result != ERROR_SUCCESS) return error_observation(static_cast<DWORD>(result), source);
        if (type != REG_DWORD || bytes != sizeof(value)) return {"unknown", nullptr, source, "Unexpected registry value type."};
        return {"available", static_cast<std::int64_t>(value), source, "Registration metadata; not a live runtime observation."};
    }
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || bytes > max_bytes || bytes % sizeof(wchar_t) != 0) return {"unknown", nullptr, source, "Unsupported type or oversized registry value."};
    std::vector<wchar_t> value(static_cast<std::size_t>(bytes) / sizeof(wchar_t) + 1, L'\0');
    result = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(value.data()), &bytes);
    if (result != ERROR_SUCCESS) return error_observation(static_cast<DWORD>(result), source);
    if (type != REG_SZ && type != REG_EXPAND_SZ) return {"unknown", nullptr, source, "Registry changed during read."};
    if (bytes % sizeof(wchar_t) || bytes > (value.size() - 1) * sizeof(wchar_t)) return {"unknown", nullptr, source, "Registry changed during read."};
    std::wstring text(value.data(), bytes / sizeof(wchar_t));
    if (!text.empty() && text.back() == L'\0') text.pop_back();
    if (text.find(L'\0') != std::wstring::npos) return {"unknown", nullptr, source, "Embedded NUL in registration metadata."};
    try { return {"available", utf8(text), source, "Unexpanded registration metadata; not verified on disk."}; }
    catch (const std::exception&) { return {"unknown", nullptr, source, "Invalid UTF-16 in registration metadata."}; }
}
Observation service_state(SC_HANDLE manager, const wchar_t* name) {
    Service service(OpenServiceW(manager, name, SERVICE_QUERY_STATUS));
    const std::string source = "Service Control Manager / " + utf8(name);
    if (!service) return error_observation(GetLastError(), source);
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &needed)) return error_observation(GetLastError(), source);
    const char* state = "other";
    switch (status.dwCurrentState) {
    case SERVICE_RUNNING: state = "running"; break;
    case SERVICE_STOPPED: state = "stopped"; break;
    case SERVICE_START_PENDING: state = "start_pending"; break;
    case SERVICE_STOP_PENDING: state = "stop_pending"; break;
    case SERVICE_PAUSED: state = "paused"; break;
    default: break;
    }
    return {"present", state, source, "Service status does not establish distribution state or optional-feature enablement."};
}
// Never follow a reparse point or access a UNC/mapped-network path. Check each
// parent before inspecting children; this also avoids cloud recall and junctions.
Observation local_path(const std::wstring& path) {
    const std::string source = utf8(path);
    if (path.size() < 3 || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') || !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'))) return {"unsupported", nullptr, source, "Only absolute local drive paths are inspected; UNC/device/relative paths are not accessed."};
    const std::wstring root = path.substr(0, 2) + L"\\";
    const UINT kind = GetDriveTypeW(root.c_str());
    if (kind != DRIVE_FIXED && kind != DRIVE_RAMDISK) return {"unsupported", nullptr, source, "Only fixed local disks and RAM disks are inspected; no remote or removable access."};
    std::wstring current = root;
    std::size_t start = 3;
    DWORD attributes = GetFileAttributesW(current.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return error_observation(GetLastError(), source);
    while (start < path.size()) {
        const auto end = path.find_first_of(L"\\/", start);
        const auto part = path.substr(start, end == std::wstring::npos ? path.size() - start : end - start);
        if (part == L".." || part == L"." || part.find(L':') != std::wstring::npos) return {"unsupported", nullptr, source, "Dot components and alternate streams are not inspected."};
        if (!part.empty()) {
            if (current.back() != L'\\') current += L'\\';
            current += part;
            attributes = GetFileAttributesW(current.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES) return error_observation(GetLastError(), source);
            if (attributes & static_cast<DWORD>(FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE)) return {"unsupported", nullptr, source, "Reparse points and offline files are not followed or recalled."};
        }
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return {"present", (attributes & FILE_ATTRIBUTE_DIRECTORY) ? "directory" : "file", source, "Local path observed; contents/effectiveness unverified."};
}
Config read_config_path(const std::wstring& path) {
    Config config;
    config.file = local_path(path);
    if (config.file.state != "present") return config;
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE) { config.file = error_observation(GetLastError(), utf8(path)); return config; }
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &tag, sizeof(tag))) { config.file = error_observation(GetLastError(), utf8(path)); return config; }
    if (tag.FileAttributes & static_cast<DWORD>(FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_OFFLINE)) { config.file = {"unsupported", nullptr, utf8(path), "Not a regular locally available file."}; return config; }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size)) { config.file = error_observation(GetLastError(), utf8(path)); return config; }
    if (size.QuadPart < 0 || size.QuadPart > max_bytes) { config.file = {"unsupported", nullptr, utf8(path), "File exceeds 1 MiB input limit."}; return config; }
    std::string input(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file.get(), input.data(), static_cast<DWORD>(input.size()), &read, nullptr)) { config.file = error_observation(GetLastError(), utf8(path)); return config; }
    if (read != input.size()) { config.file = {"unavailable", nullptr, utf8(path), "File changed or short read; retry diagnostic."}; return config; }
    try {
        if (input.size() >= 2 && static_cast<unsigned char>(input[0]) == 0xff && static_cast<unsigned char>(input[1]) == 0xfe) {
            if (input.size() % 2) throw std::runtime_error("Odd UTF-16 byte count");
            std::wstring decoded;
            for (std::size_t i = 2; i < input.size(); i += 2) decoded += static_cast<wchar_t>(static_cast<unsigned>(static_cast<unsigned char>(input[i])) | (static_cast<unsigned>(static_cast<unsigned char>(input[i + 1])) << 8U));
            input = utf8(decoded);
        } else { (void)wide(input); }
        config = parse_config(input);
        config.file.source = utf8(path);
    } catch (const std::exception&) {
        config.file = {"present", nullptr, utf8(path), "Invalid encoding; expected UTF-8 or UTF-16LE BOM."};
        config.malformed = true;
    }
    return config;
}
Config read_config() {
    PWSTR raw = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(FOLDERID_Profile, KF_FLAG_DONT_VERIFY, nullptr, &raw);
    if (FAILED(hr)) { Config config; config.file = {"unavailable", nullptr, "KnownFolder Profile", "Profile path unavailable.", static_cast<DWORD>(hr)}; return config; }
    const std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> owned(raw, &CoTaskMemFree);
    const std::wstring path = std::wstring(owned.get()) + L"\\.wslconfig";
    return read_config_path(path);
}
std::string architecture(WORD arch) {
    switch (arch) {
    case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
    case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
    case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
    default: return "unknown";
    }
}
Observation executable_version(const std::wstring& path) {
    auto inspected = local_path(path);
    if (inspected.state != "present") return inspected;
    DWORD ignored = 0;
    const DWORD bytes = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!bytes) return error_observation(GetLastError(), "wsl.exe version resource");
    if (bytes > max_bytes) return {"unsupported", nullptr, "wsl.exe version resource", "Oversized resource."};
    std::vector<BYTE> buffer(bytes);
    if (!GetFileVersionInfoW(path.c_str(), 0, bytes, buffer.data())) return error_observation(GetLastError(), "wsl.exe version resource");
    void* raw = nullptr; UINT length = 0;
    if (!VerQueryValueW(buffer.data(), L"\\", &raw, &length) || length < sizeof(VS_FIXEDFILEINFO) || !raw) return {"unavailable", nullptr, "wsl.exe version resource", "Fixed version resource unavailable."};
    VS_FIXEDFILEINFO info{}; std::memcpy(&info, raw, sizeof(info));
    return {"available", std::to_string(HIWORD(info.dwFileVersionMS)) + '.' + std::to_string(LOWORD(info.dwFileVersionMS)) + '.' + std::to_string(HIWORD(info.dwFileVersionLS)) + '.' + std::to_string(LOWORD(info.dwFileVersionLS)), "wsl.exe version resource", "Client file version; may be an inbox launcher, not the Store runtime or kernel version."};
}
void distributions(Report& r) {
    auto parent = open_key(HKEY_CURRENT_USER, lxss, r.registrations);
    r.registrations.source = "HKCU\\" + utf8(lxss);
    if (!parent) {
        r.summary["default_distribution"] = r.registrations;
        r.summary["default_generation"] = r.registrations;
        if (r.registrations.state == "absent") { r.registrations.state = "available"; r.registrations.value = 0; r.registrations.detail = "Registration key absent; zero registrations visible in this source for the current user."; }
        return;
    }
    const auto default_id = reg_value(parent.get(), L"DefaultDistribution");
    r.summary["default_distribution"] = default_id;
    r.summary["default_generation"] = reg_value(parent.get(), L"DefaultVersion", true);
    for (DWORD index = 0; index < 4096; ++index) {
        wchar_t name[256]{}; DWORD length = 256;
        const auto status = RegEnumKeyExW(parent.get(), index, name, &length, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) { r.registrations.value = static_cast<std::int64_t>(r.distributions.size()); return; }
        if (status != ERROR_SUCCESS) { r.registrations = error_observation(static_cast<DWORD>(status), "Registration enumeration"); r.registrations.detail = "Enumeration incomplete; array is partial."; return; }
        Distribution d; d.id = utf8(std::wstring(name, length));
        Observation opened;
        auto child = open_key(parent.get(), name, opened);
        if (child) {
            d.name = reg_value(child.get(), L"DistributionName");
            d.generation = reg_value(child.get(), L"Version", true);
            if (auto* v = std::get_if<std::int64_t>(&d.generation.value.data); v && *v != 1 && *v != 2) d.generation.state = "unknown";
            d.base_path = reg_value(child.get(), L"BasePath");
            d.package = reg_value(child.get(), L"PackageFamilyName");
        } else { d.name = d.generation = d.base_path = d.package = opened; }
        d.state = {"unavailable", nullptr, "No live WSL query", "Registry State is not interpreted as running/stopped/installing; no WSL process is invoked."};
        if (const auto* id = std::get_if<std::string>(&default_id.value.data)) d.is_default = {"available", _wcsicmp(wide(*id).c_str(), name) == 0, "DefaultDistribution registry value", "Current-user registration metadata."};
        else d.is_default = {"unknown", nullptr, default_id.source, "Default identity unavailable."};
        r.distributions.push_back(std::move(d));
    }
    r.registrations = {"unavailable", nullptr, "Registration enumeration", "4096 entry limit reached; array is partial."};
}
}
Config read_configuration_file(const std::wstring& path) { return read_config_path(path); }
std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    if (s.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw std::runtime_error("Unicode input too large");
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!count) throw std::runtime_error("Invalid UTF-16");
    std::string result(static_cast<std::size_t>(count), '\0');
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), result.data(), count, nullptr, nullptr)) throw std::runtime_error("UTF-16 conversion failed");
    return result;
}
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    if (s.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) throw std::runtime_error("Unicode input too large");
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!count) throw std::runtime_error("Invalid UTF-8");
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), result.data(), count)) throw std::runtime_error("UTF-8 conversion failed");
    return result;
}
Report collect(const std::string& mode) {
    Report r;
    if (mode == "summary" || mode == "distributions") {
        distributions(r);
        std::sort(r.distributions.begin(), r.distributions.end(), [](const Distribution& a, const Distribution& b) { return a.id < b.id; });
    }
    if (mode == "summary" || mode == "configuration") r.configuration = read_config();
    if (mode == "summary" || mode == "prerequisites") {
        SYSTEM_INFO native{}, process{}; GetNativeSystemInfo(&native); GetSystemInfo(&process);
        r.summary["native_architecture"] = {"available", architecture(native.wProcessorArchitecture), "GetNativeSystemInfo", "Native OS architecture."};
        r.summary["process_architecture"] = {"available", architecture(process.wProcessorArchitecture), "GetSystemInfo", "Process architecture."};
        const auto arch = architecture(native.wProcessorArchitecture);
        r.prerequisites["architecture_compatibility"] = {arch == "x64" || arch == "arm64" ? "available" : "unsupported", arch, "GetNativeSystemInfo", "x64/ARM64 are WSL 2 architecture candidates; this does not establish runtime support."};
        r.prerequisites["firmware_virtualization"] = {IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) ? "enabled" : "unknown", nullptr, "IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED)", "A negative API observation does not prove hardware lacks virtualization, especially inside a VM."};
        r.prerequisites["second_level_address_translation"] = {IsProcessorFeaturePresent(PF_SECOND_LEVEL_ADDRESS_TRANSLATION) ? "available" : "unknown", nullptr, "IsProcessorFeaturePresent(PF_SECOND_LEVEL_ADDRESS_TRANSLATION)", "Processor feature observation; a negative result is inconclusive in virtualized environments."};
#if defined(_M_X64) || defined(_M_IX86)
        int cpu[4]{}; __cpuid(cpu, 1);
        r.prerequisites["hypervisor"] = {(static_cast<unsigned>(cpu[2]) & 0x80000000U) ? "present" : "unknown", nullptr, "CPUID leaf 1 ECX bit 31", "Hypervisor indicator; does not identify Hyper-V or prove WSL 2 readiness."};
#else
        r.prerequisites["hypervisor"] = {"unsupported", nullptr, "CPUID", "CPUID observation is only implemented for x86/x64."};
#endif
        r.prerequisites["virtual_machine_platform_feature"] = {"unavailable", nullptr, "Optional-feature state", "No reliable non-elevated feature-state source is used. Service presence is not feature enablement."};
        r.prerequisites["wsl_optional_feature"] = r.prerequisites["virtual_machine_platform_feature"];
        r.prerequisites["wsl2_platform"] = {"unknown", nullptr, "Combined evidence", "Optional-feature state and runtime readiness are not established."};
        Service manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        for (const auto* name : {L"WslService", L"LxssManager", L"vmcompute"}) {
            r.prerequisites[utf8(name)] = manager ? service_state(manager.get(), name) : error_observation(GetLastError(), "Service Control Manager");
        }
    }
    if (mode == "summary") {
        using VersionFunction = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
        const HMODULE module = GetModuleHandleW(L"ntdll.dll");
        const auto symbol = module ? GetProcAddress(module, "RtlGetVersion") : nullptr;
        VersionFunction function = nullptr;
        static_assert(sizeof(function) == sizeof(symbol));
        // GetProcAddress's generic function pointer must be converted to the
        // documented ABI. Copying its representation avoids MSVC C4191.
        // NOLINTNEXTLINE(bugprone-bitwise-pointer-cast)
        std::memcpy(static_cast<void*>(&function), static_cast<const void*>(&symbol), sizeof(function));
        RTL_OSVERSIONINFOW version{}; version.dwOSVersionInfoSize = sizeof(version);
        r.summary["windows_version"] = function && function(&version) == 0 ? Observation{"available", std::to_string(version.dwMajorVersion) + '.' + std::to_string(version.dwMinorVersion) + '.' + std::to_string(version.dwBuildNumber), "RtlGetVersion", "Actual OS version/build, without product-name inference."} : Observation{"unavailable", nullptr, "RtlGetVersion", "OS version API unavailable."};
        wchar_t directory[MAX_PATH]{};
        const UINT length = GetSystemDirectoryW(directory, MAX_PATH);
        if (length && length < MAX_PATH) r.summary["client_executable_version"] = executable_version(std::wstring(directory, length) + L"\\wsl.exe");
        else r.summary["client_executable_version"] = error_observation(GetLastError(), "GetSystemDirectory");
        r.summary["runtime_version"] = {"unavailable", nullptr, "No WSL invocation", "Inbox client version is not authoritative Store runtime metadata."};
        r.summary["kernel_version"] = {"unavailable", nullptr, "No WSL invocation", "No kernel execution or distribution filesystem inspection."};
        r.summary["registered_count"] = r.registrations;
        r.summary["running_count"] = {"unavailable", nullptr, "No live WSL query", "Running state unavailable; not reported as zero."};
        bool detected = !r.distributions.empty();
        bool sources_absent = r.registrations.state == "available";
        for (const auto* name : {"WslService", "LxssManager"}) {
            const auto& service = r.prerequisites.at(name);
            detected = detected || service.state == "present";
            sources_absent = sources_absent && service.state == "absent";
        }
        r.summary["wsl_detection"] = {detected ? "present" : "unknown", nullptr, "Registrations and WSL service presence", sources_absent ? "No registrations or WSL services observed. A launcher alone does not prove an installed runtime; absence of all WSL forms cannot be established." : "Presence is evidence of registration or service metadata, not runtime health."};
        bool one = false, two = false;
        for (const auto& d : r.distributions) if (const auto* n = std::get_if<std::int64_t>(&d.generation.value.data)) { one = one || *n == 1; two = two || *n == 2; }
        r.summary["wsl1_registrations"] = {r.registrations.state == "available" ? (one ? "present" : "absent") : "unknown", nullptr, "Registration versions", "Configured generation does not establish availability to launch."};
        r.summary["wsl2_registrations"] = {r.registrations.state == "available" ? (two ? "present" : "absent") : "unknown", nullptr, "Registration versions", "Configured generation does not establish availability to launch."};
        r.summary["wsl1_availability"] = {"unknown", nullptr, "Combined evidence", "Registration metadata is not a launchability test."};
        r.summary["wsl2_availability"] = r.prerequisites.at("wsl2_platform");
    }
    derive_findings(r);
    if (mode == "summary" || mode == "configuration") {
        for (const auto& e : r.configuration.entries) {
            if (e.section != "wsl2" || e.status != "recognized") continue;
            std::string key = e.key; std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (key != "kernel" && key != "swapfile") continue;
            std::wstring path = wide(e.value);
            // WSL INI paths commonly contain escaped backslashes.
            for (std::size_t i = 0; i + 1 < path.size(); ++i) if (path[i] == L'\\' && path[i + 1] == L'\\') path.erase(i, 1);
            if (key == "swapfile") { const auto slash = path.find_last_of(L"\\/"); if (slash != std::wstring::npos) path.resize(slash == 2 ? 3 : slash); }
            const auto observed = local_path(path);
            r.findings.emplace_back(Json::Object{{"code", key == "kernel" ? "configured_kernel_path" : "configured_swap_parent"}, {"severity", observed.state == "absent" ? "warning" : "info"}, {"line", static_cast<std::int64_t>(e.line)}, {"message", "Configured path inspection; no setting effectiveness is inferred."}, {"observation", observed.json()}});
        }
    }
    return r;
}
}

#include "core.h"
#include <algorithm>
#include <cctype>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <set>

namespace wd {
namespace {
std::string quote(const std::string& s) {
    const char* hex = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 32) { out += "\\u00"; out += hex[static_cast<unsigned>(c) >> 4U]; out += hex[static_cast<unsigned>(c) & 15U]; }
            else out += static_cast<char>(c);
        }
    }
    return out + '"';
}
std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t\r");
    if (first == std::string::npos) return {};
    return s.substr(first, s.find_last_not_of(" \t\r") - first + 1);
}
std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}
bool digits(const std::string& s, bool positive) {
    if (s.empty() || s.size() > 10) return false;
    std::uint64_t n = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        n = n * 10 + static_cast<unsigned>(c - '0');
    }
    return n <= 0xffffffffULL && (!positive || n != 0);
}
bool size_value(const std::string& s, bool allow_zero) {
    if (allow_zero && s == "0") return true;
    const auto p = s.find_first_not_of("0123456789");
    if (p == std::string::npos) return false;
    const auto suffix = lower(s.substr(p));
    return digits(s.substr(0, p), true) && (suffix == "kb" || suffix == "mb" || suffix == "gb" || suffix == "tb");
}
void text_value(const Json& j, std::ostringstream& out, const std::string& prefix) {
    if (const auto* obj = std::get_if<Json::Object>(&j.data)) {
        // Observations have a compact, readable representation.
        auto state = obj->find("state");
        if (state != obj->end() && std::holds_alternative<std::string>(state->second.data)) {
            out << prefix << ": " << std::get<std::string>(state->second.data);
            auto value = obj->find("value");
            if (value != obj->end() && !std::holds_alternative<std::nullptr_t>(value->second.data)) out << " (" << value->second.dump() << ')';
            auto detail = obj->find("detail");
            if (detail != obj->end()) out << " — " << std::get<std::string>(detail->second.data);
            out << '\n';
        } else for (const auto& item : *obj) text_value(item.second, out, prefix.empty() ? item.first : prefix + '.' + item.first);
    } else if (const auto* arr = std::get_if<Json::Array>(&j.data)) {
        if (arr->empty()) out << prefix << ": []\n";
        for (std::size_t i = 0; i < arr->size(); ++i) text_value((*arr)[i], out, prefix + '[' + std::to_string(i) + ']');
    } else out << prefix << ": " << j.dump() << '\n';
}
}
std::string Json::dump() const {
    if (std::holds_alternative<std::nullptr_t>(data)) return "null";
    if (auto p = std::get_if<bool>(&data)) return *p ? "true" : "false";
    if (auto p = std::get_if<std::int64_t>(&data)) return std::to_string(*p);
    if (auto p = std::get_if<std::string>(&data)) return quote(*p);
    std::string out;
    if (auto p = std::get_if<Object>(&data)) {
        out = "{";
        for (const auto& item : *p) { if (out.size() > 1) out += ','; out += quote(item.first) + ':' + item.second.dump(); }
        return out + '}';
    }
    out = "[";
    for (const auto& item : std::get<Array>(data)) { if (out.size() > 1) out += ','; out += item.dump(); }
    return out + ']';
}
Json Observation::json() const {
    return Json::Object{{"state", state}, {"value", value}, {"source", source}, {"detail", detail}, {"win32_error", static_cast<std::int64_t>(error)}};
}
Json Entry::json() const {
    return Json::Object{{"line", static_cast<std::int64_t>(line)}, {"section", section}, {"key", key}, {"value", value}, {"raw", raw}, {"status", status}, {"detail", detail}};
}
Json Config::json() const {
    Json::Array a;
    std::transform(entries.begin(), entries.end(), std::back_inserter(a), [](const Entry& e) { return e.json(); });
    return Json::Object{{"file", file.json()}, {"entries", a}, {"malformed", malformed}, {"effective_settings_verified", false}};
}
Json Distribution::json() const {
    return Json::Object{{"registration_id", id}, {"name", name.json()}, {"generation", generation.json()}, {"state", state.json()}, {"base_path", base_path.json()}, {"package_identity", package.json()}, {"default", is_default.json()}};
}
Json Report::json(const std::string& mode) const {
    Json::Object root{{"schema_version", 1}, {"tool_version", "1.0.0"}, {"mode", mode}, {"findings", findings}};
    if (mode == "summary") { Json::Object o; for (const auto& v : summary) o.emplace(v.first, v.second.json()); root.emplace("summary", o); }
    if (mode == "summary" || mode == "prerequisites") { Json::Object o; for (const auto& v : prerequisites) o.emplace(v.first, v.second.json()); root.emplace("prerequisites", o); }
    if (mode == "summary" || mode == "distributions") { Json::Array a; for (const auto& d : distributions) a.push_back(d.json()); root.emplace("registrations", registrations.json()); root.emplace("distributions", a); }
    if (mode == "summary" || mode == "configuration") root.emplace("configuration", configuration.json());
    return root;
}
Config parse_config(const std::string& input) {
    Config config; config.file = {"present", nullptr, ".wslconfig", "Parsed file contents; effectiveness is not established."};
    if (input.find('\0') != std::string::npos) {
        config.malformed = true;
        config.entries.push_back({0, {}, {}, {}, {}, "malformed", "Embedded NUL is not supported."});
        return config;
    }
    std::istringstream lines(input);
    std::string raw, section;
    std::size_t number = 0;
    std::set<std::string> seen;
    const std::set<std::string> booleans{"localhostforwarding", "nestedvirtualization", "dnstunneling", "firewall", "autoproxy", "debugconsole"};
    while (std::getline(lines, raw)) {
        ++number;
        if (number == 1 && raw.compare(0, 3, "\xef\xbb\xbf") == 0) raw.erase(0, 3);
        std::string s = trim(raw);
        if (s.empty() || s[0] == '#' || s[0] == ';') continue;
        Entry e{number, section, {}, {}, raw, "unknown", "Unrecognized section or key; preserved."};
        if (s[0] == '[') {
            if (s.size() < 3 || s.back() != ']' || s.find(']') != s.size() - 1) {
                section.clear(); e.status = "malformed"; e.detail = "Malformed section header.";
            } else { section = trim(s.substr(1, s.size() - 2)); e.section = section; e.status = section == "wsl2" || section == "experimental" ? "section" : "unknown"; e.detail = "Section header."; }
        } else {
            const auto eq = s.find('=');
            if (eq == std::string::npos || trim(s.substr(0, eq)).empty() || section.empty()) {
                e.status = "malformed"; e.detail = "Expected key=value inside a section.";
            } else {
                e.key = trim(s.substr(0, eq)); e.value = trim(s.substr(eq + 1));
                const auto key = lower(e.key);
                bool recognized = false, valid = false;
                if (section == "wsl2") {
                    if (booleans.count(key)) { recognized = true; valid = e.value == "true" || e.value == "false"; }
                    else if (key == "processors") { recognized = true; valid = digits(e.value, true); }
                    else if (key == "vmidletimeout") { recognized = true; valid = e.value == "-1" || digits(e.value, false); }
                    else if (key == "memory" || key == "swap") { recognized = true; valid = size_value(e.value, key == "swap"); }
                    else if (key == "networkingmode") { recognized = true; const auto v = lower(e.value); valid = v == "nat" || v == "none" || v == "mirrored" || v == "bridged" || v == "virtioproxy"; }
                    else if (key == "kernel" || key == "swapfile") { recognized = true; valid = e.value.size() >= 3 && std::isalpha(static_cast<unsigned char>(e.value[0])) != 0 && e.value[1] == ':' && (e.value[2] == '\\' || e.value[2] == '/'); }
                    else if (key == "kernelcommandline") { recognized = true; valid = true; }
                }
                if (recognized) { e.status = valid ? "recognized" : "malformed"; e.detail = valid ? "Syntax recognized; runtime support and effectiveness unverified." : "Unsupported value syntax for recognized key."; }
                auto identity = section; identity += '\n'; identity += key;
                if (!seen.insert(identity).second) { e.status = "duplicate"; e.detail = "Duplicate key; effective value is ambiguous."; config.malformed = true; }
            }
        }
        if (e.status == "malformed") config.malformed = true;
        config.entries.push_back(std::move(e));
    }
    return config;
}
void derive_findings(Report& r) {
    r.findings.clear();
    auto add = [&](const char* code, const char* severity, const char* message) { r.findings.emplace_back(Json::Object{{"code", code}, {"severity", severity}, {"message", message}}); };
    bool one = false, two = false;
    for (const auto& d : r.distributions) {
        if (const auto* n = std::get_if<std::int64_t>(&d.generation.value.data)) { one = one || *n == 1; two = two || *n == 2; }
    }
    if (r.registrations.state == "available" && r.distributions.empty()) add("no_registered_distributions", "info", "No distributions were observed in the current user's registration metadata.");
    if (one && two) add("mixed_generations", "info", "Both WSL 1 and WSL 2 registrations were observed.");
    if (two) add("wsl2_prerequisites_unverified", "info", "WSL 2 registrations exist; optional-feature state and runtime readiness are not established by these observations.");
    if (r.configuration.malformed) add("configuration_malformed", "warning", ".wslconfig contains malformed or duplicate entries; consult the reported lines.");
    if (r.summary.count("runtime_version") && r.summary.at("runtime_version").state == "unavailable") add("runtime_metadata_unavailable", "info", "Authoritative WSL runtime and kernel versions are unavailable without invoking WSL; executable version is separate evidence.");
}
std::string render_text(const Json& value) { std::ostringstream out; text_value(value, out, ""); return out.str(); }
}

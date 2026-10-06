#ifndef WD_CORE_H
#define WD_CORE_H
#include <cstdint>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace wd {
struct Json {
    using Object = std::map<std::string, Json>;
    using Array = std::vector<Json>;
    std::variant<std::nullptr_t, bool, std::int64_t, std::string, Object, Array> data;
    Json() : data(nullptr) {}
    // Implicit conversions intentionally support the small JSON value DSL.
    // cppcheck-suppress noExplicitConstructor
    Json(std::nullptr_t) : data(nullptr) {}
    Json(const Json&) = default;
    Json& operator=(const Json&) = default;
    // MSVC's std::map move allocates a sentinel and may throw. Keep that
    // possibility explicit rather than terminating on allocation failure.
    // NOLINTNEXTLINE(bugprone-unsafe-to-allow-exceptions)
    Json(Json&& other) noexcept(false) : data(std::move(other.data)) {}
    // NOLINTNEXTLINE(bugprone-unsafe-to-allow-exceptions)
    Json& operator=(Json&& other) noexcept(false) { data = std::move(other.data); return *this; }
    // cppcheck-suppress noExplicitConstructor
    Json(bool v) : data(v) {}
    // cppcheck-suppress noExplicitConstructor
    Json(int v) : data(static_cast<std::int64_t>(v)) {}
    // cppcheck-suppress noExplicitConstructor
    Json(std::int64_t v) : data(v) {}
    // cppcheck-suppress noExplicitConstructor
    Json(const char* v) : data(std::string(v)) {}
    // cppcheck-suppress noExplicitConstructor
    Json(std::string v) : data(std::move(v)) {}
    // cppcheck-suppress noExplicitConstructor
    Json(Object v) : data(std::move(v)) {}
    // cppcheck-suppress noExplicitConstructor
    Json(Array v) : data(std::move(v)) {}
    std::string dump() const;
};
// Aggregate moves may propagate allocation failures (MSVC map/JSON storage).
// They are not a no-throw contract; the CLI catches acquisition failures.
// NOLINTNEXTLINE(bugprone-exception-escape)
struct Observation {
    std::string state = "unavailable";
    Json value;
    std::string source;
    std::string detail;
    std::uint32_t error = 0;
    Json json() const;
};
struct Entry {
    std::size_t line = 0;
    std::string section, key, value, raw, status, detail;
    Json json() const;
};
// NOLINTNEXTLINE(bugprone-exception-escape)
struct Config {
    Observation file;
    std::vector<Entry> entries;
    bool malformed = false;
    Json json() const;
};
// NOLINTNEXTLINE(bugprone-exception-escape)
struct Distribution {
    std::string id;
    Observation name, generation, state, base_path, package, is_default;
    Json json() const;
};
// NOLINTNEXTLINE(bugprone-exception-escape)
struct Report {
    std::map<std::string, Observation> summary, prerequisites;
    Observation registrations;
    std::vector<Distribution> distributions;
    Config configuration;
    Json::Array findings;
    Json json(const std::string& mode) const;
};
Config parse_config(const std::string& input);
Config read_configuration_file(const std::wstring& path);
void derive_findings(Report& report);
Report collect(const std::string& mode);
std::string utf8(const std::wstring& input);
std::wstring wide(const std::string& input);
std::string render_text(const Json& value);
}
#endif

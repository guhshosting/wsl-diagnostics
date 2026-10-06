# wsl-diagnostics 1.0.0

> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


A portable Windows command-line application that explains local Windows-side
WSL evidence without changing WSL or entering a distribution. C++17, MIT,
no runtime third-party dependencies, no telemetry, no intentional network access.
Ordinary diagnostics use the current user's permissions; elevation is not required.

```text
wsl-diagnostics summary
wsl-diagnostics distributions
wsl-diagnostics configuration
wsl-diagnostics prerequisites
wsl-diagnostics --json summary
wsl-diagnostics --help
wsl-diagnostics --version
```

The default command is `summary`; `--json` can precede or follow the command.
Exit codes: 0 = report produced (including unavailable evidence and warnings),
1 = fatal acquisition/encoding/output failure, 2 = invalid command line.
Warnings are diagnostic observations, not a verdict that the machine is broken.
Redirected output is UTF-8 without a BOM; console output uses Unicode Win32 APIs.
Reports include names, local paths, and configured values: review before sharing.

## Architecture and acquisition

`src/windows.cpp` acquires evidence; `src/core.cpp` parses and renders deterministic
JSON and derives conservative findings; `src/main.cpp` handles CLI and output.
No shell or child process is created. **wsl.exe is never executed: no subcommands
are used.** Process timeout/failure tests are therefore not applicable. This
deliberate limit trades live state/version coverage for a small read-only surface.

Exactly these sources are inspected:

| Source | Observation and limits |
| --- | --- |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` (native 64-bit view) | Current-user registration subkeys, `DistributionName`, `Version`, `BasePath`, `PackageFamilyName`, root `DefaultDistribution` and `DefaultVersion`. Undocumented implementation metadata, subject to change; not a supported enumeration contract. Other users' registrations are not read. No registry writes. |
| Local Service Control Manager | `WslService`, `LxssManager`, `vmcompute`, using connect/query-status access only. Service presence or status does not prove optional-feature enablement or WSL readiness. |
| `RtlGetVersion` | Actual Windows major/minor/build; no marketing-name inference. Dynamically resolved from already loaded ntdll. |
| `GetSystemInfo`, `GetNativeSystemInfo` | Process and native architecture. |
| `IsProcessorFeaturePresent` | Firmware virtualization and SLAT observations. Negative observations remain unknown, especially in guests. |
| x86/x64 CPUID leaf 1 ECX bit 31 | Hypervisor presence indicator; does not identify Hyper-V or prove readiness. |
| System directory `wsl.exe` file version resource | Inbox client/launcher file version only. No execution. This is not authoritative Store WSL runtime/kernel metadata. |
| Known-folder current user profile `.wslconfig` | Bounded read of at most 1 MiB; UTF-8 (optional BOM) or UTF-16LE BOM. No rewrites. |
| Recognized `kernel` and `swapFile` paths | Local path attributes only (swap parent). No content reads, writes or opening VHDs. |

No `.wslconfig` setting is claimed to be effective. No `/etc/wsl.conf`, distribution
filesystem, networking, virtual switch, package inventory or Hyper-V configuration
is inspected. Root default distribution is reported as registration identity;
per-distribution default flags provide its association with the observed names.
Registry `State` is deliberately not mapped to running/stopped/installing. Live
distribution state and running count are **unavailable**, never zero by inference.
Default generation is metadata, not evidence of launchability.

Authoritative optional-feature state is unavailable: this version does not use an
elevated DISM session or scrape localized feature commands. `wsl1_availability`
and `wsl2_availability` therefore remain unknown. Registered generations and
virtualization/service observations are useful independent evidence. WSL detection
is present when registration or WSL service metadata exists; otherwise unknown.
Individual source absence is explicit; absence of every installation form is not
claimed. Partial enumeration is marked unavailable and retains observed entries.
Snapshots are not atomic; concurrent registration/configuration changes can occur.

## Configuration parser

Recognizes these keys in `[wsl2]`, case-insensitively: `memory`, `processors`,
`swap`, `localhostForwarding`, `nestedVirtualization`, `networkingMode`,
`dnsTunneling`, `firewall`, `autoProxy`, `kernel`, `kernelCommandLine`,
`debugConsole`, `vmIdleTimeout`, `swapFile`. Section names are case-sensitive.
`[experimental]` is preserved but its keys are not interpreted.

Sizes accept positive integer KB/MB/GB/TB (case-insensitive); swap also accepts
bare 0. Processor count is a positive uint32. vmIdleTimeout accepts uint32 or -1.
Booleans accept literal `true` or `false`. Networking modes: nat, none, mirrored,
bridged, virtioproxy; recognition does not imply version support, and bridged is
deprecated upstream. Paths require an absolute drive path; doubled backslashes
are decoded only for path inspection. No environment expansion or quoting syntax
is applied. Whole-line `#`/`;` comments are skipped; inline characters remain
part of values. Unknown keys/sections, raw non-comment lines and original line
numbers are preserved. Duplicates and invalid recognized values are reported;
no ambiguous effective-value selection is made. This is a conservative parser,
not a complete recreation of WSL's parser. See [Microsoft configuration reference](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

## Read-only and network policy

No install/update/register/start/stop/terminate/mount/repair/configuration actions,
Linux commands or distribution shells exist in the application. It requests
read/query-only registry/service/file rights. It creates no sockets, resolves no
hosts, sends no DNS/HTTP, downloads nothing and performs no network probes.
SCM access is local. The app does not execute WSL and thus initiates none of WSL's
internal IPC. Windows APIs can use local OS IPC internally.

File inspection rejects UNC/device/relative paths, network/removable drives,
alternate streams, dot components, offline files and reparse points encountered
in each path component. It never intentionally accesses network files or recalls
cloud files. Concurrent hostile replacement of parent directories is outside this
diagnostic's threat model; path checks are not an atomic filesystem sandbox.
Even read-only reads may cause normal OS access-time, cache, audit or antivirus
activity; the application makes no modification requests.

## Compatibility and build

Targets Windows 10 and Windows 11 with applicable WSL functionality. Build uses
Windows 10 API baseline (`_WIN32_WINNT=0x0A00`); Server 2025 is a development host,
not the minimum supported version. Store WSL and inbox WSL do not expose identical
metadata. Missing sources or access denial are reported explicitly. x64 is the
release target; ARM64/x86 packages are not qualified or supplied.

Use MSVC Build Tools with C++ tools, Windows SDK and CMake 3.24+:

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cpack --config build/CPackConfig.cmake -C Release -B artifacts
```

Visual Studio 2022 is also supported; substitute its generator. All project code
builds with `/W4 /WX /analyze /permissive- /sdl`; static CRT makes the executable
portable without a separate VC runtime installation. No dependencies are fetched.
`scripts/validate.ps1` reproduces Release build, CTest, clang-tidy and Cppcheck
checks if installed. [JSON contract](docs/JSON.md) and
[validation record](docs/VALIDATION.md) describe schema and qualification limits.
When tests run elevated, the ordinary-user permission test reports skipped;
run CTest from a non-admin account to complete that check.

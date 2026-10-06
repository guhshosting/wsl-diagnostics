# Validation and release context: wsl-diagnostics 1.0.0

Development/build validation: Windows Server 2025 x64. The exact executable completed physical Windows 11 Pro 25H2 x64 qualification (build 26200.9550) and Windows 10 Pro 22H2 x64 qualification in a dedicated QEMU VM (build 19045.6466). Physical Windows 10 hardware and ARM64 were not qualified. Windows 11 status: PASS WITH FINDINGS, supported by the preserved physical qualification report dated 2026-10-02 and raw/run ledgers. Historical Windows 10 detailed ledgers are unavailable; completion is user supplied.

The final ZIP was assembled after executable qualification around the unchanged qualified EXE. Execution of this final assembled package on Windows is not claimed. Development validation is distinct from client qualification.

Qualified executable SHA-256: `94f3740f3148dd72a19d93020ab0e01d92c7aac9bd80b3ca3091e8383a28cdd3`.

No separately imported MSVC C++ runtime DLLs were found; Windows system libraries remain required.

Physical Windows 11 observations: Summary, distributions, configuration and prerequisites in text/JSON. Independent current-user Lxss read finds no registrations, services WslService/LxssManager/vmcompute absent, System32 launcher present. Existing .wslconfig recognized without modification. Running count, kernel/runtime versions and authoritative feature servicing state remain unavailable or unknown. No observed wsl.exe child; polling is not exhaustive proof.

Recorded findings: Invalid command with --json returns exit 2 and stderr, without a JSON error envelope. No current-user registrations or WSL services; launcher and existing configuration are distinguished from installed/running runtime.

Qualification safety limits: no broad filesystem, registry or policy mutation tracing was performed. Parent-PID TCP polling observed no connections; UDP, child traffic and packet-level activity were not monitored. These observations are not a formal proof of absence of all side effects.

See application documentation for query, output and safety limits. Windows may perform internal activity while servicing read-only API calls.

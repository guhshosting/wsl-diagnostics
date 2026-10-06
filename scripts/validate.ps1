param([string]$Build = 'build')
$ErrorActionPreference = 'Stop'
cmake -S . -B $Build -G 'Visual Studio 18 2026' -A x64
if ($LASTEXITCODE) { throw 'Configure failed' }
cmake --build $Build --config Release
if ($LASTEXITCODE) { throw 'Build failed' }
ctest --test-dir $Build -C Release --output-on-failure
if ($LASTEXITCODE) { throw 'Tests failed' }
$tidy = 'C:\Program Files\LLVM\bin\clang-tidy.exe'
if (Test-Path $tidy) {
    foreach ($file in @('src/core.cpp','src/windows.cpp','src/main.cpp','tests/tests.cpp','tests/permissions.cpp')) {
        & $tidy $file '--warnings-as-errors=*' '--checks=clang-analyzer-*,bugprone-*,performance-*,portability-*' -- -std=c++17 -Isrc -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 -fms-extensions -fms-compatibility
        if ($LASTEXITCODE) { throw "clang-tidy failed: $file" }
    }
} else { Write-Warning 'clang-tidy unavailable' }
$cppcheck = 'C:\Program Files\Cppcheck\cppcheck.exe'
if (Test-Path $cppcheck) {
    & $cppcheck --inline-suppr --enable=warning,style,performance,portability --error-exitcode=1 --std=c++17 --platform=win64 --library=windows -Isrc -DUNICODE -D_UNICODE -D_M_X64=100 -D_WIN32_WINNT=0x0A00 src tests/tests.cpp tests/permissions.cpp
    if ($LASTEXITCODE) { throw 'Cppcheck failed' }
} else { Write-Warning 'Cppcheck unavailable' }

param([string]$Build = 'build', [string]$Output = 'artifacts')
$ErrorActionPreference = 'Stop'
cpack --config "$Build/CPackConfig.cmake" -C Release -B $Output
if ($LASTEXITCODE) { throw 'Packaging failed' }
$archive = Join-Path $Output 'wsl-diagnostics-1.0.0-windows-x64.zip'
$digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
"$digest  wsl-diagnostics-1.0.0-windows-x64.zip" | Set-Content -Encoding ascii (Join-Path $Output 'SHA256SUMS.txt')
Write-Output $archive

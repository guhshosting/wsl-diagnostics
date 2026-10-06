param([Parameter(Mandatory=$true)][string]$Exe)
$ErrorActionPreference = 'Stop'
foreach ($mode in @('summary','distributions','configuration','prerequisites')) {
    $output = & $Exe --json $mode
    if ($LASTEXITCODE -ne 0) { throw "Failed mode $mode" }
    $report = $output | ConvertFrom-Json
    if ($report.schema_version -ne 1 -or $report.tool_version -ne '1.0.0' -or $report.mode -ne $mode) { throw 'Invalid JSON envelope' }
    if ($mode -eq 'summary' -and $report.summary.running_count.state -ne 'unavailable') { throw 'Unknown count collapsed' }
    $text = & $Exe $mode
    if ($LASTEXITCODE -ne 0 -or -not $text) { throw 'Text output failed' }
}
$default = & $Exe --json | ConvertFrom-Json
if ($default.mode -ne 'summary') { throw 'Default mode failed' }
$ErrorActionPreference = 'Continue' # Windows PowerShell wraps native stderr in error records.
& $Exe invalid 2>$null
if ($LASTEXITCODE -ne 2) { throw 'Invalid arguments must return 2' }
& $Exe summary distributions 2>$null
if ($LASTEXITCODE -ne 2) { throw 'Multiple commands must return 2' }
$ErrorActionPreference = 'Stop'
Write-Output 'CLI contracts passed'

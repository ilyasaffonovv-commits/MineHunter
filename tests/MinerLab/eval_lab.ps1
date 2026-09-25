<#
  eval_lab.ps1 - matches every MinerLab object (manifest + dynamic list) against a MineHunter scan
  (report.json + entities.json produced with:  MineHunter.exe scan --quick --report-dir D --dump D\entities.json).
  Prints, per lab object: the entity score, the finding verdict it ended up in, and the top evidence.
  Read-only.
#>
param(
    [Parameter(Mandatory)][string]$ScanDir,
    [string]$Manifest,
    [string]$Dynamic
)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Manifest) { $Manifest = Join-Path $here 'lab_manifest.json' }
if (-not $Dynamic)  { $Dynamic  = Join-Path $here 'lab_dynamic.json' }
$ents = Get-Content "$ScanDir\entities.json" -Raw | ConvertFrom-Json
$rep  = Get-Content "$ScanDir\report.json" -Raw | ConvertFrom-Json
$man  = Get-Content $Manifest -Raw | ConvertFrom-Json
$dyn  = if (Test-Path $Dynamic) { Get-Content $Dynamic -Raw | ConvertFrom-Json } else { @() }

# entity -> finding verdict
$verdictOf = @{}
foreach ($f in $rep.findings) { foreach ($e in $f.entities) { $verdictOf[$e.id] = "$($f.verdict) ($($f.score))" } }
function Find-Entities([scriptblock]$pred) { @($ents | Where-Object $pred) }
function Verdict-For($e) {
    # entities.json has no id; match by kind+location in the report's entities
    foreach ($f in $rep.findings) { foreach ($x in $f.entities) { if ($x.kind -eq $e.kind -and $x.location -eq $e.location -and $x.title -eq $e.title) { return "$($f.verdict)" } } }
    if ($e.score -ge 12) { return 'note' } else { return '-' }
}
function Show($label, $found) {
    if ($found.Count -eq 0) { "{0,-6} NOT SEEN" -f $label; return }
    $best = $found | Sort-Object score -Descending | Select-Object -First 1
    $top = ($best.evidence | Where-Object { $_.weight -gt 0 } | Sort-Object weight -Descending | Select-Object -First 3 | ForEach-Object { "$($_.rule)($($_.weight))" }) -join ' '
    "{0,-6} score {1,3}  {2,-10}  {3}" -f $label, $best.score, (Verdict-For $best), $top
}

"=== static objects"
foreach ($it in $man.items) {
    $d = "$($it.detail)"
    switch ($it.kind) {
        'file'    { $found = Find-Entities { $_.kind -eq 'File' -and $_.location -eq $d } }
        'run-key' { $name = if ($it.id -eq 'S10a') { 'MinerLabTestAutorun' } else { 'MinerLabTestAutorunHKLM' }; $found = Find-Entities { $_.kind -eq 'RunKey' -and $_.title -eq $name } }
        'task'    { $found = Find-Entities { $_.kind -eq 'Task' -and $_.title -eq $d } }
        'service' { $sn = if ($it.id -eq 'S13a') { 'MinerLabTestService' } else { 'MinerLabTestServiceTemp' }; $found = Find-Entities { $_.kind -eq 'Service' -and $_.title -eq $sn } }
        'wmi'     { $wn = if ($it.id -eq 'S14a') { 'MinerLabTestConsumer' } else { 'MinerLabTestScriptConsumer' }; $found = Find-Entities { $_.kind -eq 'Wmi' -and $_.title -eq $wn } }
        'startup' { $found = Find-Entities { $_.kind -eq 'StartupItem' -and $_.location -eq $d } }
        default   { $found = @() }
    }
    Show $it.id $found
    "        ($($it.description))"
}
"=== running processes (dynamic)"
foreach ($d in $dyn) {
    $found = Find-Entities { $_.kind -eq 'Process' -and $_.props.pid -eq "$($d.pid)" }
    Show $d.id $found
    "        ($($d.description))"
}

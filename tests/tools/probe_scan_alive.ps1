<#
  probe_scan_alive.ps1 - starts the MinerLab dynamic processes, runs a MineHunter scan right away and reports which lab processes the scan saw
  (test-helper: checks that process enumeration happens at the start of the scan).
#>
param([string]$ArgString = 'scan --quick --no-files --no-browsers')
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root '..\research\mh_lab\probe'
New-Item -ItemType Directory -Force $out | Out-Null
& powershell.exe -NoProfile -File (Join-Path $root 'MinerLab\lab.ps1') -Action Start-Dynamic | Select-Object -Last 1
$t0 = Get-Date
$dyn = Get-Content (Join-Path $root 'MinerLab\lab_dynamic.json') -Raw | ConvertFrom-Json
$exe = Join-Path (Split-Path -Parent $root) 'src\_bin\MineHunter.exe'
$p = Start-Process -FilePath $exe -ArgumentList ($ArgString + " --report-dir `"$out`" --dump `"$out\entities.json`" --quiet") -Wait -PassThru -WindowStyle Hidden
"scan finished after {0:N0}s, exit {1}" -f ((Get-Date) - $t0).TotalSeconds, $p.ExitCode
$rep = Get-Content (Join-Path $out 'report.json') -Raw | ConvertFrom-Json
"scan.started = $($rep.scan.started)   (dynamic start = $($t0.ToString('o')))"
$ents = Get-Content (Join-Path $out 'entities.json') -Raw | ConvertFrom-Json
$pids = @($ents | Where-Object { $_.kind -eq 'Process' } | ForEach-Object { "$($_.props.pid)" })
foreach ($d in $dyn) { "{0,-4} pid {1,6}  seen-by-scan: {2}" -f $d.id, $d.pid, ($pids -contains "$($d.pid)") }

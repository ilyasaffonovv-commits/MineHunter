# measure_lab.ps1 - records the REAL cpu/memory of the running MinerLab processes (so the lab's "80%" claim is measured, not assumed)
param([string]$Out, [int]$Delay = 6, [int]$Window = 10)
if (-not $Out) { $Out = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'lab_dynamic_measure.json' }
Start-Sleep -Seconds $Delay
$cores = [Environment]::ProcessorCount
function Snap { $h = @{}; foreach ($p in Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -match '\\MinerLab' }) { $gp = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue; if ($gp) { $h[$p.ProcessId] = [pscustomobject]@{ path = $p.ExecutablePath; ppid = $p.ParentProcessId; cpu = $gp.TotalProcessorTime.TotalSeconds; ws = $gp.WorkingSet64; cmd = $p.CommandLine } } }; $h }
$a = Snap; $t0 = Get-Date; Start-Sleep -Seconds $Window; $b = Snap; $dt = ((Get-Date) - $t0).TotalSeconds
$rows = foreach ($k in $b.Keys) { if ($a.ContainsKey($k)) { [ordered]@{ pid = $k; ppid = $b[$k].ppid; exe = (Split-Path $b[$k].path -Leaf); dir = (Split-Path $b[$k].path -Parent); avgCpuPercentOfTotal = [math]::Round(100 * ($b[$k].cpu - $a[$k].cpu) / ($dt * $cores), 1); workingSetMB = [math]::Round($b[$k].ws / 1MB, 1); cmd = $b[$k].cmd } } }
[ordered]@{ measuredAt = (Get-Date).ToString('o'); logicalCores = $cores; windowSec = [math]::Round($dt, 1); processes = @($rows | Sort-Object { $_.pid }) } | ConvertTo-Json -Depth 4 | Set-Content $Out -Encoding UTF8

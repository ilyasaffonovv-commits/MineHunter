<#
  MinerLabCleanup.ps1 - removes EVERYTHING that MinerLab (lab.ps1) created, then verifies nothing is left.
  Only objects carrying the 'MinerLab' / 'MinerLabTest' label or living in MinerLab's own directories are touched.
  Safe to run repeatedly. Run elevated, Windows PowerShell 5.1 recommended (WMI cmdlets).
#>
param([switch]$Quiet)
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.ArrayList
function Say($m) { [void]$log.Add($m); if (-not $Quiet) { $m } }

$tmp = Join-Path $env:TEMP 'MinerLab'
$dirs = @($tmp, (Join-Path $env:LOCALAPPDATA 'MinerLab'), (Join-Path $env:APPDATA 'MinerLab'), (Join-Path $env:APPDATA 'MinerLabMulti'),
          (Join-Path $env:ProgramFiles 'MinerLabTest'), (Join-Path $env:ProgramData 'MinerLab'))
$rootFiles = @((Join-Path $env:LOCALAPPDATA 'MinerLabTest_root.exe'), (Join-Path $env:APPDATA 'MinerLabTest_root2.exe'))

# 0. kill switch: every harness process ends within ~1 s
foreach ($d in @($tmp, (Join-Path $env:ProgramData 'MinerLab'))) { try { New-Item -ItemType Directory -Force $d | Out-Null; Set-Content (Join-Path $d 'MinerLab.STOP') 'stop' } catch {} }
Start-Sleep -Seconds 2

# 1. processes: anything running from a MinerLab directory (covers masquerade names such as svchost.exe in %TEMP%\MinerLab)
$killed = 0
foreach ($p in Get-CimInstance Win32_Process) {
    $path = $p.ExecutablePath
    if (-not $path) { continue }
    foreach ($d in $dirs) { if ($path.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $killed++; Say "killed process $($p.ProcessId) $path" } catch { Say "cannot kill $($p.ProcessId): $($_.Exception.Message)" } } }
    foreach ($r in $rootFiles) { if ($path -eq $r) { try { Stop-Process -Id $p.ProcessId -Force; $killed++ } catch {} } }
}
Say "processes killed: $killed"

# 2. services
foreach ($s in Get-CimInstance Win32_Service | Where-Object { $_.Name -like 'MinerLabTest*' }) {
    if ($s.State -eq 'Running') { Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue }
    & sc.exe delete $s.Name | Out-Null; Say "service removed: $($s.Name)"
}

# 3. scheduled tasks (any folder) + the Microsoft-looking folder
foreach ($t in Get-ScheduledTask | Where-Object { $_.TaskName -like 'MinerLabTest*' }) {
    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue; Say "task removed: $($t.TaskPath)$($t.TaskName)"
}
try {
    $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect()
    $root = $svc.GetFolder('\Microsoft\Windows')
    foreach ($f in $root.GetFolders(0)) { if ($f.Name -eq 'MinerLabTestFolder') { $root.DeleteFolder('MinerLabTestFolder', 0); Say 'task folder removed: \Microsoft\Windows\MinerLabTestFolder' } }
} catch { Say "task folder: $($_.Exception.Message)" }

# 4. autorun values
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce') {
    $item = Get-ItemProperty $k -ErrorAction SilentlyContinue
    if ($item) { foreach ($p in $item.PSObject.Properties) { if ($p.Name -like 'MinerLabTest*') { Remove-ItemProperty $k -Name $p.Name -ErrorAction SilentlyContinue; Say "run value removed: $k\$($p.Name)" } } }
}

# 5. WMI: bindings first, then consumers and filters
foreach ($b in Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue) {
    if ("$($b.Filter)$($b.Consumer)" -match 'MinerLabTest') { $b | Remove-WmiObject; Say "wmi binding removed" }
}
foreach ($cls in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') {
    foreach ($c in Get-WmiObject -Namespace root\subscription -Class $cls -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MinerLabTest*' }) { $c | Remove-WmiObject; Say "wmi $cls removed: $($c.Name)" }
}
foreach ($f in Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MinerLabTest*' }) { $f | Remove-WmiObject; Say "wmi filter removed: $($f.Name)" }

# 6. startup-folder shortcuts
foreach ($sd in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    Get-ChildItem $sd -Filter 'MinerLabTest*' -Force -ErrorAction SilentlyContinue | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force; Say "startup item removed: $($_.FullName)" }
}

# 7. files and directories (explicit lab paths only)
foreach ($f in $rootFiles) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue; Say "file removed: $f" } }
foreach ($d in $dirs) {
    if (Test-Path -LiteralPath $d) {
        Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $d) { cmd /c rd /s /q "`"$d`"" 2>$null }
        Say ("dir " + $(if (Test-Path -LiteralPath $d) { 'STILL PRESENT: ' } else { 'removed: ' }) + $d)
    }
}

# 8. verification: search for any trace by label
$left = New-Object System.Collections.ArrayList
foreach ($d in $dirs) { if (Test-Path -LiteralPath $d) { [void]$left.Add("dir $d") } }
foreach ($f in $rootFiles) { if (Test-Path -LiteralPath $f) { [void]$left.Add("file $f") } }
Get-CimInstance Win32_Service | Where-Object { $_.Name -like 'MinerLabTest*' } | ForEach-Object { [void]$left.Add("service $($_.Name)") }
Get-ScheduledTask | Where-Object { $_.TaskName -like 'MinerLabTest*' } | ForEach-Object { [void]$left.Add("task $($_.TaskName)") }
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run') { (Get-ItemProperty $k -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -like 'MinerLabTest*' } | ForEach-Object { [void]$left.Add("run $($_.Name)") } }
Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MinerLabTest*' } | ForEach-Object { [void]$left.Add("wmi filter $($_.Name)") }
Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MinerLabTest*' } | ForEach-Object { [void]$left.Add("wmi consumer $($_.Name)") }
Get-Process | Where-Object { $_.Path -and $_.Path -match '\\MinerLab' } | ForEach-Object { [void]$left.Add("process $($_.Id) $($_.Path)") }

if ($left.Count -eq 0) { Say 'CLEANUP OK: no MinerLab objects remain.'; exit 0 } else { Say "CLEANUP INCOMPLETE ($($left.Count) left):"; $left | ForEach-Object { Say "  $_" }; exit 1 }

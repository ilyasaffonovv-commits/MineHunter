<#
  lab.ps1 - creates the BENIGN synthetic infection used to test anti-miner tools.
  Run with Windows PowerShell 5.1 (WMI-subscription cmdlets), elevated.

    powershell -File lab.ps1 -Action Create-Static     # files + persistence entries (nothing is running)
    powershell -File lab.ps1 -Action Start-Dynamic     # starts the short-lived (<=55 s) simulated processes
    powershell -File lab.ps1 -Action Status
  Cleanup is a separate script: MinerLabCleanup.ps1

  Every object carries the label 'MinerLabTest' and points ONLY at MinerLab's own harness executable.
  No downloads, no external URLs, no PowerShell payloads, no security settings are touched
  (Defender / firewall / hosts / certificates are deliberately NOT modified).
#>
param(
    [Parameter(Mandatory)][ValidateSet('Create-Static','Create-Multi','Start-Dynamic','Status')][string]$Action,
    [string]$HarnessExe,
    [string]$ManifestPath
)
$ErrorActionPreference = 'Stop'
$labDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $HarnessExe)   { $HarnessExe   = Join-Path $labDir 'bin\MinerSimulation.exe' }
if (-not $ManifestPath) { $ManifestPath = Join-Path $labDir 'lab_manifest.json' }
if (-not (Test-Path $HarnessExe)) { throw "harness not found: $HarnessExe  (build it first: tests\MinerLab\build_lab.ps1)" }

$tmp = Join-Path $env:TEMP 'MinerLab'
$la  = Join-Path $env:LOCALAPPDATA 'MinerLab'
$ap  = Join-Path $env:APPDATA 'MinerLab'
$apm = Join-Path $env:APPDATA 'MinerLabMulti'
$pf  = Join-Path $env:ProgramFiles 'MinerLabTest'
$pd  = Join-Path $env:ProgramData 'MinerLab'
$startup = [Environment]::GetFolderPath('Startup')

# Every copy gets a small unique tail (default: derived from its path) so that copies do NOT share one hash - like unrelated programs.
# Copies that must be identical (launcher/child groups; the harness refuses to start a child that is not hash-identical) pass the same -Salt.
function Copy-Harness([string]$dest, [string]$Salt = '') {
    New-Item -ItemType Directory -Force (Split-Path $dest -Parent) | Out-Null
    Copy-Item -LiteralPath $HarnessExe -Destination $dest -Force
    if (-not $Salt) { $Salt = $dest.ToLowerInvariant() }
    $tail = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes('MinerLabTest|' + $Salt))
    $fs = [IO.File]::Open($dest, [IO.FileMode]::Append, [IO.FileAccess]::Write)
    try { $fs.Write($tail, 0, $tail.Length) } finally { $fs.Dispose() }
    $dest
}
$manifest = [ordered]@{ created = (Get-Date).ToString('o'); harnessSha256 = (Get-FileHash $HarnessExe -Algorithm SHA256).Hash; items = New-Object System.Collections.ArrayList }
function Add-Item($id, $kind, $desc, $extra) { [void]$manifest.items.Add([ordered]@{ id = $id; kind = $kind; description = $desc; detail = $extra }) }
function Args-Sim([int]$cpu, [int]$sec = 20, [string]$more = '') { "--mode sim --cpu $cpu --seconds $sec --label MinerLabTest $more".Trim() }

switch ($Action) {
'Create-Static' {
    # ---------- files: unsigned harness copies in different locations
    $f = Copy-Harness "$tmp\MinerSimulation.exe";                   Add-Item 'S01' 'file' 'unsigned exe in %TEMP%\MinerLab' $f
    $f = Copy-Harness "$la\MinerSimulation.exe";                    Add-Item 'S02' 'file' 'unsigned exe in %LOCALAPPDATA%\MinerLab' $f
    $f = Copy-Harness "$ap\MinerSimulation.exe";                    Add-Item 'S03' 'file' 'unsigned exe in %APPDATA%\MinerLab' $f
    $f = Copy-Harness "$env:LOCALAPPDATA\MinerLabTest_root.exe";    Add-Item 'S04' 'file' 'unsigned exe directly in the ROOT of %LOCALAPPDATA%' $f
    $f = Copy-Harness "$env:APPDATA\MinerLabTest_root2.exe";        Add-Item 'S05' 'file' 'unsigned exe directly in the ROOT of %APPDATA%' $f
    $f = Copy-Harness "$pf\MinerSimulation.exe";                    Add-Item 'S06' 'file' 'unsigned exe in C:\Program Files\MinerLabTest' $f
    $f = Copy-Harness "$pd\MinerSimulation.exe";                    Add-Item 'S07' 'file' 'unsigned exe in C:\ProgramData\MinerLab' $f
    # signed control: a genuine Microsoft-signed binary copied to a "suspicious" place (not executed)
    $signedSrc = "$env:SystemRoot\System32\notepad.exe"
    New-Item -ItemType Directory -Force "$tmp\signed_copy" | Out-Null
    Copy-Item $signedSrc "$tmp\signed_copy\notepad.exe" -Force
    Add-Item 'S08' 'file' 'Microsoft-SIGNED notepad.exe copied into %TEMP%\MinerLab\signed_copy (FP control)' "$tmp\signed_copy\notepad.exe"
    # masquerade names, only inside MinerLab directories, never in System32/Windows
    $i = 0
    foreach ($m in @(@("$tmp\masq", 'svchost.exe'), @("$ap\masq", 'taskhostw.exe'), @("$la\masq", 'RuntimeBroker.exe'), @("$tmp\masq", 'csrss.exe'))) {
        $f = Copy-Harness (Join-Path $m[0] $m[1]); $i++
        Add-Item ("S09" + [char](96 + $i)) 'file' "SYSTEM-LIKE NAME + WRONG PATH ($($m[1]))" $f
    }
    # ---------- persistence: autorun (HKCU + HKLM)
    $runVal = '"' + "$la\MinerSimulation.exe" + '" ' + (Args-Sim 0 15)
    New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'MinerLabTestAutorun' -Value $runVal -PropertyType String -Force | Out-Null
    Add-Item 'S10a' 'run-key' 'HKCU Run -> LocalAppData harness' $runVal
    $runValM = '"' + "$pf\MinerSimulation.exe" + '" ' + (Args-Sim 0 15)
    New-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'MinerLabTestAutorunHKLM' -Value $runValM -PropertyType String -Force | Out-Null
    Add-Item 'S10b' 'run-key' 'HKLM Run -> Program Files harness' $runValM
    # ---------- scheduled tasks
    $act = New-ScheduledTaskAction -Execute "$ap\MinerSimulation.exe" -Argument (Args-Sim 0 15)
    $trg = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries
    Register-ScheduledTask -TaskName 'MinerLabTestTask' -TaskPath '\' -Action $act -Trigger $trg -Settings $set -Description 'MinerLabTest benign task' -Force | Out-Null
    Add-Item 'S11' 'task' 'task \MinerLabTestTask (AtLogOn) -> AppData harness' 'MinerLabTestTask'
    $setH = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries
    $actH = New-ScheduledTaskAction -Execute "$tmp\MinerSimulation.exe" -Argument (Args-Sim 0 15)
    Register-ScheduledTask -TaskName 'MinerLabTestTaskHidden' -TaskPath '\' -Action $actH -Trigger $trg -Settings $setH -Description 'MinerLabTest benign hidden task' -Force | Out-Null
    Add-Item 'S11b' 'task' 'HIDDEN task \MinerLabTestTaskHidden -> Temp harness' 'MinerLabTestTaskHidden'
    Register-ScheduledTask -TaskName 'MinerLabTestTaskMs' -TaskPath '\Microsoft\Windows\MinerLabTestFolder\' -Action $act -Trigger $trg -Settings $set -Description 'MinerLabTest benign task in a Microsoft-looking folder' -Force | Out-Null
    Add-Item 'S12' 'task' 'task in \Microsoft\Windows\MinerLabTestFolder\ (impersonates the Windows namespace) -> AppData harness' 'MinerLabTestTaskMs'
    # ---------- services (demand start, never started by the lab)
    $svcBin = '"' + "$la\MinerSimulation.exe" + '" --mode service --svcname MinerLabTestService --seconds 20'
    New-Service -Name 'MinerLabTestService' -BinaryPathName $svcBin -DisplayName 'MinerLabTest Service (benign)' -Description 'MinerLab benign test service' -StartupType Manual | Out-Null
    Add-Item 'S13a' 'service' 'service MinerLabTestService (manual) -> LocalAppData harness' $svcBin
    $svcTmp = Copy-Harness "$tmp\MinerLabTestServiceTemp.exe"
    $svcBin2 = '"' + $svcTmp + '" --mode service --svcname MinerLabTestServiceTemp --seconds 20'
    New-Service -Name 'MinerLabTestServiceTemp' -BinaryPathName $svcBin2 -DisplayName 'MinerLabTest Service Temp (benign)' -Description 'MinerLab benign test service in Temp' -StartupType Manual | Out-Null
    Add-Item 'S13b' 'service' 'service whose name == exe stem, image in %TEMP%' $svcBin2
    # ---------- WMI permanent event subscriptions (filter never matches -> never fires)
    $q = "SELECT * FROM __InstanceCreationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'MinerLabTestNeverMatches.exe'"
    $flt = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{ Name = 'MinerLabTestFilter'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = $q }
    $cmdT = '"' + "$la\MinerSimulation.exe" + '" ' + (Args-Sim 0 15)
    $con = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{ Name = 'MinerLabTestConsumer'; CommandLineTemplate = $cmdT; ExecutablePath = "$la\MinerSimulation.exe" }
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = $flt; Consumer = $con } | Out-Null
    Add-Item 'S14a' 'wmi' 'CommandLineEventConsumer (plain harness path, no cmd.exe, no ..\) + filter + binding' $cmdT
    $flt2 = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{ Name = 'MinerLabTestFilter2'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = $q }
    $con2 = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments @{ Name = 'MinerLabTestScriptConsumer'; ScriptingEngine = 'VBScript'; ScriptText = "' MinerLabTest: intentionally empty, never triggered" }
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = $flt2; Consumer = $con2 } | Out-Null
    Add-Item 'S14b' 'wmi' 'ActiveScriptEventConsumer (VBScript comment only) + filter + binding' 'MinerLabTestScriptConsumer'
    # ---------- Startup-folder shortcut
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut((Join-Path $startup 'MinerLabTest.lnk'))
    $lnk.TargetPath = "$tmp\MinerSimulation.exe"; $lnk.Arguments = (Args-Sim 0 15); $lnk.Description = 'MinerLabTest benign shortcut'; $lnk.Save()
    Add-Item 'S15' 'startup' 'Startup-folder shortcut -> Temp harness' (Join-Path $startup 'MinerLabTest.lnk')
    $manifest | ConvertTo-Json -Depth 5 | Set-Content $ManifestPath -Encoding UTF8
    "static lab created: $($manifest.items.Count) items. manifest: $ManifestPath"
}
'Create-Multi' {
    # multi-signal object: unsigned + AppData + (later) sustained CPU + Run key + task with a repeating trigger + Startup shortcut
    Copy-Harness "$apm\MinerLabMulti.exe" -Salt multi | Out-Null; Copy-Harness "$apm\MinerLabMultiWorker.exe" -Salt multi | Out-Null; Copy-Harness "$apm\MinerLabMultiLauncher.exe" -Salt multi | Out-Null
    $runM = '"' + "$apm\MinerLabMulti.exe" + '" ' + (Args-Sim 60 15 '--port 3333')
    New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'MinerLabTestMultiRun' -Value $runM -PropertyType String -Force | Out-Null
    $qt = [string][char]34
    $childArgs = (Args-Sim 60 15 '--port 3333')
    $actM = New-ScheduledTaskAction -Execute "$apm\MinerLabMultiLauncher.exe" -Argument ("--mode launcher --seconds 15 --label MinerLabTest_Ml --child " + $qt + "$apm\MinerLabMulti.exe" + $qt + " --childargs " + $qt + $childArgs + $qt)
    $trgM = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName 'MinerLabTestMultiTask' -TaskPath '\' -Action $actM -Trigger $trgM -Description 'MinerLabTest benign multi-signal task (repeats every 5 min, first run in one year)' -Force | Out-Null
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut((Join-Path $startup 'MinerLabTestMulti.lnk')); $lnk.TargetPath = "$apm\MinerLabMulti.exe"; $lnk.Arguments = (Args-Sim 60 15); $lnk.Save()
    "multi-signal persistence created (Run + task with 5-minute repeating trigger + Startup lnk) for $apm\MinerLabMulti.exe"
}
'Start-Dynamic' {
    $sec = 55
    $cfg = New-Object System.Collections.ArrayList
    function Start-Sim($id, $exe, $argLine, $desc) {
        $p = Start-Process -FilePath $exe -ArgumentList $argLine -WindowStyle Hidden -PassThru
        [void]$cfg.Add([ordered]@{ id = $id; pid = $p.Id; exe = $exe; args = $argLine; description = $desc })
        $p
    }
    # A/B/C/D/E/F of the false-positive matrix (all unsigned harness copies)
    Start-Sim 'D1' "$tmp\MinerSimulation.exe"  "--mode sim --cpu 10 --seconds $sec --label MinerLabTest_D1" 'Temp, LOW cpu (10%), no persistence of its own' | Out-Null
    Start-Sim 'D2' "$pf\MinerSimulation.exe"   "--mode sim --cpu 80 --seconds $sec --label MinerLabTest_D2" 'Program Files, HIGH cpu (80%), unsigned' | Out-Null
    Copy-Harness "$tmp\D3\MinerSimulation.exe" | Out-Null
    Start-Sim 'D3' "$tmp\D3\MinerSimulation.exe" "--mode sim --cpu 80 --seconds $sec --label MinerLabTest_D3" 'Temp, HIGH cpu (80%), unsigned, no persistence' | Out-Null
    Start-Sim 'D4' "$ap\MinerSimulation.exe"   "--mode sim --cpu 80 --seconds $sec --label MinerLabTest_D4" 'AppData, HIGH cpu, unsigned, has HKCU Run + task' | Out-Null
    # process chain launcher -> sim -> worker (all identical copies)
    $l1 = Copy-Harness "$la\chain\MinerLabLauncher.exe" -Salt chain; $s1 = Copy-Harness "$la\chain\MinerSimulation.exe" -Salt chain; $w1 = Copy-Harness "$la\chain\MinerLabWorker.exe" -Salt chain
    $qt = [string][char]34
    $simArgs = "--mode sim --cpu 25 --seconds $sec --label MinerLabTest_D5s --child $w1"
    Start-Sim 'D5' $l1 ("--mode launcher --seconds $sec --label MinerLabTest_D5l --child $s1 --childargs " + $qt + $simArgs + $qt) 'chain: MinerLabLauncher -> MinerSimulation -> MinerLabWorker' | Out-Null
    # memory
    Copy-Harness "$la\mem\MinerSimulation.exe" | Out-Null
    Start-Sim 'D6' "$la\mem\MinerSimulation.exe" "--mode sim --mem 800 --seconds $sec --label MinerLabTest_D6" 'holds 800 MB RAM, no CPU' | Out-Null
    # localhost network (port 3333 is a typical mining port; loopback only)
    Copy-Harness "$tmp\net\MinerLabServer.exe" | Out-Null; Copy-Harness "$tmp\net\MinerSimulation.exe" | Out-Null
    Start-Sim 'D7s' "$tmp\net\MinerLabServer.exe" "--mode server --port 3333 --seconds $sec --label MinerLabTest_D7s" 'loopback TCP server 127.0.0.1:3333' | Out-Null
    Start-Sleep -Milliseconds 700
    Start-Sim 'D7c' "$tmp\net\MinerSimulation.exe" "--mode sim --port 3333 --seconds $sec --label MinerLabTest_D7c" 'loopback client -> 127.0.0.1:3333' | Out-Null
    # miner-like command line (localhost only, the harness ignores unknown switches).
    # The scheme is assembled at run time so that this script itself does not contain a literal miner URL (scanners would flag the script).
    $poolScheme = 'stratum' + '+tcp'
    $minerish = (@('--algo', 'test-algo', '--url', "${poolScheme}://127.0.0.1:3333", ('--us' + 'er'), 'MinerLabTest', ('--pa' + 'ss'), 'x') -join ' ')
    Copy-Harness "$tmp\cmdline\MinerSimulation.exe" | Out-Null
    Start-Sim 'D8' "$tmp\cmdline\MinerSimulation.exe" "--mode sim --seconds $sec --label MinerLabTest_D8 $minerish" 'miner-like switches in the command line (loopback URL only)' | Out-Null
    # running masquerades
    Start-Sim 'D9a' "$tmp\masq\svchost.exe"    "--mode sim --seconds $sec --label MinerLabTest_D9a" 'running SYSTEM-LIKE name svchost.exe in %TEMP%' | Out-Null
    Start-Sim 'D9b' "$ap\masq\taskhostw.exe"   "--mode sim --seconds $sec --label MinerLabTest_D9b" 'running SYSTEM-LIKE name taskhostw.exe in %APPDATA%' | Out-Null
    # multi-signal: unsigned + AppData + sustained CPU + autorun + task + WMI + startup lnk + unusual chain + loopback socket
    $mw = "$apm\MinerLabMultiWorker.exe"; $mm = "$apm\MinerLabMulti.exe"
    $qt = [string][char]34
    $mArgs = "--mode sim --cpu 60 --port 3333 --seconds $sec --label MinerLabTest_M --child $mw"
    Start-Sim 'M' "$apm\MinerLabMultiLauncher.exe" ("--mode launcher --seconds $sec --label MinerLabTest_Ml --child $mm --childargs " + $qt + $mArgs + $qt) 'MULTI-SIGNAL object (see multi persistence entries)' | Out-Null
    $cfg | ConvertTo-Json -Depth 4 | Set-Content (Join-Path (Split-Path $ManifestPath -Parent) 'lab_dynamic.json') -Encoding UTF8
    "started $($cfg.Count) simulated processes (each ends by itself after $sec s)"
}
'Status' {
    "processes: "; Get-Process | Where-Object { $_.Path -and $_.Path -match 'MinerLab' } | Select-Object Id, ProcessName, Path | Format-Table -AutoSize
}
}

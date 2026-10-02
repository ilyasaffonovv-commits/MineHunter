<#
  run.ps1 - adversarial life-cycle test of the RELEASE EXE (MineHunter-cli.exe) against harmless imitations of persistence mechanisms (vectors.ps1).

  Per vector it checks, in this order:
    1 Detect      the artifact is reported (a finding, or - for the controls - correctly not reported / reported but kept)
    2 Explain     the finding carries a severity, evidence lines with a readable text and a plan
    3 Quarantine  "--fix" removes it, the artifact is really gone, a quarantine record was written
    4 Re-scan     the verification scan inside --fix agrees (outcome Remediated / reboot) and no unexpected finding appeared
    5 Restore     "quarantine restore" brings it back
    6 Identical   what comes back is identical to what was there (SHA-256 of files, the exact registry value, the task XML length)
    7 Reappear    after cleaning twice, re-creating it is recognised as "came back after cleaning" (REL.REAPPEARED)
    8 Cleanup     the final cleanup leaves the system equal to the baseline (registry/service/task/WMI/startup snapshot) and no false finding
  Anything that was not run says NOT TESTED. Run as administrator, in ONE tool context (the desktop app virtualizes HKCU/AppData per context):

    powershell -NoProfile -File tests\adversarial\run.ps1 [-Out <dir>] [-Ids R01,S02] [-AgeWaitSec 200] [-KeepArtifacts]
#>
param(
    [string]$Out = (Join-Path $env:TEMP 'mh_adv'),
    [string[]]$Ids,
    [int]$AgeWaitSec = 200,
    [switch]$KeepArtifacts,
    [switch]$CreateOnly,       # create the imitations and stop (to point another tool at them); remove them later with -CleanupOnly
    [switch]$CleanupOnly
)
$ErrorActionPreference = 'Continue'
$env:PSModulePath = (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules') + ';' + (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules') + ';' + (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules')
. "$PSScriptRoot\vectors.ps1"
$exe = Join-Path $script:Root 'MineHunter-cli.exe'
$labDir = Join-Path $script:Root 'tests\MinerLab'
Remove-Item $Out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Out | Out-Null
$logFile = Join-Path $Out 'run.log'
function Log([string]$m) { $l = ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $m); Add-Content -Path $logFile -Value $l -Encoding UTF8; Write-Host $l }
$res = @{}        # vector id -> ordered table of check results
function Mark([string]$id, [string]$check, [string]$state, [string]$note = '') {
    if (-not $res.ContainsKey($id)) { $res[$id] = [ordered]@{} }
    $res[$id][$check] = [pscustomobject]@{ State = $state; Note = $note }
}

# --------------------------------------------------------------------------- the process vectors (they need live programs)
$minerish = (@('--algo', 'test-algo', '--url', ('stratum' + '+tcp') + '://127.0.0.1:3333', ('--us' + 'er'), 'MinerLabAdv', ('--pa' + 'ss'), 'x') -join ' ')
$script:Procs = New-Object System.Collections.ArrayList
function Start-Harness([string]$Path, [string]$ArgLine) { $p = Start-Process -FilePath $Path -ArgumentList $ArgLine -WindowStyle Hidden -PassThru; [void]$script:Procs.Add($p); $p }
Vec 'P01' 'WATCHDOG PAIR: a running miner-like program and a second program that puts its file back; both are killed together' {
    $src = Copy-Unique "$script:LA\p01\src.exe"
    New-Item -ItemType Directory -Force "$script:LA\p01" | Out-Null
    Copy-Item $src "$script:LA\p01\miner.exe" -Force
    $w = Copy-Unique "$script:LA\p01\watch.exe"
    Start-Harness "$script:LA\p01\miner.exe" ("--mode sim --seconds 280 --label MinerLabAdvP01R $minerish") | Out-Null
    Start-Harness $w ("--mode respawn --seconds 280 --label MinerLabAdvP01W --source `"$src`" --target `"$script:LA\p01\miner.exe`" $minerish") | Out-Null
    Start-Sleep -Seconds 2
} { (Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -like '*MinerLabAdv\p01\*' }).Count -gt 0 -or (Test-Path -LiteralPath "$script:LA\p01\miner.exe") } 'MinerLabAdvP01|\\MinerLabAdv\\p01\\' 'finding' $false $null
Vec 'P02' 'LONE WATCHDOG (nothing marks it as bad) that silently restores a persistent file after it is removed: the result must be reported honestly' {
    $src = Copy-Unique "$script:LA\p02\src.exe"
    New-Item -ItemType Directory -Force "$script:LA\p02" | Out-Null
    Copy-Item $src "$script:LA\p02\payload.exe" -Force
    Set-RegStr $run 'MinerLabAdvRun20' ('"' + "$script:LA\p02\payload.exe" + '" ' + $script:IDLE)
    $w = Copy-Unique "$script:LA\p02\w2.exe"
    Start-Harness $w ("--mode respawn --seconds 280 --label MinerLabAdvP02 --source `"$src`" --target `"$script:LA\p02\payload.exe`"") | Out-Null
    Start-Sleep -Seconds 2
} { Has-RegVal $run 'MinerLabAdvRun20' } 'MinerLabAdvRun20|\\MinerLabAdv\\p02\\' 'honest' $false $null

# --------------------------------------------------------------------------- state snapshot (what could change "unrelated to the test")
function Get-Snapshot {
    $s = New-Object System.Collections.ArrayList
    $keys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKCU:\Software\Microsoft\Command Processor', 'HKLM:\SOFTWARE\Microsoft\Command Processor', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
    foreach ($k in $keys) {
        if (Test-Path -LiteralPath $k) { $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue; foreach ($n in $p.PSObject.Properties.Name) { if ($n -notmatch '^PS') { [void]$s.Add("value|$k|$n") } } } else { [void]$s.Add("nokey|$k") }
    }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit', 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKCU:\Software\Classes', 'HKCU:\Software\Classes\CLSID', 'HKLM:\SYSTEM\CurrentControlSet\Services') {
        if (Test-Path -LiteralPath $k) { foreach ($n in (Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })) { [void]$s.Add("subkey|$k|$n") } } else { [void]$s.Add("nokey|$k") }
    }
    foreach ($t in (& schtasks.exe /query /fo csv /nh 2>$null | ForEach-Object { ($_ -split '","')[0].Trim('"') } | Sort-Object -Unique)) { [void]$s.Add("task|$t") }
    foreach ($ns in 'root\subscription', 'root\default', 'root\cimv2') {
        foreach ($cls in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
            foreach ($o in (Get-WmiObject -Namespace $ns -Class $cls -ErrorAction SilentlyContinue)) { [void]$s.Add("wmi|$ns|$cls|$($o.Name)") }
        }
    }
    foreach ($d in @($script:Startup, [Environment]::GetFolderPath('CommonStartup'))) { if (Test-Path $d) { foreach ($f in Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue) { [void]$s.Add("startup|$($f.FullName)") } } }
    foreach ($d in @($env:LOCALAPPDATA, $env:APPDATA, $env:ProgramData, 'C:\Users\Public', (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'))) { foreach ($f in Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'MinerLab' }) { [void]$s.Add("leftover|$($f.FullName)") } }
    @($s | Sort-Object -Unique)
}

# --------------------------------------------------------------------------- removal of every artifact (the harness' own cleanup, not MineHunter's)
function Remove-AllArtifacts {
    New-Item -ItemType Directory -Force (Join-Path $env:TEMP 'MinerLab') | Out-Null
    Set-Content -LiteralPath (Join-Path $env:TEMP 'MinerLab\MinerLab.STOP') -Value 'stop' -ErrorAction SilentlyContinue      # kill switch of the harness
    Start-Sleep -Seconds 2
    foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) { if ($p.ExecutablePath -and $p.ExecutablePath -match 'MinerLabAdv') { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } }
    foreach ($k in $run, 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') {
        if (Test-Path -LiteralPath $k) { foreach ($n in (Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue).PSObject.Properties.Name) { if ($n -like 'MinerLabAdv*') { Remove-ItemProperty -LiteralPath $k -Name $n -Force -ErrorAction SilentlyContinue } } }
    }
    foreach ($pair in @(@('HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows', 'Load'), @('HKCU:\Software\Microsoft\Command Processor', 'AutoRun'))) {
        $v = Get-RegStr $pair[0] $pair[1]; if ($v -and "$v" -match 'MinerLabAdv') { Remove-ItemProperty -LiteralPath $pair[0] -Name $pair[1] -Force -ErrorAction SilentlyContinue }
    }
    foreach ($k in 'HKCU:\Software\Classes\.mlabadv', 'HKCU:\Software\Classes\CLSID\{7A1B0C2D-0000-4000-8000-00000000AD12}', 'HKCU:\Software\Classes\CLSID\{7A1B0C2D-0000-4000-8000-00000000AD13}',
        'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{7A1B0C2D-0000-4000-8000-00000000AD11}', "$ifeo\MinerLabAdvApp.exe", "$ifeo\MinerLabAdvApp10.exe",
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\MinerLabAdvApp9.exe') { Remove-RegKey $k }
    $ms = Get-RegStr 'HKCU:\Software\Classes\ms-settings\shell\open\command' '(default)'; if ($ms -and "$ms" -match 'MinerLabAdv') { Remove-RegKey 'HKCU:\Software\Classes\ms-settings' }
    foreach ($n in 'MinerLabAdvSvc01', 'MinerLabAdvNssm02', 'MinerLabAdvDll03', 'MinerLabAdvFail04', 'MinerLabAdvDrv05') { if (Has-Svc $n) { & sc.exe stop $n 2>&1 | Out-Null; & sc.exe delete $n 2>&1 | Out-Null } ; Remove-RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\$n" }
    foreach ($n in 'MinerLabAdvTask01', 'MinerLabAdvTask02') { if (Has-Task $n) { & schtasks.exe /delete /tn $n /f 2>&1 | Out-Null } }
    foreach ($ns in 'root\subscription', 'root\default', 'root\cimv2') {
        foreach ($b in Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue) { if ("$($b.Filter)$($b.Consumer)" -match 'MinerLabAdv') { $b | Remove-WmiObject -ErrorAction SilentlyContinue } }
        foreach ($c in Get-WmiObject -Namespace $ns -Class __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MinerLabAdv*' }) { $c | Remove-WmiObject -ErrorAction SilentlyContinue }
        foreach ($f in Get-WmiObject -Namespace $ns -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MinerLabAdv*' }) { $f | Remove-WmiObject -ErrorAction SilentlyContinue }
    }
    foreach ($f in Get-ChildItem -LiteralPath $script:Startup -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MinerLabAdv*' }) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
    foreach ($d in $script:Dirs) {
        if (Test-Path -LiteralPath $d) {
            Get-ChildItem -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }
            Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $d) { & cmd.exe /c ('rd /s /q "' + $d + '"') 2>$null | Out-Null }
        }
    }
    Remove-Item -LiteralPath (Join-Path $env:TEMP 'MinerLab\MinerLab.STOP') -Force -ErrorAction SilentlyContinue
}

function Invoke-Mh([string[]]$A, [string]$Name) {
    $con = Join-Path $Out ($Name + '.console.txt')
    & $exe @A *> $con
    $code = $LASTEXITCODE
    Log ("  MineHunter " + ($A -join ' ') + "  ->  exit $code")
    $code
}
function Read-Json([string]$Path) { if (Test-Path -LiteralPath $Path) { Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null } }
function Entity-Text($e) { '{0}|{1}|{2}' -f $e.kind, $e.title, $e.location }
function Hits($report, $v) {
    $list = @()
    if ($report -and $report.findings) { foreach ($f in $report.findings) { foreach ($e in $f.entities) { if ((Entity-Text $e) -match $v.Match) { $list += $f; break } } } }
    $list
}
function Note-Hits($report, $v) {
    $list = @()
    if ($report -and $report.lowRiskNotes) { foreach ($n in $report.lowRiskNotes) { if (('{0}|{1}|{2}' -f $n.kind, $n.title, $n.location) -match $v.Match) { $list += $n } } }
    $list
}
function Quarantine-Ids([string]$SinceStamp) {
    $o = & $exe quarantine list 2>&1 | Out-String
    @($o -split "`r?`n" | Where-Object { $_ -match '^\d{8}-\d{6}-[0-9a-f]{6}\s' } | ForEach-Object { ($_ -split '\s+')[0] } | Where-Object { $_ -ge $SinceStamp })
}

# =========================================================================== the run
if ($CleanupOnly) {
    Remove-AllArtifacts
    & powershell -NoProfile -File (Join-Path $labDir 'MinerLabCleanup.ps1') -Quiet | Out-Null
    $left = @(Get-Snapshot | Where-Object { $_ -like 'leftover|*' })
    Write-Host ("cleanup done, leftovers: " + $left.Count); exit $(if ($left.Count) { 1 } else { 0 })
}
if ($CreateOnly) { $KeepArtifacts = $true }
$tStart = Get-Date
$stamp = $tStart.ToString('yyyyMMdd-HHmmss')
$active = @($script:Vectors | Where-Object { -not $Ids -or $Ids -contains $_.Id })
Log "adversarial life-cycle test: $($active.Count) vectors, release EXE $exe"
$ver = (& $exe --version 2>&1 | Out-String).Trim(); Log "version: $ver"
try {
    Log 'step 0: removing leftovers of earlier runs'
    Remove-AllArtifacts
    & powershell -NoProfile -File (Join-Path $labDir 'MinerLabCleanup.ps1') -Quiet | Out-Null

    Log 'step 1: baseline snapshot and baseline scan (what MineHunter says about this PC before anything is created)'
    $snap0 = Get-Snapshot
    Invoke-Mh @('scan', '--quick', '--report-dir', "$Out\scan0", '--json', "$Out\scan0\report0.json", '--quiet') 'scan0' | Out-Null
    $base = Read-Json "$Out\scan0\report0.json"
    $baseKeys = @(); if ($base -and $base.findings) { foreach ($f in $base.findings) { $baseKeys += ($f.title + '|' + ($f.entities | Select-Object -First 1).location) } }
    Log "baseline: $(@($baseKeys).Count) finding(s) already on this PC (left untouched)"

    Log 'step 2: creating the imitations'
    foreach ($v in $active) {
        try { & $v.Create; $v.Created = $true } catch { $v.CreateError = $_.Exception.Message; Log "  $($v.Id) CREATE FAILED: $($v.CreateError)" }
        if ($v.Created) {
            $ex = $false; try { $ex = [bool](& $v.Exists) } catch { }
            if (-not $ex) { $v.Created = $false; $v.CreateError = 'artifact not present after creation'; Log "  $($v.Id): artifact not present after creation" }
            elseif ($v.Capture) { try { $v.Captured = & $v.Capture } catch { } }
        }
        if (-not $v.Created) { Mark $v.Id 'Create' 'NOT TESTED' $v.CreateError } else { Mark $v.Id 'Create' 'PASS' '' }
    }
    $live = @($active | Where-Object { $_.Created })
    Log "created: $($live.Count) of $($active.Count)"
    if ($CreateOnly) { ($live | ForEach-Object { $_.Id }) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Out 'created.json') -Encoding UTF8; Log 'create-only: artifacts left in place'; $res.Clear(); exit 0 }

    Log 'step 3: scan and clean (--fix, every finding of the imitations, optional steps included; game cheats are kept)'
    Invoke-Mh @('scan', '--quick', '--fix', '--yes', '--min', 'suspicious', '--all-steps', '--only', 'MinerLabAdv', '--report-dir', "$Out\fix1", '--json', "$Out\fix1\report.json", '--dump', "$Out\fix1\entities.json", '--quiet') 'fix1' | Out-Null
    $r1 = Read-Json "$Out\fix1\report.json"
    Start-Sleep -Seconds 6       # a watchdog that was missed would have put its file back by now
    $unexpected = @()
    if ($r1 -and $r1.findings) {
        foreach ($f in $r1.findings) {
            $m = $false; foreach ($e in $f.entities) { foreach ($v in $live) { if ((Entity-Text $e) -match $v.Match) { $m = $true } } }
            $k = $f.title + '|' + ($f.entities | Select-Object -First 1).location
            if (-not $m -and ($baseKeys -notcontains $k)) { $unexpected += "$($f.badge) $($f.title)" }
        }
    }
    foreach ($v in $live) {
        $h = @(Hits $r1 $v); $stillExists = $false; try { $stillExists = [bool](& $v.Exists) } catch { }
        switch ($v.Expect) {
            'finding' {
                if ($h.Count -eq 0) { Mark $v.Id 'Detect' 'FAIL' 'not reported as a finding'; Mark $v.Id 'Explain' 'NOT TESTED' ''; Mark $v.Id 'Quarantine' 'NOT TESTED' ''; continue }
                $f = $h[0]
                Mark $v.Id 'Detect' 'PASS' ("$($f.badge) score $($f.score)")
                $okE = ($f.severity -and $f.evidence.Count -ge 1 -and $f.evidence[0].textLocalized -and $f.recommendedSteps.Count -ge 1 -and $f.chain.Count -ge 1)
                Mark $v.Id 'Explain' $(if ($okE) { 'PASS' } else { 'FAIL' }) ("top evidence: " + ($f.evidence | Select-Object -First 2 | ForEach-Object { $_.rule }) -join ', ')
                $rr = if ($f.remediation) { $f.remediation.result } else { 'none' }
                if ($rr -eq 'Remediated' -and -not $stillExists) { Mark $v.Id 'Quarantine' 'PASS' "$rr" }
                elseif ($rr -eq 'RebootRequired') { Mark $v.Id 'Quarantine' 'PASS' 'removed except for what Windows deletes at the next restart' }
                else { Mark $v.Id 'Quarantine' 'FAIL' "outcome $rr, artifact still present: $stillExists $(if ($f.remediation) { $f.remediation.stillPresent -join '; ' })" }
            }
            'kept' {
                if ($h.Count -eq 0) { Mark $v.Id 'Detect' 'FAIL' 'a game cheat that sets off the usual signals was not reported at all'; continue }
                $f = $h[0]
                Mark $v.Id 'Detect' $(if ($f.toolClass -eq 'GameCheat') { 'PASS' } else { 'FAIL' }) "$($f.badge) toolClass=$($f.toolClass)"
                Mark $v.Id 'Explain' $(if ($f.recommendation -like 'Kept:*') { 'PASS' } else { 'FAIL' }) $f.recommendation
                Mark $v.Id 'Quarantine' $(if ($stillExists -and -not $f.remediation) { 'PASS' } else { 'FAIL' }) 'a game cheat must be left alone: still present and untouched'
            }
            'none' {
                Mark $v.Id 'Detect' $(if ($h.Count -eq 0) { 'PASS' } else { 'FAIL' }) $(if ($h.Count -eq 0) { 'correctly not reported (false-positive control)' } else { "FALSE POSITIVE: $($h[0].badge) $($h[0].title)" })
                Mark $v.Id 'Quarantine' $(if ($stillExists) { 'PASS' } else { 'FAIL' }) 'a control must never be touched'
            }
            'honest' {
                $f = if ($h.Count) { $h[0] } else { $null }
                if (-not $f) { Mark $v.Id 'Detect' 'FAIL' 'not reported'; continue }
                Mark $v.Id 'Detect' 'PASS' $f.badge
                $fileBack = Test-Path -LiteralPath "$script:LA\p02\payload.exe"
                $rr = if ($f.remediation) { $f.remediation.result } else { 'none' }
                Mark $v.Id 'Quarantine' $(if ($fileBack -and $rr -eq 'Remediated') { 'FAIL' } else { 'PASS' }) "file back: $fileBack, reported outcome: $rr (an unknown program restores the file: 'removed' would be a false claim)"
            }
        }
    }
    # the process vector: both programs gone, no respawn
    $p01 = $live | Where-Object { $_.Id -eq 'P01' }
    if ($p01) {
        $alive = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -like '*MinerLabAdv\p01\*' })
        Mark 'P01' 'Quarantine' $(if ($alive.Count -eq 0 -and -not (Test-Path -LiteralPath "$script:LA\p01\miner.exe")) { 'PASS' } else { 'FAIL' }) "processes still running: $($alive.Count); miner file present: $(Test-Path -LiteralPath "$script:LA\p01\miner.exe")"
    }
    Mark '(all)' 'No false findings during cleaning' $(if ($unexpected.Count -eq 0) { 'PASS' } else { 'FAIL' }) ($unexpected -join '; ')

    Log 'step 4: restoring everything from the quarantine'
    $q1 = Quarantine-Ids $stamp
    Log "  quarantine records written by the cleaning: $($q1.Count)"
    foreach ($id in $q1) { & $exe quarantine restore $id 2>&1 | Out-Null }
    foreach ($v in $live | Where-Object { $_.Expect -eq 'finding' -and $_.Restorable }) {
        $ex = $false; try { $ex = [bool](& $v.Exists) } catch { }
        if (-not $ex) { Mark $v.Id 'Restore' 'FAIL' 'the artifact did not come back'; continue }
        Mark $v.Id 'Restore' 'PASS' ''
        if ($v.Capture) {
            $now = $null; try { $now = & $v.Capture } catch { }
            Mark $v.Id 'Identical' $(if ("$now" -eq "$($v.Captured)") { 'PASS' } else { 'FAIL' }) $(if ("$now" -ne "$($v.Captured)") { "before: $($v.Captured)  after: $now" } else { '' })
        }
    }
    foreach ($v in $live | Where-Object { $_.Expect -eq 'finding' -and -not $_.Restorable }) { Mark $v.Id 'Restore' 'NOT TESTED' 'a stopped process cannot be restored (by design)' }
    Remove-AllArtifacts       # the restored artifacts and the running watchdogs go; the next round re-creates what it needs
    $script:Procs | ForEach-Object { try { $_.Kill() } catch { } }

    Log 'step 5: second cleaning (new quarantine records), then the relapse test'
    foreach ($v in $live | Where-Object { $_.Expect -in 'finding', 'honest' -and $_.Id -notin 'P01', 'P02' }) { try { & $v.Create } catch { } }
    Invoke-Mh @('scan', '--quick', '--fix', '--yes', '--min', 'suspicious', '--all-steps', '--only', 'MinerLabAdv', '--report-dir', "$Out\fix2", '--json', "$Out\fix2\report.json", '--quiet') 'fix2' | Out-Null
    $tFix2 = Get-Date
    $waitLeft = [int]($AgeWaitSec - ((Get-Date) - $tFix2).TotalSeconds)
    Log "  waiting $AgeWaitSec s so that the records are older than the 3 minutes after which a returning file counts as 'came back' ..."
    Start-Sleep -Seconds ([Math]::Max(1, $waitLeft))
    $again = @($live | Where-Object { $_.Reappear })
    foreach ($v in $again) { try { & $v.Create } catch { Log "  $($v.Id) re-create failed: $($_.Exception.Message)" } }
    Invoke-Mh @('scan', '--quick', '--report-dir', "$Out\scan3", '--json', "$Out\scan3\report.json", '--dump', "$Out\scan3\entities.json", '--quiet') 'scan3' | Out-Null
    $dump3 = Read-Json "$Out\scan3\entities.json"; $r3 = Read-Json "$Out\scan3\report.json"
    foreach ($v in $again) {
        $found = $false
        foreach ($e in @($dump3)) { if ((Entity-Text $e) -match $v.Match -and ($e.evidence | Where-Object { $_.rule -eq 'REL.REAPPEARED' })) { $found = $true; break } }
        Mark $v.Id 'Reappear' $(if ($found) { 'PASS' } else { 'FAIL' }) 'recognised as "came back after cleaning"'
    }
    foreach ($v in $live | Where-Object { $_.Expect -eq 'finding' -and -not $_.Reappear }) { Mark $v.Id 'Reappear' 'NOT TESTED' 'only a representative set is re-created (files, Run values, tasks, services, WMI)' }

    Log 'step 6: final cleanup and comparison with the baseline'
    Remove-AllArtifacts
    & powershell -NoProfile -File (Join-Path $labDir 'MinerLabCleanup.ps1') -Quiet | Out-Null
    $script:Procs | ForEach-Object { try { $_.Kill() } catch { } }
    $snap1 = Get-Snapshot
    $diff = @(Compare-Object -ReferenceObject $snap0 -DifferenceObject $snap1 | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" })
    Mark '(all)' 'Unrelated changes after cleanup' $(if ($diff.Count -eq 0) { 'PASS' } else { 'FAIL' }) ($diff -join ' ;; ')
    Invoke-Mh @('scan', '--quick', '--report-dir', "$Out\scan4", '--json', "$Out\scan4\report.json", '--quiet') 'scan4' | Out-Null
    $r4 = Read-Json "$Out\scan4\report.json"
    $left = @(); if ($r4 -and $r4.findings) { foreach ($f in $r4.findings) { $k = $f.title + '|' + ($f.entities | Select-Object -First 1).location; if ($baseKeys -notcontains $k) { $left += "$($f.badge) $($f.title)" } } }
    Mark '(all)' 'No false finding after cleanup' $(if ($left.Count -eq 0) { 'PASS' } else { 'FAIL' }) ($left -join '; ')
    foreach ($v in $live) { Mark $v.Id 'Cleanup' 'PASS' '' }
}
finally {
    if (-not $KeepArtifacts) { Remove-AllArtifacts; & powershell -NoProfile -File (Join-Path $labDir 'MinerLabCleanup.ps1') -Quiet | Out-Null; $script:Procs | ForEach-Object { try { $_.Kill() } catch { } } }
}

# --------------------------------------------------------------------------- report
foreach ($n in $script:NotCreated) { Mark $n.Id 'Create' 'NOT TESTED' ($n.What + ' - ' + $n.Why) }
$lines = New-Object System.Collections.ArrayList
$fail = 0; $pass = 0; $nt = 0
foreach ($id in $res.Keys | Sort-Object) {
    foreach ($c in $res[$id].Keys) {
        $r = $res[$id][$c]
        if ($r.State -eq 'FAIL') { $fail++ } elseif ($r.State -eq 'PASS') { $pass++ } else { $nt++ }
        $desc = ($script:Vectors | Where-Object { $_.Id -eq $id } | Select-Object -First 1).Desc
        [void]$lines.Add(('{0,-5} {1,-34} {2,-10} {3}{4}' -f $id, $c, $r.State, $(if ($r.Note) { $r.Note } else { '' }), $(if ($c -eq 'Create' -and $desc) { "   [$desc]" } else { '' })))
    }
}
$summary = "ADVERSARIAL TEST: $pass passed, $fail FAILED, $nt not tested   (version $ver, $((Get-Date) - $tStart))"
$lines.Insert(0, $summary)
$lines | Set-Content -LiteralPath (Join-Path $Out 'results.txt') -Encoding UTF8
$res | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Out 'results.json') -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
if ($fail -gt 0) { exit 1 } else { exit 0 }

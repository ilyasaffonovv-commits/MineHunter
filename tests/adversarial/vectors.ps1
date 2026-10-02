<#
  vectors.ps1 - the harmless imitations used by run.ps1.
  Every vector only CREATES a test artifact that points at MinerLab's own harness (it idles for a few seconds, opens nothing, downloads nothing);
  nothing here ever runs anything malicious. Every artifact carries the label MinerLabAdv so that it can be found and removed again.

  A vector is: Id, Description, Create {}, Exists {} (is the artifact there?), Match (regex over "kind|title|location" of what MineHunter reports),
  Expect ('finding' = reported as a finding that gets cleaned; 'kept' = reported but deliberately not removed (game cheat); 'none' = must NOT be reported),
  Restorable (a quarantine round trip is expected to bring it back), Capture {} (what must be identical after a restore), Reappear (re-created after cleaning to test the relapse check).
  What was NOT turned into a vector, and why, is listed in $script:NotCreated (always shown in the report as NOT TESTED).
#>
$script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:Harness = Join-Path $script:Root 'tests\MinerLab\bin\MinerSimulation.exe'
$script:LA = Join-Path $env:LOCALAPPDATA 'MinerLabAdv'
$script:AP = Join-Path $env:APPDATA 'MinerLabAdv'
$script:TMPD = Join-Path $env:TEMP 'MinerLabAdv'
$script:DL = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\MinerLabAdv'
$script:PUB = 'C:\Users\Public\MinerLabAdv'
$script:Startup = [Environment]::GetFolderPath('Startup')
$script:IDLE = '--mode idle --seconds 5 --label MinerLabAdv'
$script:Dirs = @($script:LA, $script:AP, $script:TMPD, $script:DL, $script:PUB)
$script:Vectors = New-Object System.Collections.ArrayList

# --------------------------------------------------------------------------- helpers
function Copy-Unique([string]$Dest) {
    New-Item -ItemType Directory -Force (Split-Path $Dest -Parent) | Out-Null
    Copy-Item -LiteralPath $script:Harness -Destination $Dest -Force
    $tail = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes('MinerLabAdv|' + $Dest.ToLowerInvariant()))
    $fs = [IO.File]::Open($Dest, 'Append', 'Write'); try { $fs.Write($tail, 0, $tail.Length) } finally { $fs.Dispose() }
    $Dest
}
function Set-RegStr([string]$Key, [string]$Name, [string]$Value, [string]$Type = 'String') {
    if (-not (Test-Path -LiteralPath $Key)) { New-Item -Path $Key -Force | Out-Null }
    if ($Name -eq '(default)') { Set-ItemProperty -LiteralPath $Key -Name '(default)' -Value $Value }
    else { New-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null }
}
function Get-RegStr([string]$Key, [string]$Name) {
    try { (Get-ItemProperty -LiteralPath $Key -ErrorAction Stop).$Name } catch { $null }
}
function Has-RegVal([string]$Key, [string]$Name) { $null -ne (Get-RegStr $Key $Name) }
function Remove-RegKey([string]$Key) { if (Test-Path -LiteralPath $Key) { Remove-Item -LiteralPath $Key -Recurse -Force -ErrorAction SilentlyContinue } }
function Has-Svc([string]$Name) { $null -ne (Get-Service -Name $Name -ErrorAction SilentlyContinue) }
function Has-Task([string]$Name) { $o = & schtasks.exe /query /tn $Name 2>&1; $LASTEXITCODE -eq 0 }
function Invoke-Sc([string[]]$Args2) { & sc.exe @Args2 | Out-Null }
# an argument for a native program that must contain double quotes
function Q([string]$s) { '\"' + $s + '\"' }
# a binary stream of a file (needs Windows PowerShell 5.1: -Stream)
function Set-Stream([string]$File, [string]$Stream, [string]$SourceExe) { Set-Content -LiteralPath $File -Stream $Stream -Encoding Byte -Value ([IO.File]::ReadAllBytes($SourceExe)) }
function Sha([string]$Path) { if (Test-Path -LiteralPath $Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash } else { $null } }
function Vec([string]$Id, [string]$Desc, [scriptblock]$Create, [scriptblock]$Exists, [string]$Match, [string]$Expect, [bool]$Restorable = $true, [scriptblock]$Capture = $null, [bool]$Reappear = $false) {
    [void]$script:Vectors.Add([pscustomobject]@{ Id = $Id; Desc = $Desc; Create = $Create; Exists = $Exists; Match = $Match; Expect = $Expect; Restorable = $Restorable; Capture = $Capture; Reappear = $Reappear; Captured = $null; Created = $false; CreateError = $null })
}
$clsRoot = 'HKCU:\Software\Classes\CLSID'
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# --------------------------------------------------------------------------- registry autostart points
Vec 'R01' 'HKCU Run value -> unique harness in LocalAppData' {
    $exe = Copy-Unique "$script:LA\r01\app.exe"; Set-RegStr $run 'MinerLabAdvRun01' ('"' + $exe + '" ' + $script:IDLE)
} { Has-RegVal $run 'MinerLabAdvRun01' } 'MinerLabAdvRun01|\\MinerLabAdv\\r01\\' 'finding' $true { Get-RegStr $run 'MinerLabAdvRun01' } $true

Vec 'R02' 'HKCU RunOnce value' {
    $exe = Copy-Unique "$script:LA\r02\app.exe"; Set-RegStr 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' 'MinerLabAdvRun02' ('"' + $exe + '" ' + $script:IDLE)
} { Has-RegVal 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' 'MinerLabAdvRun02' } 'MinerLabAdvRun02|\\MinerLabAdv\\r02\\' 'finding' $true { Get-RegStr 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' 'MinerLabAdvRun02' }

Vec 'R03' 'HKLM Policies\Explorer\Run value' {
    $exe = Copy-Unique "$script:LA\r03\app.exe"; Set-RegStr 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' 'MinerLabAdvRun03' ('"' + $exe + '" ' + $script:IDLE)
} { Has-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' 'MinerLabAdvRun03' } 'MinerLabAdvRun03|\\MinerLabAdv\\r03\\' 'finding' $true { Get-RegStr 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' 'MinerLabAdvRun03' }

Vec 'R04' 'Windows Load value (old autostart trick)' {
    $exe = Copy-Unique "$script:LA\r04\app.exe"; Set-RegStr 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' 'Load' ('"' + $exe + '" ' + $script:IDLE)
} { Has-RegVal 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' 'Load' } 'Windows Load|\\MinerLabAdv\\r04\\' 'finding' $true { Get-RegStr 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' 'Load' }

Vec 'R05' 'cmd.exe AutoRun (runs whenever any Command Prompt starts; idles 1 s)' {
    $exe = Copy-Unique "$script:LA\r05\app.exe"; Set-RegStr 'HKCU:\Software\Microsoft\Command Processor' 'AutoRun' ('"' + $exe + '" --mode idle --seconds 1 --label MinerLabAdv')
} { Has-RegVal 'HKCU:\Software\Microsoft\Command Processor' 'AutoRun' } 'AutoRun|\\MinerLabAdv\\r05\\' 'finding' $true { Get-RegStr 'HKCU:\Software\Microsoft\Command Processor' 'AutoRun' }

Vec 'R06' 'per-user handler of a made-up file type (.mlabadv)' {
    $exe = Copy-Unique "$script:LA\r06\app.exe"; Set-RegStr 'HKCU:\Software\Classes\.mlabadv\shell\open\command' '(default)' ('"' + $exe + '" ' + $script:IDLE)
} { Has-RegVal 'HKCU:\Software\Classes\.mlabadv\shell\open\command' '(default)' } 'mlabadv|\\MinerLabAdv\\r06\\' 'finding' $true { Get-RegStr 'HKCU:\Software\Classes\.mlabadv\shell\open\command' '(default)' }

Vec 'R07' 'per-user ms-settings override (UAC bypass pattern)' {
    if (Test-Path 'HKCU:\Software\Classes\ms-settings') { throw 'HKCU ms-settings already exists on this PC: not touched' }
    $exe = Copy-Unique "$script:LA\r07\app.exe"; Set-RegStr 'HKCU:\Software\Classes\ms-settings\shell\open\command' '(default)' ('"' + $exe + '" ' + $script:IDLE)
    Set-RegStr 'HKCU:\Software\Classes\ms-settings\shell\open\command' 'DelegateExecute' ''
} { Has-RegVal 'HKCU:\Software\Classes\ms-settings\shell\open\command' '(default)' } 'ms-settings|\\MinerLabAdv\\r07\\' 'finding' $true { Get-RegStr 'HKCU:\Software\Classes\ms-settings\shell\open\command' '(default)' }

Vec 'R08' 'IFEO debugger for a made-up program name' {
    $exe = Copy-Unique "$script:LA\r08\app.exe"; Set-RegStr "$ifeo\MinerLabAdvApp.exe" 'Debugger' ('"' + $exe + '" ' + $script:IDLE)
} { Has-RegVal "$ifeo\MinerLabAdvApp.exe" 'Debugger' } 'MinerLabAdvApp|\\MinerLabAdv\\r08\\' 'finding' $true { Get-RegStr "$ifeo\MinerLabAdvApp.exe" 'Debugger' }

Vec 'R09' 'SilentProcessExit monitor for a made-up program name' {
    $exe = Copy-Unique "$script:LA\r09\app.exe"; Set-RegStr 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\MinerLabAdvApp9.exe' 'MonitorProcess' ('"' + $exe + '" ' + $script:IDLE)
} { Has-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\MinerLabAdvApp9.exe' 'MonitorProcess' } 'MinerLabAdvApp9|\\MinerLabAdv\\r09\\' 'finding' $true { Get-RegStr 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\MinerLabAdvApp9.exe' 'MonitorProcess' }

Vec 'R10' 'IFEO verifier DLL for a made-up program name' {
    $dll = Copy-Unique "$script:LA\r10\v.dll"; Set-RegStr "$ifeo\MinerLabAdvApp10.exe" 'VerifierDlls' $dll
} { Has-RegVal "$ifeo\MinerLabAdvApp10.exe" 'VerifierDlls' } 'MinerLabAdvApp10|\\MinerLabAdv\\r10\\' 'finding' $true { Get-RegStr "$ifeo\MinerLabAdvApp10.exe" 'VerifierDlls' }

Vec 'R11' 'Active Setup StubPath' {
    $exe = Copy-Unique "$script:LA\r11\app.exe"
    $k = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{7A1B0C2D-0000-4000-8000-00000000AD11}'
    Set-RegStr $k 'StubPath' ('"' + $exe + '" ' + $script:IDLE); Set-RegStr $k 'Version' '1,0,0,1'
} { Has-RegVal 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{7A1B0C2D-0000-4000-8000-00000000AD11}' 'StubPath' } 'AD11|\\MinerLabAdv\\r11\\' 'finding' $true { Get-RegStr 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{7A1B0C2D-0000-4000-8000-00000000AD11}' 'StubPath' }

Vec 'R12' 'per-user COM class whose server is a program in a user folder' {
    $dll = Copy-Unique "$script:LA\r12\server.dll"; Set-RegStr "$clsRoot\{7A1B0C2D-0000-4000-8000-00000000AD12}\InprocServer32" '(default)' $dll
} { Has-RegVal "$clsRoot\{7A1B0C2D-0000-4000-8000-00000000AD12}\InprocServer32" '(default)' } 'AD12|\\MinerLabAdv\\r12\\' 'finding' $true { Get-RegStr "$clsRoot\{7A1B0C2D-0000-4000-8000-00000000AD12}\InprocServer32" '(default)' }

Vec 'R13' 'per-user COM scriptlet class' {
    New-Item -ItemType Directory -Force "$script:LA\r13" | Out-Null
    Set-Content -LiteralPath "$script:LA\r13\x.sct" -Value '<!-- MinerLabAdv: benign empty scriptlet -->' -Encoding ASCII
    $k = "$clsRoot\{7A1B0C2D-0000-4000-8000-00000000AD13}"
    Set-RegStr "$k\InprocServer32" '(default)' "$env:SystemRoot\System32\scrobj.dll"
    Set-RegStr "$k\ScriptletURL" '(default)' ('script:file:///' + ("$script:LA\r13\x.sct" -replace '\\', '/'))
} { Has-RegVal "$clsRoot\{7A1B0C2D-0000-4000-8000-00000000AD13}\ScriptletURL" '(default)' } 'AD13|ScriptletURL' 'finding' $true { Get-RegStr "$clsRoot\{7A1B0C2D-0000-4000-8000-00000000AD13}\ScriptletURL" '(default)' }

Vec 'R14' 'Run value that starts a program out of a hidden NTFS stream' {
    $exe = Copy-Unique "$script:LA\r14\app.exe"
    Set-Content -LiteralPath "$script:LA\r14\notes.txt" -Value 'meeting notes' -Encoding ASCII
    Set-Stream "$script:LA\r14\notes.txt" 'payload.exe' $exe
    Set-RegStr $run 'MinerLabAdvRun14' ('cmd.exe /c start "" "' + "$script:LA\r14\notes.txt" + ':payload.exe"')
} { Has-RegVal $run 'MinerLabAdvRun14' } 'MinerLabAdvRun14|\\MinerLabAdv\\r14\\' 'finding' $true { Get-RegStr $run 'MinerLabAdvRun14' } $true

Vec 'R15' 'DLL side-loading pair: a signed program in a user folder with an unsigned version.dll beside it, started by Run' {
    New-Item -ItemType Directory -Force "$script:LA\r15" | Out-Null
    Copy-Item "$env:SystemRoot\System32\notepad.exe" "$script:LA\r15\notepad.exe" -Force
    Copy-Unique "$script:LA\r15\version.dll" | Out-Null
    Set-RegStr $run 'MinerLabAdvRun15' ('"' + "$script:LA\r15\notepad.exe" + '"')
} { Has-RegVal $run 'MinerLabAdvRun15' } 'MinerLabAdvRun15|\\MinerLabAdv\\r15\\' 'finding' $true { Get-RegStr $run 'MinerLabAdvRun15' }

# --------------------------------------------------------------------------- services and drivers (never started)
Vec 'S01' 'service with a program in a user folder' {
    $exe = Copy-Unique "$script:LA\s01\svc.exe"
    Invoke-Sc @('create', 'MinerLabAdvSvc01', 'binPath=', ((Q $exe) + ' --mode service --svcname MinerLabAdvSvc01 --seconds 20'), 'start=', 'demand', 'DisplayName=', 'MinerLabAdv service 01')
} { Has-Svc 'MinerLabAdvSvc01' } 'MinerLabAdvSvc01|\\MinerLabAdv\\s01\\' 'finding' $true { Get-RegStr 'HKLM:\SYSTEM\CurrentControlSet\Services\MinerLabAdvSvc01' 'ImagePath' } $true

Vec 'S02' 'service that is only a wrapper (NSSM style): the real program is a parameter' {
    $exe = Copy-Unique "$script:LA\s02\app.exe"
    Invoke-Sc @('create', 'MinerLabAdvNssm02', 'binPath=', "$env:SystemRoot\System32\notepad.exe", 'start=', 'demand')
    Set-RegStr 'HKLM:\SYSTEM\CurrentControlSet\Services\MinerLabAdvNssm02\Parameters' 'Application' $exe
} { Has-Svc 'MinerLabAdvNssm02' } 'MinerLabAdvNssm02|\\MinerLabAdv\\s02\\' 'finding' $true { Get-RegStr 'HKLM:\SYSTEM\CurrentControlSet\Services\MinerLabAdvNssm02\Parameters' 'Application' }

Vec 'S03' 'shared-process service whose ServiceDll is in a user folder' {
    $dll = Copy-Unique "$script:LA\s03\svc.dll"
    Invoke-Sc @('create', 'MinerLabAdvDll03', 'type=', 'share', 'binPath=', '%SystemRoot%\system32\svchost.exe -k MinerLabAdvGroup', 'start=', 'demand')
    Set-RegStr 'HKLM:\SYSTEM\CurrentControlSet\Services\MinerLabAdvDll03\Parameters' 'ServiceDll' $dll 'ExpandString'
} { Has-Svc 'MinerLabAdvDll03' } 'MinerLabAdvDll03|\\MinerLabAdv\\s03\\' 'finding' $true { Get-RegStr 'HKLM:\SYSTEM\CurrentControlSet\Services\MinerLabAdvDll03\Parameters' 'ServiceDll' }

Vec 'S04' 'service recovery command that starts a program in a user folder' {
    $exe = Copy-Unique "$script:LA\s04\app.exe"
    Invoke-Sc @('create', 'MinerLabAdvFail04', 'binPath=', "$env:SystemRoot\System32\notepad.exe", 'start=', 'demand')
    Invoke-Sc @('failure', 'MinerLabAdvFail04', 'reset=', '3600', 'command=', ((Q $exe) + ' --mode idle --seconds 3'), 'actions=', 'run/60000')
} { Has-Svc 'MinerLabAdvFail04' } 'MinerLabAdvFail04|\\MinerLabAdv\\s04\\' 'finding' $true { Get-RegStr 'HKLM:\SYSTEM\CurrentControlSet\Services\MinerLabAdvFail04' 'FailureCommand' }

Vec 'S05' 'kernel-driver service entry whose file is in a user folder (never loaded)' {
    $sys = Copy-Unique "$script:LA\s05\drv.sys"
    Invoke-Sc @('create', 'MinerLabAdvDrv05', 'type=', 'kernel', 'start=', 'demand', 'binPath=', $sys)
} { Has-Svc 'MinerLabAdvDrv05' } 'MinerLabAdvDrv05|\\MinerLabAdv\\s05\\' 'finding' $true { Get-RegStr 'HKLM:\SYSTEM\CurrentControlSet\Services\MinerLabAdvDrv05' 'ImagePath' }

# --------------------------------------------------------------------------- scheduled tasks
Vec 'T01' 'task whose command uses an environment variable path' {
    $exe = Copy-Unique "$script:LA\t01\app.exe"
    & schtasks.exe /create /tn 'MinerLabAdvTask01' /tr ('\"%LOCALAPPDATA%\MinerLabAdv\t01\app.exe\" --mode idle --seconds 5') /sc onlogon /f | Out-Null
} { Has-Task 'MinerLabAdvTask01' } 'MinerLabAdvTask01|\\MinerLabAdv\\t01\\' 'finding' $true { (& schtasks.exe /query /tn 'MinerLabAdvTask01' /xml | Out-String).Length } $true

Vec 'T02' 'task that starts when the PC is idle' {
    $exe = Copy-Unique "$script:LA\t02\app.exe"
    $xml = '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>MinerLabAdv benign idle task</Description></RegistrationInfo><Triggers><IdleTrigger><Enabled>true</Enabled></IdleTrigger></Triggers><Settings><Enabled>true</Enabled><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout></IdleSettings></Settings><Actions Context="Author"><Exec><Command>' + $exe + '</Command><Arguments>--mode idle --seconds 5</Arguments></Exec></Actions></Task>'
    $xf = Join-Path $env:TEMP 'MinerLabAdvTask02.xml'
    [IO.File]::WriteAllText($xf, $xml, [Text.Encoding]::Unicode)
    & schtasks.exe /create /tn 'MinerLabAdvTask02' /xml $xf /f | Out-Null
    Remove-Item -LiteralPath $xf -Force -ErrorAction SilentlyContinue
} { Has-Task 'MinerLabAdvTask02' } 'MinerLabAdvTask02|\\MinerLabAdv\\t02\\' 'finding' $true { (& schtasks.exe /query /tn 'MinerLabAdvTask02' /xml | Out-String).Length }

# --------------------------------------------------------------------------- WMI in a namespace nobody looks at
Vec 'W01' 'WMI permanent subscription kept in root\default, started through ExecutablePath' {
    $exe = Copy-Unique "$script:LA\w01\app.exe"
    $q = "SELECT * FROM __InstanceCreationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'MinerLabAdvNeverMatches.exe'"
    $flt = Set-WmiInstance -Namespace root\default -Class __EventFilter -Arguments @{ Name = 'MinerLabAdvFilter01'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = $q }
    $con = Set-WmiInstance -Namespace root\default -Class CommandLineEventConsumer -Arguments @{ Name = 'MinerLabAdvConsumer01'; CommandLineTemplate = $script:IDLE; ExecutablePath = $exe }
    Set-WmiInstance -Namespace root\default -Class __FilterToConsumerBinding -Arguments @{ Filter = $flt; Consumer = $con } | Out-Null
} { $null -ne (Get-WmiObject -Namespace root\default -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'MinerLabAdvConsumer01' }) } 'MinerLabAdvConsumer01|\\MinerLabAdv\\w01\\' 'finding' $true { (Get-WmiObject -Namespace root\default -Class CommandLineEventConsumer | Where-Object { $_.Name -eq 'MinerLabAdvConsumer01' }).ExecutablePath } $true

# --------------------------------------------------------------------------- files and shortcuts
Vec 'F01' 'hidden batch file in the Startup folder' {
    $exe = Copy-Unique "$script:LA\f01\app.exe"
    $f = Join-Path $script:Startup 'MinerLabAdvStart.cmd'
    Set-Content -LiteralPath $f -Value ('@echo off' + "`r`n" + 'start "" "' + $exe + '" ' + $script:IDLE) -Encoding ASCII
    (Get-Item -LiteralPath $f -Force).Attributes = 'Hidden'
} { Test-Path -LiteralPath (Join-Path $script:Startup 'MinerLabAdvStart.cmd') } 'MinerLabAdvStart|\\MinerLabAdv\\f01\\' 'finding' $true { Sha (Join-Path $script:Startup 'MinerLabAdvStart.cmd') }

Vec 'F02' 'archive in Downloads that holds a program named like a known miner' {
    New-Item -ItemType Directory -Force $script:DL | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zf = Join-Path $script:DL 'MinerLabAdvTools.zip'
    if (Test-Path $zf) { Remove-Item $zf -Force }
    $za = [IO.Compression.ZipFile]::Open($zf, 'Create')
    $n = 'xm' + 'rig'
    foreach ($e in @("$n-6.21.0/$n.exe", 'readme.txt')) { $en = $za.CreateEntry($e); $sw = New-Object IO.StreamWriter($en.Open()); $sw.Write('MinerLabAdv benign placeholder'); $sw.Dispose() }
    $za.Dispose()
} { Test-Path -LiteralPath "$script:DL\MinerLabAdvTools.zip" } 'MinerLabAdvTools' 'finding' $true { Sha "$script:DL\MinerLabAdvTools.zip" }

Vec 'F03' 'program whose name hides its real extension with a right-to-left override' {
    Copy-Unique ("$script:AP\f03\invoice" + [char]0x202E + 'txt.exe') | Out-Null
} { (Get-ChildItem -LiteralPath "$script:AP\f03" -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name.Contains([string][char]0x202E) }) -ne $null } 'f03|invoice' 'finding' $true { (Get-ChildItem -LiteralPath "$script:AP\f03" -Force | Select-Object -First 1 | ForEach-Object { Sha $_.FullName }) } $true

Vec 'F04' 'program with a double extension (a "photo" that is a program)' {
    Copy-Unique "$script:AP\f04\holiday-photo.jpg.exe" | Out-Null
} { Test-Path -LiteralPath "$script:AP\f04\holiday-photo.jpg.exe" } 'holiday-photo' 'finding' $true { Sha "$script:AP\f04\holiday-photo.jpg.exe" }

Vec 'F05' 'program hidden in an alternate data stream of a text file (nothing starts it)' {
    $exe = Copy-Unique "$script:LA\f05\app.exe"
    Set-Content -LiteralPath "$script:LA\f05\readme.txt" -Value 'just a readme' -Encoding ASCII
    Set-Stream "$script:LA\f05\readme.txt" 'hidden.exe' $exe
    Remove-Item -LiteralPath $exe -Force
} { (Get-Item -LiteralPath "$script:LA\f05\readme.txt" -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -eq 'hidden.exe' }) -ne $null } 'f05\\readme' 'finding' $true { (Get-Item -LiteralPath "$script:LA\f05\readme.txt" -Stream hidden.exe -ErrorAction SilentlyContinue).Length }

Vec 'F06' 'miner configuration file (pool, wallet, algorithm) with no program beside it' {
    New-Item -ItemType Directory -Force "$script:AP\f06" | Out-Null
    $cfg = '{"autosave": true, "pools": [{"url": "127.0.0.1:3333", "user": "MinerLabAdvWalletNotReal0000000", "pass": "x", "keepalive": true}], "algo": "' + ('rx' + '/0') + '", "' + ('donate' + '-level') + '": 1, "_comment": "MinerLabAdv benign file"}'
    Set-Content -LiteralPath "$script:AP\f06\config.json" -Value $cfg -Encoding ASCII
} { Test-Path -LiteralPath "$script:AP\f06\config.json" } 'f06\\config' 'finding' $true { Sha "$script:AP\f06\config.json" }

Vec 'F07' 'hidden and system-flagged program in the shared Public folder' {
    $f = Copy-Unique "$script:PUB\f07\update.exe"
    (Get-Item -LiteralPath $f -Force).Attributes = 'Hidden, System'
} { Test-Path -LiteralPath "$script:PUB\f07\update.exe" } 'MinerLabAdv\\f07' 'finding' $true { Sha "$script:PUB\f07\update.exe" }

Vec 'F08' 'CONTROL: Microsoft-signed notepad.exe copied into a user folder' {
    New-Item -ItemType Directory -Force "$script:LA\f08" | Out-Null
    Copy-Item "$env:SystemRoot\System32\notepad.exe" "$script:LA\f08\notepad.exe" -Force
} { Test-Path -LiteralPath "$script:LA\f08\notepad.exe" } 'MinerLabAdv\\f08' 'none' $true { Sha "$script:LA\f08\notepad.exe" }

Vec 'F09' 'GAME CHEAT (not a miner): a tool called like a known cheat, started by Run' {
    $exe = Copy-Unique "$script:LA\f09\CheatEngine\cheatengine-x86_64.exe"; Set-RegStr $run 'MinerLabAdvRun09' ('"' + $exe + '" ' + $script:IDLE)
} { Has-RegVal $run 'MinerLabAdvRun09' } 'MinerLabAdvRun09|\\MinerLabAdv\\f09\\' 'kept' $true { Sha "$script:LA\f09\CheatEngine\cheatengine-x86_64.exe" }

Vec 'F10' 'CHEAT THAT CARRIES A MINER: the same kind of tool with a miner configuration beside it' {
    $exe = Copy-Unique "$script:LA\f10\CheatEngine\cheatengine-x64.exe"; Set-RegStr $run 'MinerLabAdvRun10' ('"' + $exe + '" ' + $script:IDLE)
    $cfg = '{"autosave": true, "pools": [{"url": "127.0.0.1:3333", "user": "MinerLabAdvWalletNotReal0000001", "pass": "x"}], "algo": "' + ('rx' + '/0') + '", "' + ('donate' + '-level') + '": 1}'
    Set-Content -LiteralPath "$script:LA\f10\CheatEngine\config.json" -Value $cfg -Encoding ASCII
} { Has-RegVal $run 'MinerLabAdvRun10' } 'MinerLabAdvRun10|\\MinerLabAdv\\f10\\' 'finding' $true { Sha "$script:LA\f10\CheatEngine\cheatengine-x64.exe" }

# --------------------------------------------------------------------------- what is deliberately not created on a real PC
$script:NotCreated = @(
    @{ Id = 'N01'; What = 'Winlogon Shell / Userinit, AppInit_DLLs, AppCertDlls, LSA packages, KnownDLLs, Session Manager boot commands, SYSTEM\Setup CmdLine, RDP initial program, AppCompat shim database'; Why = 'a wrong value in these keys can stop Windows from starting or open a hole in every program; they are tested on a scratch registry hive in the self test (autostart: ... checks), not on the real one' },
    @{ Id = 'N02'; What = 'Defender exclusion, hosts-file block, firewall rule against a security program'; Why = 'these change the security settings of the computer; the lab never touches them. Detection and removal are covered by the self test and by the earlier lab runs only in code paths, not on the live system' },
    @{ Id = 'N03'; What = 'task with a damaged XML definition, task cache entry without a file'; Why = 'the Task Scheduler refuses to register a broken definition, so the real thing cannot be created without editing its private store; covered by the self test (damaged XML read as text)' },
    @{ Id = 'N04'; What = 'process hollowing, herpaderping, manually mapped code, unsigned module inside a signed process'; Why = 'a benign program cannot do these without writing the attack code itself; covered only by reading real processes on this PC (no false positives) and by the memory-marker lab (D10-D12)' },
    @{ Id = 'N05'; What = 'rootkits, kernel-level hiding, malicious drivers that are actually loaded'; Why = 'cannot be created safely; MineHunter has no kernel component and says so' }
)

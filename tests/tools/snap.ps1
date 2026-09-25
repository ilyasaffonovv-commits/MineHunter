<#
  snap.ps1 - takes a read-only snapshot of persistence-relevant Windows state and writes it as JSON.
  Used to compare BEFORE / AFTER a tool run (MinerSearch, MineHunter, the synthetic MinerLab).
  It never modifies the system.
#>
param(
    [Parameter(Mandatory)][string]$Out,
    [string[]]$ExtraDirs = @()
)
$ErrorActionPreference = 'SilentlyContinue'; $SnapDebug = $true
$snap = [ordered]@{}
$snap.meta = [ordered]@{ taken = (Get-Date).ToString('o'); computer = $env:COMPUTERNAME; user = $env:USERNAME }

# ---- processes
$snap.processes = @(Get-CimInstance Win32_Process | ForEach-Object {
    [ordered]@{ pid = $_.ProcessId; ppid = $_.ParentProcessId; name = $_.Name; path = $_.ExecutablePath; cmd = $_.CommandLine }
} | Sort-Object { $_.pid })

# ---- services
$snap.services = @(Get-CimInstance Win32_Service | ForEach-Object {
    [ordered]@{ name = $_.Name; state = $_.State; start = $_.StartMode; path = $_.PathName; account = $_.StartName }
} | Sort-Object { $_.name })

# ---- scheduled tasks
$snap.tasks = @(Get-ScheduledTask | ForEach-Object {
    $t = $_
    $acts = @($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() })
    [ordered]@{ path = $t.TaskPath; name = $t.TaskName; state = "$($t.State)"; actions = $acts; hidden = $t.Settings.Hidden }
} | Sort-Object { $_.path + $_.name })

# ---- WMI permanent subscriptions (all classes, not only CommandLine)
$wmi = [ordered]@{}
foreach ($cls in '__EventFilter','__EventConsumer','__FilterToConsumerBinding') {
    $wmi[$cls] = @(Get-CimInstance -Namespace root\subscription -ClassName $cls | ForEach-Object {
        $o = [ordered]@{ class = $_.CimClass.CimClassName }
        foreach ($p in $_.CimInstanceProperties) {
            if ($p.Name -in 'Name','Query','QueryLanguage','CommandLineTemplate','ExecutablePath','ScriptText','ScriptFileName','ScriptingEngine','Filter','Consumer') { $o[$p.Name] = "$($p.Value)" }
        }
        $o
    })
}
$snap.wmi = $wmi

# ---- registry autoruns and related persistence points
$regKeys = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager',
 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System',
 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths','HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes','HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions',
 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths','HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
 'HKCU:\Software\M1nerSearch','HKLM:\SOFTWARE\M1nerSearch'
)
$reg = [ordered]@{}
foreach ($k in $regKeys) {
    if (Test-Path $k) {
        $item = Get-ItemProperty $k
        $vals = [ordered]@{}
        foreach ($p in $item.PSObject.Properties) { if ($p.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { $vals[$p.Name] = "$($p.Value)" } }
        $subs = @(Get-ChildItem $k | ForEach-Object { $_.PSChildName })
        $reg[$k] = [ordered]@{ values = $vals; subkeys = $subs }
    }
}
# IFEO debugger values + SilentProcessExit
$ifeo = @()
foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') {
    if (Test-Path $root) { Get-ChildItem $root | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        if ($p.Debugger -or $p.MonitorProcess -or $p.GlobalFlag) { $ifeo += "$($_.PSChildName): Debugger=$($p.Debugger) Monitor=$($p.MonitorProcess) GlobalFlag=$($p.GlobalFlag)" }
    } }
}
$reg['IFEO_SilentExit_nonEmpty'] = $ifeo
# task cache tree names (detect tasks hidden from the XML store)
$reg['TaskCacheTreeCount'] = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' -Recurse).Count
$snap.registry = $reg

# ---- startup folders
$startup = @()
foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
    if (Test-Path $d) { Get-ChildItem $d -Force -Recurse -File | ForEach-Object {
        $startup += [ordered]@{ path = $_.FullName; size = $_.Length; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
    } }
}
$snap.startup = $startup

# ---- hosts
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$snap.hosts = [ordered]@{ sha256 = (Get-FileHash $hostsPath -Algorithm SHA256).Hash; lines = @(Get-Content $hostsPath | Where-Object { $_ -and $_.Trim() -notmatch '^#' }) }

# ---- firewall rules (COM policy object: fast and complete)
$fw = @()
try {
    $pol = New-Object -ComObject HNetCfg.FwPolicy2
    foreach ($r in $pol.Rules) { $fw += "$($r.Name)|$($r.ApplicationName)|dir=$($r.Direction)|act=$($r.Action)|en=$($r.Enabled)" }
} catch {}
$snap.firewall = [ordered]@{ count = $fw.Count; rules = @($fw | Sort-Object) }

# ---- Defender configuration (may be unavailable when the service is off; recorded as such)
$def = [ordered]@{}
try { $mp = Get-MpPreference; $def.ExclusionPath = @($mp.ExclusionPath); $def.ExclusionProcess = @($mp.ExclusionProcess); $def.ExclusionExtension = @($mp.ExclusionExtension); $def.DisableRealtimeMonitoring = $mp.DisableRealtimeMonitoring } catch { $def.error = $_.Exception.Message }
try { $st = Get-MpComputerStatus; $def.AMServiceEnabled = $st.AMServiceEnabled; $def.RealTimeProtectionEnabled = $st.RealTimeProtectionEnabled } catch {}
$snap.defender = $def
# third-party AV registered in Security Center
$snap.securityCenter = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { "$($_.displayName) state=$($_.productState)" })

# ---- directory listings (top level for large roots, full recursion for extra dirs)
function Get-Listing($path, [int]$depth) {
    if (-not (Test-Path $path)) { return @() }
    Get-ChildItem $path -Force -Recurse -Depth $depth | ForEach-Object {
        $rel = $_.FullName
        "{0}|{1}|{2}" -f $rel, $(if ($_.PSIsContainer) { 'dir' } else { $_.Length }), $_.LastWriteTimeUtc.ToString('yyyyMMddHHmmss')
    }
}
$dirs = [ordered]@{}
$roots = @(
  @{ p = $env:TEMP;                                   d = 1 }
  @{ p = $env:APPDATA;                                d = 1 }
  @{ p = $env:LOCALAPPDATA;                           d = 0 }
  @{ p = "$env:ProgramData";                          d = 1 }
  @{ p = "$env:PUBLIC";                               d = 1 }
  @{ p = "$env:ProgramFiles";                         d = 0 }
  @{ p = "${env:ProgramFiles(x86)}";                  d = 0 }
  @{ p = "$env:SystemRoot\Tasks";                     d = 2 }
  @{ p = "$env:SystemRoot\System32\Tasks";            d = 3 }
)
foreach ($r in $roots) { $dirs[$r.p] = @(Get-Listing $r.p $r.d | Sort-Object) }
foreach ($x in $ExtraDirs) { $dirs[$x] = @(Get-Listing $x 8 | Sort-Object) }
$snap.dirs = $dirs

# ---- pending file operations (delete-on-reboot queue)
$snap.pendingRename = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations).PendingFileRenameOperations)

# Plain .NET values only (PowerShell wraps strings in PSObjects; ConvertTo-Json blew up on the graph in Windows PowerShell 5.1, JavaScriptSerializer reports cycles)
function Plain($o) {
    if ($null -eq $o) { return $null }
    if ($o -is [string]) { return [string]$o }
    if ($o -is [bool] -or $o -is [int] -or $o -is [long] -or $o -is [double] -or $o -is [uint32] -or $o -is [uint64]) { return $o }
    if ($o -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $o.Keys) { $h[[string]$k] = Plain $o[$k] }
        return $h
    }
    if ($o -is [System.Collections.IEnumerable]) { return ,@(foreach ($x in $o) { Plain $x }) }
    return [string]$o
}
Add-Type -AssemblyName System.Web.Extensions
$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$ser.MaxJsonLength = [int]::MaxValue; $ser.RecursionLimit = 64
try { [System.IO.File]::WriteAllText($Out, $ser.Serialize((Plain $snap)), (New-Object System.Text.UTF8Encoding($true))) }
catch { Write-Host ('SERIALIZE FAILED: ' + $_.Exception.Message) }
"snapshot written: $Out  ($([math]::Round((Get-Item $Out).Length/1KB)) KB)"

<#
  snapdiff.ps1 - compares two snap.ps1 JSON files and prints what was added / removed / changed.
  Process changes are shown separately because processes churn constantly; -IgnoreDirs limits noisy roots.
#>
param(
    [Parameter(Mandatory)][string]$Before,
    [Parameter(Mandatory)][string]$After,
    [string[]]$IgnoreDirPatterns = @('\\Temp\\claude\\','\\Temp\\MineHunterWork\\','\\Claude\\','\\.claude','\\Cache','\\GPUCache','\\Code Cache','\\Crashpad','\\node_modules\\','\\Local Storage','\\Session Storage','\\IndexedDB','\\Service Worker'),
    [switch]$ShowProcesses
)
$a = Get-Content $Before -Raw | ConvertFrom-Json
$b = Get-Content $After  -Raw | ConvertFrom-Json
$script:changes = 0

function Show-SetDiff($title, $x, $y) {
    $x = @($x); $y = @($y)
    $added = $y | Where-Object { $_ -notin $x }
    $removed = $x | Where-Object { $_ -notin $y }
    if ($added -or $removed) {
        "=== $title"
        foreach ($i in $added)   { "  + $i"; $script:changes++ }
        foreach ($i in $removed) { "  - $i"; $script:changes++ }
    }
}
function Flat($items, [scriptblock]$fmt) { @($items | ForEach-Object { & $fmt $_ }) }

Show-SetDiff 'services'  (Flat $a.services { "$($args[0].name) | $($args[0].start) | $($args[0].path) | $($args[0].account)" }) (Flat $b.services { "$($args[0].name) | $($args[0].start) | $($args[0].path) | $($args[0].account)" })
Show-SetDiff 'service STATE changes' (Flat $a.services { "$($args[0].name) = $($args[0].state)" }) (Flat $b.services { "$($args[0].name) = $($args[0].state)" })
Show-SetDiff 'scheduled tasks' (Flat $a.tasks { "$($args[0].path)$($args[0].name) [$($args[0].state)] hidden=$($args[0].hidden) :: $($args[0].actions -join ' ; ')" }) (Flat $b.tasks { "$($args[0].path)$($args[0].name) [$($args[0].state)] hidden=$($args[0].hidden) :: $($args[0].actions -join ' ; ')" })
foreach ($cls in '__EventFilter','__EventConsumer','__FilterToConsumerBinding') {
    Show-SetDiff "WMI $cls" (Flat $a.wmi.$cls { ($args[0].PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ' }) (Flat $b.wmi.$cls { ($args[0].PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ' })
}
# registry
$keys = @($a.registry.PSObject.Properties.Name + $b.registry.PSObject.Properties.Name | Sort-Object -Unique)
foreach ($k in $keys) {
    $ra = $a.registry.$k; $rb = $b.registry.$k
    if ($k -in 'IFEO_SilentExit_nonEmpty') { Show-SetDiff "registry $k" $ra $rb; continue }
    if ($k -eq 'TaskCacheTreeCount') { if ($ra -ne $rb) { "=== TaskCache tree entries: $ra -> $rb"; $script:changes++ }; continue }
    $va = if ($ra) { @($ra.values.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) } else { @('<key absent>') }
    $vb = if ($rb) { @($rb.values.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) } else { @('<key absent>') }
    Show-SetDiff "registry $k (values)" $va $vb
    Show-SetDiff "registry $k (subkeys)" @($ra.subkeys) @($rb.subkeys)
}
Show-SetDiff 'startup folder' (Flat $a.startup { "$($args[0].path) $($args[0].sha256)" }) (Flat $b.startup { "$($args[0].path) $($args[0].sha256)" })
if ($a.hosts.sha256 -ne $b.hosts.sha256) { "=== hosts file CHANGED"; Show-SetDiff 'hosts lines' $a.hosts.lines $b.hosts.lines }
if ($a.firewall.count -ne $b.firewall.count -or (Compare-Object @($a.firewall.rules) @($b.firewall.rules))) { Show-SetDiff "firewall rules ($($a.firewall.count) -> $($b.firewall.count))" $a.firewall.rules $b.firewall.rules }
Show-SetDiff 'Defender config' (@($a.defender.PSObject.Properties | ForEach-Object { "$($_.Name)=$(@($_.Value) -join ',')" })) (@($b.defender.PSObject.Properties | ForEach-Object { "$($_.Name)=$(@($_.Value) -join ',')" }))
Show-SetDiff 'pending file rename ops' $a.pendingRename $b.pendingRename

# directories
foreach ($d in @($a.dirs.PSObject.Properties.Name + $b.dirs.PSObject.Properties.Name | Sort-Object -Unique)) {
    $la = @($a.dirs.$d); $lb = @($b.dirs.$d)
    $strip = { param($l) $l | Where-Object { $ln = $_; -not ($IgnoreDirPatterns | Where-Object { $ln -match $_ }) } }
    $la = & $strip $la; $lb = & $strip $lb
    $sa = $la | ForEach-Object { ($_ -split '\|')[0] + '|' + ($_ -split '\|')[1] }   # ignore mtime for change detection of set membership
    $sb = $lb | ForEach-Object { ($_ -split '\|')[0] + '|' + ($_ -split '\|')[1] }
    Show-SetDiff "dir $d" $sa $sb
}
if ($ShowProcesses) {
    Show-SetDiff 'processes (name|path|cmd)' (Flat $a.processes { "$($args[0].name) | $($args[0].path) | $($args[0].cmd)" }) (Flat $b.processes { "$($args[0].name) | $($args[0].path) | $($args[0].cmd)" })
}
"--- total differences: $script:changes"

<#
  build_release.ps1 - builds MineHunter and lays out the ready-to-run portable folder.

    powershell -ExecutionPolicy Bypass -File build_release.ps1              # build + lay the programs out next to this script
    powershell -ExecutionPolicy Bypass -File build_release.ps1 -Zip         # also produces dist\MineHunter-Portable-x64.zip (what you attach to a GitHub release)

  Needs the .NET SDK (dotnet build). The result runs on any Windows 10/11 x64 without installing anything (.NET Framework 4.7.2+ ships with Windows).

  Layout (the same in the repository folder after a build and inside the zip):
    MineHunter.exe              main program (window, tray, command line)
    MineHunter Quick Scan.exe   double click = quick scan
    MineHunter Full Scan.exe    double click = full scan of all drives
    MineHunter-cli.exe          console version for scripts
    components\                 shared engine and window libraries, the updater helper (internal files)
    rules\ config.json docs\    detection rules, settings, documentation
#>
param([switch]$Zip, [string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$sln  = Join-Path $root 'src\MineHunter.sln'
$bin  = Join-Path $root 'src\_bin'

Write-Host '== build'
if (Test-Path $bin) { Remove-Item $bin -Recurse -Force }
& dotnet build $sln -c $Configuration -v q --nologo | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

$programs = 'MineHunter.exe', 'MineHunter Quick Scan.exe', 'MineHunter Full Scan.exe', 'MineHunter-cli.exe'
$components = 'MineHunter.Core.dll', 'MineHunter.UI.dll', 'MineHunter.UpdateHelper.exe', 'MineHunter.UpdateHelper.exe.config'
foreach ($f in $programs) {
    Copy-Item (Join-Path $bin $f) (Join-Path $root $f) -Force
    Copy-Item (Join-Path $bin "$f.config") (Join-Path $root "$f.config") -Force -ErrorAction SilentlyContinue
}
$comp = Join-Path $root 'components'
New-Item -ItemType Directory -Force $comp | Out-Null
foreach ($f in $components) { Copy-Item (Join-Path $bin $f) (Join-Path $comp $f) -Force -ErrorAction SilentlyContinue }

$ver = (Get-Item (Join-Path $root 'MineHunter.exe')).VersionInfo.ProductVersion
$sumFiles = @($programs) + @($components | Where-Object { $_ -notlike '*.config' } | ForEach-Object { "components\$_" }) + 'rules\core.json'
$sums = foreach ($f in $sumFiles) { $h = (Get-FileHash (Join-Path $root $f) -Algorithm SHA256).Hash.ToLower(); "$h  " + $f.Replace('\', '/') }
[System.IO.File]::WriteAllText((Join-Path $root 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"), (New-Object System.Text.ASCIIEncoding))   # LF endings: `sha256sum -c` works too
Write-Host "== ready: version $ver"; $sums | Out-Host

if ($Zip) {
    $dist = Join-Path $root 'dist'; New-Item -ItemType Directory -Force $dist | Out-Null
    $zipPath = Join-Path $dist 'MineHunter-Portable-x64.zip'
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    $items = @($programs | ForEach-Object { $_; "$_.config" }) + 'components', 'config.json', 'rules', 'README.md', 'README.ru.md', 'CHANGELOG.md', 'LICENSE', 'SHA256SUMS.txt', 'docs'
    $items = $items | ForEach-Object { Join-Path $root $_ } | Where-Object { Test-Path $_ }
    # ZipArchive with '/' separators (Windows PowerShell's Compress-Archive writes backslashes, which non-Windows extractors mishandle)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zs = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
    $za = New-Object System.IO.Compression.ZipArchive($zs, [System.IO.Compression.ZipArchiveMode]::Create)
    foreach ($it in $items) {
        $files = if ((Get-Item $it).PSIsContainer) { Get-ChildItem $it -Recurse -File } else { Get-Item $it }
        foreach ($f in $files) {
            $rel = $f.FullName.Substring($root.Length).Replace([string][char]92, '/').TrimStart('/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($za, $f.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal)
        }
    }
    $za.Dispose(); $zs.Dispose()
    $zh = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
    [System.IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS-release.txt'), "$zh  MineHunter-Portable-x64.zip`n", (New-Object System.Text.ASCIIEncoding))
    Write-Host "== zip: $zipPath ($([math]::Round((Get-Item $zipPath).Length/1KB)) KB)  sha256 $zh"
}

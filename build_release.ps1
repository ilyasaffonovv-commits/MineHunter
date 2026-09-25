<#
  build_release.ps1 - builds MineHunter and lays out the ready-to-run release folder.

    powershell -ExecutionPolicy Bypass -File build_release.ps1              # build + copy MineHunter.exe / MineHunter-cli.exe next to this script
    powershell -ExecutionPolicy Bypass -File build_release.ps1 -Zip         # also produces dist\MineHunter-<version>.zip (what you attach to a GitHub release)

  Needs the .NET SDK (dotnet build). The result runs on any Windows 10/11 x64 without installing anything (.NET Framework 4.7.2+ ships with Windows).
  MineHunter-cli.exe is the same program with the PE subsystem flipped to "console": it waits for completion and writes to stdout (scripts, CI).
#>
param([switch]$Zip)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$proj = Join-Path $root 'src\MineHunter\MineHunter.csproj'
$bin  = Join-Path $root 'src\_bin'

Write-Host '== build'
& dotnet build $proj -c Release -o $bin -v q --nologo | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

$exe = Join-Path $bin 'MineHunter.exe'
Copy-Item $exe (Join-Path $root 'MineHunter.exe') -Force
Copy-Item (Join-Path $bin 'MineHunter.exe.config') (Join-Path $root 'MineHunter.exe.config') -Force -ErrorAction SilentlyContinue

# console flavour: flip IMAGE_SUBSYSTEM_WINDOWS_GUI (2) to IMAGE_SUBSYSTEM_WINDOWS_CUI (3)
$bytes = [System.IO.File]::ReadAllBytes($exe)
$pe = [BitConverter]::ToInt32($bytes, 0x3C)
$subsystemOffset = $pe + 4 + 20 + 68
if ($bytes[$subsystemOffset] -ne 2) { throw "unexpected subsystem $($bytes[$subsystemOffset])" }
$bytes[$subsystemOffset] = 3
[System.IO.File]::WriteAllBytes((Join-Path $root 'MineHunter-cli.exe'), $bytes)
Copy-Item (Join-Path $bin 'MineHunter.exe.config') (Join-Path $root 'MineHunter-cli.exe.config') -Force -ErrorAction SilentlyContinue

$ver = (Get-Item (Join-Path $root 'MineHunter.exe')).VersionInfo.ProductVersion
$sums = foreach ($f in 'MineHunter.exe', 'MineHunter-cli.exe', 'rules\core.json') { $h = (Get-FileHash (Join-Path $root $f) -Algorithm SHA256).Hash.ToLower(); "$h  $f" }
[System.IO.File]::WriteAllText((Join-Path $root 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"), (New-Object System.Text.ASCIIEncoding))   # LF endings: `sha256sum -c` works too
Write-Host "== ready: version $ver"; $sums | Out-Host

if ($Zip) {
    $dist = Join-Path $root 'dist'; New-Item -ItemType Directory -Force $dist | Out-Null
    $zipPath = Join-Path $dist ("MineHunter-v$ver.zip")
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    $items = 'MineHunter.exe', 'MineHunter.exe.config', 'MineHunter-cli.exe', 'MineHunter-cli.exe.config', 'config.json', 'rules', 'README.md', 'README.ru.md', 'LICENSE', 'SHA256SUMS.txt', 'docs' | ForEach-Object { Join-Path $root $_ } | Where-Object { Test-Path $_ }
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
    Write-Host "== zip: $zipPath ($([math]::Round((Get-Item $zipPath).Length/1KB)) KB)"
}

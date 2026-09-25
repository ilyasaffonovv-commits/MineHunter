# MineHunter

[Русский](README.ru.md) | English

MineHunter is a scanner for hidden cryptominers and the persistence mechanisms they leave behind, for Windows 10/11 x64. It looks at running processes, autostart locations, scheduled tasks, services, WMI subscriptions, browser extensions and files, shows the evidence behind every finding, and can move what it finds into a quarantine. It runs on demand and is not an antivirus.

[![build](https://github.com/ilyasaffonovv-commits/MineHunter/actions/workflows/build.yml/badge.svg)](https://github.com/ilyasaffonovv-commits/MineHunter/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/ilyasaffonovv-commits/MineHunter)](https://github.com/ilyasaffonovv-commits/MineHunter/releases/latest)
[![license](https://img.shields.io/github/license/ilyasaffonovv-commits/MineHunter)](LICENSE)

![Results](docs/img/en/1_results_en.png)

## Download

Take `MineHunter-v1.0.0.zip` from the [latest release](https://github.com/ilyasaffonovv-commits/MineHunter/releases/latest), unzip it into a folder and run `MineHunter.exe`. The SHA-256 of the archive is in the release notes.

Requirements: Windows 10 or 11 x64 and .NET Framework 4.7.2 or newer, which is already part of current Windows builds. There is no installer. The program asks for administrator rights; without them services, scheduled tasks, WMI and other users' processes cannot be read.

## Running

On start MineHunter downloads `version.json` from this repository (skipped when offline), installs a newer rule pack if one is published, and starts a quick scan. Both can be turned off on the About tab.

- Quick: processes, autostart, tasks, services, WMI, protection settings, browsers, and the usual drop locations (Temp, AppData, Downloads, Desktop, ProgramData, drive roots).
- Full: all fixed drives, stops after 45 minutes. Results for unchanged files are cached, so repeat scans are faster.
- Custom: one folder or drive.

Measured on the author's PC (24 logical cores, about 82,000 files on the fixed drives): quick scan 50 to 60 s with a warm cache and about 110 s with a cold one; full scan 5 to 8.5 minutes the first time and 2 min 45 s to 4 min 10 s with a warm cache. A slower disk or CPU will take longer. See [docs/TEST_REPORT.md](docs/TEST_REPORT.md).

Findings are graded Suspicious, High Risk or Malware. Items with a low score are listed separately as notes and are not threats. Each finding shows what it is, where it is, every piece of evidence with its score, the chain (autostart entry, file, process, connection) and the suggested steps.

![Threat graph](docs/img/en/4_graph_en.png)

## What is checked

| Area | Details |
|---|---|
| Processes | Miner command lines (pool URL, wallet, algorithm). System-named processes running outside the Windows folder. Unexpected parent processes. Signed programs that load an unsigned DLL from their own user-writable folder. CPU load, and GPU load when the "GPU Engine" performance counters are available. |
| Process memory | Image header in memory compared with the file on disk (hollowing). PE images in private executable memory. Threads that start outside every loaded module. System utilities left suspended. |
| Network | TCP connections per process, mining ports, pool domains taken from the DNS cache, long-lived external connections of unsigned programs, external connections of programs that normally have none (`dwm.exe`, `InstallUtil.exe` and similar). |
| Autostart | Run and RunOnce keys, startup folders, services and drivers (including known vulnerable drivers), scheduled tasks (hidden ones, tasks with a removed security descriptor, tasks placed under `\Microsoft\`), WMI event subscriptions, Winlogon, IFEO and SilentProcessExit, AppInit_DLLs, AppCertDLLs, LSA packages, HKCU COM registrations, profiler environment variables, BootExecute. |
| Windows protection | Defender exclusions, disabled real-time protection, UAC, SmartScreen and firewall state, hosts-file entries that block update and security sites, policies that block Task Manager, regedit or listed security tools, firewall rules that allow user-folder programs. |
| Browsers | Chrome, Edge, Brave, Opera, Opera GX, Yandex, Vivaldi, Avast Secure Browser, Chromium and Firefox: extension code, risky permissions, forced installs by policy, changed search engine and start page, browser shortcuts with risky flags. VS Code, Cursor and Windsurf extensions are checked for miner code and for scripts that disable protection. |
| Files | PE analysis (signature, entropy, imports, overlay, padded files), miner strings, system file names in the wrong folder, look-alike folders such as `system92`, executables in the Recycle Bin and in `AppData\Microsoft\Windows`. |

The rules are listed in [docs/RULES.md](docs/RULES.md). What the rules are based on is described in [docs/THREAT_RESEARCH.md](docs/THREAT_RESEARCH.md).

A single weak signal never raises an object to High Risk. Being unsigned, running from AppData or using CPU is common in ordinary software, so these signals carry small weights and caps. High Risk needs a definitive item (for example a complete miner command line) or evidence from at least two independent categories. Signed files from known publishers and Windows components have their own weak signals reduced. [docs/RISK_MODEL.md](docs/RISK_MODEL.md) has the exact rules.

## What can be fixed

Neutralize runs the selected steps of a finding: freeze the processes, remove autostart entries, kill the processes, move the files to quarantine. It then scans again and reports a finding as fixed only if the second scan no longer sees it. By default only the steps for High Risk and Malware findings are selected. Critical Windows processes and trusted system files are never touched.

- Files, scheduled tasks, services, registry values, WMI subscriptions, Defender exclusions, hosts entries and browser extensions are saved before removal and can be restored from the Quarantine tab. Quarantined files are stored XOR-masked and checked against their SHA-256 on restore.
- Firewall rules are removed and only recorded, they are not restored automatically. A killed process cannot be brought back.
- A file that is locked is renamed and deleted on the next reboot.
- "Mark as safe" adds a file (path and SHA-256) to an allow list. Wrong verdicts can be reported with the false positive issue template.

## Limitations

- The checks are heuristic and run on demand. There is no kernel driver and no real-time protection. Kernel rootkits and samples that leave no trace on disk, in memory or in autostart can be missed. Whatever could not be examined (protected processes, folders without access, a scan stopped by its time limit) is listed in the report.
- It has not been run against real malware samples. Testing used the benign simulator in `tests/MinerLab` and one real machine. Windows 10 and low-end hardware were not tested.
- The executables are not code-signed. Some antivirus products distrust unsigned programs. The EXE contains no miner strings in plain text (the rule pack is embedded compressed, and the self test checks the EXE for markers), but a scanner may still flag it. Please report that, and any normal program that MineHunter flags, with the false positive template.
- The detailed documentation in `docs/` is in Russian.

## Command line

`MineHunter-cli.exe` is the same program built for the console subsystem: it waits for completion and writes to stdout.

```
MineHunter-cli.exe scan [--quick | --full | --path <dir>] [--fix [--yes] [--min suspicious|high|malware] [--only <text>] [--all-steps]]
                        [--report-dir <dir>] [--json <file>] [--dump <file>]
                        [--no-browsers] [--no-memory] [--no-files] [--no-cache] [--sample-ms <n>] [--quiet]
MineHunter-cli.exe quarantine list | restore <id> [--to <path>] | delete <id> | delete-all
MineHunter-cli.exe allow <path>
MineHunter-cli.exe update-check | update-rules
MineHunter-cli.exe markers <file>
MineHunter-cli.exe rules-info | selftest | --version
```

`--fix` asks for confirmation unless `--yes` is given. `--only` limits it to findings whose files, paths or names contain the text. `--dump` writes every scanned object with its evidence. `markers` lists the miner markers found inside a file.

Exit codes: 0 clean, 1 suspicious, 2 high risk or malware, 3 error, 4 confirmation needed.

Reports are written to `%ProgramData%\MineHunter\Reports` as `report.json` and `report.txt`.

## Updates and privacy

The only network request is an HTTPS GET of [`version.json`](version.json) and, when it is newer, [`rules/core.json`](rules/core.json). Nothing about the computer is sent. A rule pack is installed only if its SHA-256 matches the manifest and its RSA signature verifies against the public key built into the program. A new program version is shown as a link to the release page and is not installed automatically. Details are in [docs/UPDATES.md](docs/UPDATES.md).

The data folder `%ProgramData%\MineHunter` (quarantine, allow list, downloaded rules, reports) is writable only by SYSTEM and administrators.

## Build

```
powershell -ExecutionPolicy Bypass -File build_release.ps1 -Zip
```

This needs the .NET SDK. It writes `MineHunter.exe` and `MineHunter-cli.exe` next to the script and, with `-Zip`, `dist\MineHunter-v<version>.zip`. The sources are C# for .NET Framework 4.7.2 with WPF and no third-party packages.

Layout: `src/` program, `rules/` rule pack (JSON), `tests/` MinerLab and test helpers, `docs/`, `tools/` maintainer scripts.

## Tests

`MineHunter-cli.exe selftest` runs the built-in checks (60 in the 1.0.0 build, the count is printed at the end): path handling, rules and their sample lines, signature checks, scoring on known harmless combinations, quarantine round trips, the update flow against a local server, and the marker check of the EXE itself. It does not use the network and changes nothing outside a temporary folder.

MinerLab (`tests/MinerLab`) creates harmless look-alikes of miner infections: system-named files in wrong folders, Run keys, hidden tasks, services, WMI subscriptions, watchdog chains and loopback sockets. Every object points at the lab's own harmless executable, and a cleanup script removes everything again. Results are in [docs/TEST_REPORT.md](docs/TEST_REPORT.md). A comparison with MinerSearch is in [docs/COMPARISON.md](docs/COMPARISON.md).

## Contributing, security, license

Rule proposals and reports of false positives or missed detections are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities as described in [SECURITY.md](SECURITY.md). MIT license.

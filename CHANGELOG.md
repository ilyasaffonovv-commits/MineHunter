# Changelog

## 1.1.0 (2026-10-03)

A finished Windows program built around the same detection engine: three programs, a new window, real-time monitoring, scheduled scans, a signed self-update, drivers and Windows-health pages. Detection was also hardened (see "Detection and safety").

### Programs

- `MineHunter Quick Scan.exe`: double click, allow the Windows prompt, the quick scan starts at once, with a live status (what is being checked, elapsed time, objects checked, suspicious items so far) and ends with "No threats found" or the findings with their explanations and a Neutralize button.
- `MineHunter Full Scan.exe`: the same for a full scan of all fixed drives (USB and network drives optional), with a stop button that is safe at any moment.
- `MineHunter.exe`: the main program with a new dark window and 13 pages: Home, Scan, Protection, Check a file, Processes, Startup, Network, Quarantine, Drivers, Windows health, Schedule, History, Settings.
- `MineHunter-cli.exe` is now a real console program (it used to be the same EXE with a flipped header flag) and has new commands: `quick`, `full`, `check <file>`, `scan <file>`, `hash`, `reputation`, `status`, `health`, `processes`, `connections`, `startup`, `drivers`, `history`.
- One engine: all four programs use `MineHunter.Core.dll`, and the same scan settings give the same result in each (the self test checks this). The libraries and the updater helper live in `components\`.
- Release file: `MineHunter-Portable-x64.zip`.

### New features

- **Check a file** (drag and drop, a button, or the Explorer right-click menu): verdict in plain words, reasons with weights, signature and certificate chain, hashes, Mark of the Web, PE sections with entropy, imports, exports, manifest, packer hints, URLs, domains, IPs, PowerShell fragments, miner markers, reputation sources. A file is only read.
- **Real-time layer** (works while the window or the tray icon runs; it watches and reports, it does not claim to block before launch): File Guard, Download Guard, Process Guard (parent chains, command lines), Script Guard (with AMSI as a client), Persistence Guard (with a journal of system changes), Network Guard (with Windows Firewall rules created on your click), USB Guard, Ransomware Guard (opt-in, decoy files). Warnings need several independent signs and say what concretely happened.
- **Schedule** through the Windows Task Scheduler: daily, every 3 days, weekly, monthly, every N days; quick, full or chosen folders; run a missed scan at the next start; only when idle; not on battery; notify only if something is found.
- **Self-update**: signed announcement (RSA), SHA-256 and size checked before unpacking, safe unpacking, a separate helper that installs after the program closes, keeps a backup and rolls back on any failure.
- **Drivers**: inventory, official vendor pages, Windows Update search (read-only), install with Hardware ID check, restore point, saved copy of the old driver and roll-back. BIOS and firmware are never automated; storage and chipset drivers need an explicit confirmation.
- **Windows health**: 17 concrete checks (Defender and its exclusions, firewall per profile, SmartScreen, UAC, updates, Secure Boot, TPM, memory integrity, hosts, proxy, WinHTTP, DNS, PowerShell policy, RDP, remote-access programs, shares). A fix button only where a safe fix exists.
- **Startup manager**: one list of everything that starts by itself, with a safe on/off switch (nothing is deleted).
- **Settings**: presets Normal / Strict / Developer, sensitivity Normal / Strict / Paranoid, CPU limit, threads, archives, file size limit, USB and network drives, exclusions (folders, publishers, SHA-256), notifications level, game mode, VirusTotal hash lookup (off by default, your own key, only the hash is sent).
- History of scans with HTML, TXT and JSON reports; the HTML report is one self-contained page.
- False-positive report: a text file with names removed, never sent by the program.

### Detection and safety

- Rule pack 2026.10.04.1: six more command-line rules (shadow-copy deletion and recovery switched off, event-log clearing, firewall switched off, SmartScreen switched off, Remote Desktop switched on, an account added to Administrators).
- Hardening from the audit: more autostart points (Session Manager, RDP, screensaver, print processors, AppCompat shims, KnownDLLs, IFEO verification), per-user file-type and COM overrides, other users' registry (also users who are not signed in), DLL side-loading pairs, NTFS alternate streams, 8.3 names, damaged task definitions, NSSM-wrapped services, atomic and durable quarantine records, a restore that refuses junction folders, a cleaning lock for the whole PC, a journal that unfreezes programs after an interrupted cleaning, game cheats graded Suspicious and kept by default.
- Autostart tricks that ordinary software hardly ever uses now reach "Suspicious" on their own when they start an unsigned program from a user folder: a WMI subscription kept outside `root\subscription`, the `Load`/`Run` value of the Windows key, a service (or its NSSM-style wrapped program, or its recovery command) in a folder every user can write to, a hidden file in a Startup folder, a task that starts only when the PC is idle. A single Run value, per-user COM server or Active Setup entry stays a weak signal on purpose: ordinary programs do that all the time.
- A miner configuration (pool, wallet, algorithm) next to an unsigned program marks that program (`MINER.PROGRAM_NEXT_TO_CONFIG`), so the program, the entry that starts it and the configuration are one finding and are cleaned together; a folder with more than four programs is not guessed at.
- `scan --fix --only <text>` also matches the data of registry values (the command line behind a per-user handler, an AutoRun, a COM class) and the repeat rounds after the first cleaning obey it: they used to look at the whole PC, so a finding that did not match `--only` could still be cleaned in round two (found when a test run on the author's PC moved file-type entries and program files of installed programs to quarantine; everything was restored from quarantine, and a self test now covers the rule).
- Cleaning a per-user override of a file type or protocol (the `ms-settings` UAC bypass and its relatives) now removes the whole override key and the empty keys it leaves, and the quarantine record brings all of it back. Before, only the command was removed: a `DelegateExecute` value stayed behind and `ms-settings:` links (Settings) could stop opening.
- Neutralizing a finding that contains a running program now also quarantines the program file behind it (when it is not trusted and not a Windows file). Before, stopping the process left the file for the next logon or for its watchdog.
- Gen Digital (Avast, AVG, Norton) and Avira are trusted publishers: their boot-time tool `icarus_rvrt.exe` showed up in `BootExecute` for a few minutes on the author's PC and was called Suspicious.
- After cleaning, a finding whose only action was removing a hidden NTFS stream is verified by the stream, not by the host file (which stays by design); it used to be reported as "partial".
- The "Show the minor notes" button on a clean result no longer stretches into a big empty box.
- Starting any program without its `components` folder (for example from the preview of a zip file) now shows one clear sentence in Russian and English instead of a .NET crash window.
- False positives found on a real PC were fixed (words of a miner in the memory of an idle chat program; ordinary per-user file types).
- A fix in the update helper found by its own tests: after a failed update it tried to restore a file that had never been replaced and reported that the previous version could not be restored.

### Tests

- Self test: 356 checks (182 existing + 174 for the product layer and this round). Update helper tests, a live test of the guards in the real program with harmless lab files, and the earlier lab, adversarial, robustness and operations suites. See [docs/TEST_REPORT.md](docs/TEST_REPORT.md).

### Not done / limits

- No kernel driver. Real-time protection is user-mode monitoring, not a blocker. A real ransomware sample, a real AMSI detection, a real USB stick and a real driver install were not tested.
- No installer yet (planned: Explorer menu, tray at sign-in and shortcuts in one setup). The portable zip is fully working.
- No MineHunter Cloud: there is no server. VirusTotal by hash is optional.
- The executables are not code-signed.

## 1.0.1 (2026-10-01)

- Reports now go to a `Reports` folder next to `MineHunter.exe` instead of `%ProgramData%\MineHunter\Reports`, so they are easy to find without digging through Windows folders. Quarantine, the allow list and downloaded rules stay in the protected `%ProgramData%\MineHunter` - that protection is what stops a miner running as an ordinary user from un-quarantining itself or planting a fake rule update. Falls back to the old location if the folder next to the EXE is not writable.

- Scheduled tasks: `ComHandler` actions (a task that runs a registered COM class instead of a command line - fileless persistence with no `Exec` entry to look for) are now parsed. The class id is resolved the way COM itself resolves it, HKCU first then HKLM; a class registered only per-user is flagged (`TASK.COMHANDLER_HKCU`) and, when the registry scanner also found that HKCU registration, the two are merged into one finding.
- Rule pack 2026.10.01.1: 5 new command-line rules (`CMD.PS.AMSI_BYPASS`, `CMD.UAC.DISABLE`, `CMD.DEFENDER.TASK_DISABLE`, `CMD.MINER.LHR_UNLOCK`, `CMD.RUNDLL32.USERPATH`) and 5 more known vulnerable driver names used in BYOVD attacks (TrueSight, Zemana zam64/zamguard, Dell dbutil_2_3).
- MinerLab: new scenario S16 (hidden COM-handler task + per-user COM hijack) with matching cleanup.

## 1.0.0 (2026-09-25)

First public release.

- Scanners for processes and process memory, network connections, autostart locations (registry, startup folders, services, scheduled tasks, WMI), Windows protection settings, browser and VS Code extensions, and files.
- Risk score from weighted evidence in categories. High Risk and Malware need a definitive item or evidence from several independent categories.
- Neutralization with quarantine, followed by a rescan. Locked files are deleted on the next reboot.
- WPF window (English and Russian) with a threat graph, reports as `report.json` and `report.txt`, and `MineHunter-cli.exe` for the console.
- Version check and rule-pack updates, installed only if the SHA-256 and the RSA signature match.
- Self test (60 checks) and the MinerLab simulator.
- Rule packs: for the same rule id the newer pack wins; `disabledRules`, `knownGoodHashes`, per-rule `textRu` and `samples` (checked by the self test).
- Rule pack 2026.09.26.1 adds 22 command-line rules (Defender registry, cloud and service tampering, killing of security agents and competing miners, service/task/Run persistence in user folders, WMI subscriptions, reflective PowerShell, certutil/msiexec/mshta, hidden PowerShell downloads), 7 path indicators for drop locations and 28 miner program names.

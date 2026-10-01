# Changelog

## Unreleased

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

# Changelog

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

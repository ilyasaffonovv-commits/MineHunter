# Changelog

## 1.0.0 (2026-09-25)
First release.
- Scanner -> Evidence -> Analyzer -> Risk -> Decision -> Remediation -> Verification pipeline; transparent, corroborated risk scoring.
- Processes and memory (hollowing, PE in private memory, orphan threads), network-to-process mapping, autostart (Run, startup folders, services/drivers, scheduled tasks incl. hidden, WMI, Winlogon, IFEO, AppInit, LSA, COM), Windows protection tampering, browser extensions and settings, files (static PE analysis, miner strings, masquerade).
- Quarantine-first reversible remediation with rescan verification; delete-on-reboot for locked files.
- Modern WPF window (RU/EN), threat graph, reports (report.json / report.txt), update check + verified rule-pack updates (SHA-256, optional RSA signature).
- 60 built-in self checks; MinerLab benign infection simulator.
- Rule packs: newest version wins per rule id, `disabledRules` (instant noisy-rule kill), `knownGoodHashes`, per-rule `textRu` and `samples` enforced by the self-test.
- Rule pack 2026.09.26.1: +21 command-line rules (Defender registry/cloud/service tampering, security-agent killers, miner competitor killers, service/task/Run persistence into user folders, WMI subscriptions, reflective PowerShell, certutil/msiexec/mshta LOLBins, hidden-download PowerShell), +7 staging-folder path IOCs, +28 miner program names.

# Contributing to MineHunter

The most valuable contributions are **false-positive reports**, **missed-detection reports** and **new rules**. MineHunter's promise is "does not flag normal programs", so an incorrect verdict is a bug.

## Reporting a false positive
Use the *False positive* issue template. Attach the finding text from the *Results* tab (or `report.txt`), the file's SHA-256 and what the program is. Never upload private files; hashes and evidence are enough.

## Reporting a missed detection
Use the *Missed detection* template. Please do **not** attach live malware. Describe the technique (where it persists, how it hides, what its command line looks like) or share a public report/link. `MineHunter-cli.exe scan --full --dump entities.json` produces a research dump of everything the scan saw.

## Adding or changing rules
Rules live in [`rules/core.json`](rules/core.json) (plain JSON: miner strings, command-line patterns with weights and categories, trusted publishers, heavy-app names, IOC paths…). The engine and evidence weights live in `src/MineHunter/Scanning` and `src/MineHunter/Risk`; the catalogue is generated into [`docs/RULES.md`](docs/RULES.md) (`python tests/tools/gen_rules_doc.py`). Guidelines:

1. **A rule needs a source** (public report, sample analysis) in the PR description. Do not paste malware hashes without a verifiable source; a wrong hash is a false positive for someone.
2. A weak signal (CPU, unsigned, odd folder) must stay weak. New strong signals go into a category, have a cap, and must be corroborated by another category before they can reach *High Risk*.
3. Every new rule ships `samples` (`"samples": {"match": [...], "noMatch": [...]}`): command lines that **must** and **must not** trigger it, plus a `textRu` translation. The self-test enforces the samples. Add a self-test or a MinerLab scenario when you change detection logic, and run:
   ```
   powershell -ExecutionPolicy Bypass -File build_release.ps1
   MineHunter-cli.exe selftest
   ```
4. Do not put miner strings into C# code as literals — the EXE must contain **no** miner marker (a self-test checks this). Put them into the rule pack; write test strings through `Obf.J("xm", "rig")`.
5. Bump `version` in `rules/core.json`; the maintainer signs and publishes it (`tools/publish_rules.ps1`).

## Code
C# 10, .NET Framework 4.7.2, WPF, **no third-party packages**. Keep the pipeline separation *Scanner → Evidence → Analyzer → Risk → Decision → Remediation*: scanners only read, remediation only acts on a decision plan, every action must be reversible or explicitly marked as not.

## Translations
UI strings live in `src/MineHunter/Report/Loc*.cs` (RU/EN) and inline `L("en", "ru")` calls in the window code.

## What this changes
<!-- New rule, changed weight, bug fix, translation … -->

## Why (source / evidence)
<!-- Public report or analysis for a new detection; the false-positive report it fixes; a reproduction for a bug -->

## Checklist
- [ ] `MineHunter-cli.exe selftest` passes (all checks)
- [ ] weak signals (CPU, unsigned, odd folder) stay weak; anything strong is corroborated by another category
- [ ] no miner strings as literals in C# code (use the rule pack / `Obf.J`), no unverifiable malware hashes
- [ ] a self-test or MinerLab scenario covers the change (if it touches detection logic)
- [ ] `rules/core.json` `version` bumped (if rules changed) and `docs/RULES.md` regenerated

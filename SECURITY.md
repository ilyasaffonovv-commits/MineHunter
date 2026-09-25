# Security policy

## Reporting a vulnerability in MineHunter

Please do not open a public issue for a security problem. Use GitHub's private reporting: Security, then "Report a vulnerability" on this repository. Describe what an attacker gains and how to reproduce it. A proof of concept helps. Fixes are released as a new version and listed in the [changelog](CHANGELOG.md).

Of particular interest: making MineHunter delete or quarantine something it should not, making it trust an attacker's file, accepting an unsigned or forged rule pack, writing outside its data folder, or gaining privileges through its data folder or update mechanism.

## What to rely on

- Network: one HTTPS GET of the public `version.json` and of the rule pack it names. Nothing about the machine is sent. Plain `http` is accepted only for loopback addresses, which the tests use.
- A rule pack is installed only if its SHA-256 matches the manifest and its RSA-SHA256 signature verifies against the public key compiled into the program. The private key is not in this repository.
- `%ProgramData%\MineHunter` is writable only by SYSTEM and Administrators.
- Neutralization saves what it removes before removing it. Critical Windows processes and trusted system files are not touched.

## Not a vulnerability

A miner or persistence trick that MineHunter misses, and a false positive, are ordinary bugs. Please use the "Missed detection" or "False positive" issue templates. MineHunter is a heuristic scanner that runs on demand.

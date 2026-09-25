# Security policy

## Reporting a vulnerability in MineHunter itself

Please **do not** open a public issue for a security problem. Use GitHub's private reporting: **Security → Report a vulnerability** on this repository. Describe what an attacker gains and how to reproduce it; a proof of concept is welcome. You will get an answer as soon as possible; fixes are released as a new version and mentioned in the [changelog](CHANGELOG.md).

Especially interesting: ways to make MineHunter delete or quarantine something it should not, to trust an attacker's file, to accept an unsigned/forged rule pack, to write outside its data folder, or to escalate privileges through its data folder or update mechanism.

## Design points you can rely on (and attack)

* Network: a single HTTPS `GET` of the public `version.json` (and the rule pack it names). No data about the machine is sent. Plain `http` is accepted only for loopback addresses (tests).
* A rule pack is installed only if its SHA-256 matches the manifest **and** its RSA-SHA256 signature verifies against the public key compiled into the program. The private key is never stored in this repository.
* `%ProgramData%\MineHunter` is writable only by SYSTEM and Administrators.
* Neutralization is quarantine-first and reversible; critical Windows processes and trusted system files are never touched.

## Not a vulnerability

Detection gaps (a miner or persistence trick MineHunter misses) and false positives are normal bugs — use the *Missed detection* / *False positive* issue templates. MineHunter is a heuristic, on-demand scanner and says so.

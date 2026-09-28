# Security & Responsible Use

HashCracker is a **defensive and authorized-testing** tool for identifying and
recovering password hashes. It is intended only for:

- Systems and data you **own**, or
- Engagements where you have **explicit written authorization** (penetration
  tests, red-team exercises, audits),
- **CTF competitions**, and
- **Education and research** on data you are permitted to use.

Unauthorized access to computer systems and unauthorized cracking of
credentials is illegal in most jurisdictions. You are solely responsible for
ensuring you have permission before using this tool against any hash.

## Handling of hashes

- **Local by default.** Cracking runs entirely on your machine (hashcat / John
  the Ripper). No hash leaves the host unless you explicitly opt in.
- **Online lookup is opt-in.** The `--online` flag (or `online.enabled = true`
  in the config) sends the hash to third-party services
  (`hashtoolkit.com`, `nitrxgen.net`) *before* local cracking. Do **not** use
  it for sensitive or client/engagement hashes. `--offline` always forces
  local-only and overrides any config default.
- **Results log.** Cracked results are appended to `~/.hashcracker/results.log`
  in plaintext. Treat that file as sensitive and remove it when no longer
  needed.

## Reporting a vulnerability

If you find a security issue in HashCracker itself, please open an issue at
<https://github.com/sp1r4-r/hashcracker/issues> describing the problem and how
to reproduce it. For anything you consider sensitive, note that in the issue so
it can be triaged appropriately.

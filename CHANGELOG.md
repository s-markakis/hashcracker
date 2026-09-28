# Changelog

All notable changes to HashCracker will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Online lookup is now opt-in.** Hashes are no longer sent to third-party
  services (`hashtoolkit.com`, `nitrxgen.net`) by default. Use `--online` to
  enable it; `--offline` always forces local-only and overrides the config.
  The lookup now names the services it contacts before sending anything.
- Added `SECURITY.md` documenting authorized-use scope and hash handling.

### Fixed
- **Passwords containing `:` are no longer truncated.** hashcat now uses
  `--outfile-format 2` (plaintext only) and John output is parsed colon-safely.
- CI `lint` job now passes — cleared all flake8 findings (unused imports,
  f-string placeholders, whitespace/indent) and centralized config in `.flake8`.
- Machine-readable output (`--output-format json|csv`) no longer prints the
  ASCII banner to stdout, so it can be piped and parsed directly.
- Banner box no longer overflows for longer version strings (dynamic padding).
- Base64 decode note only appends `...` when the hex is actually truncated.

### Changed
- Online lookup default (`online.enabled`) flipped to `false`.
- `hashcat -I` device detection is cached per run instead of re-probed on every
  crack attempt (notable speedup in combo mode).
- John jumbo detection prefers `--list=build-info` over banner scraping.
- Hash signature regexes are pre-compiled once at import.
- Swallowed exceptions now log at debug level instead of passing silently.
- Added `test`/`dev` extras (`pip install -e '.[test]'`) and expanded test
  coverage (crack-output parsing, online guard, config, base64).

## [2.0.0] - 2026-03-31

### Added
- **Modular architecture** — refactored into a clean Python package structure
- **60+ hash type signatures** — SHA3, Blake2, NTLMv2, NetNTLM, DCC2, Cisco IOS/ASA, Oracle, PostgreSQL, phpass (WordPress), MSSQL, WPA/WPA2, SSHA (LDAP), Joomla, vBulletin, and more
- **Confidence scoring** — each identified hash type is ranked by real-world probability (Most Likely / Likely / Possible / Unlikely)
- **Attack modes** — dictionary (`-a dictionary`), rule-based (`-a rule`), mask/brute-force (`-a mask`), and combo (`-a combo`) which chains all strategies automatically
- **JSON and CSV output** — machine-readable results via `--output-format json|csv` with file export (`-o`)
- **Online hash lookup** — checks free online databases before spending CPU/GPU time (disable with `--offline`)
- **GPU/CPU auto-detection** — detects available hashcat devices and selects optimal mode; falls back to CPU when no GPU is found
- **Real-time progress display** — streams hashcat status during cracking (suppress with `-q`)
- **Session and resume support** — save cracking sessions (`--session name`) and resume them later (`--resume name`)
- **Combo wordlist strategy** — automatically tries wordlists from smallest to largest, then rules, then mask attacks
- **Clipboard input** — read hash directly from system clipboard (`--clipboard`)
- **Base64 auto-detection** — detects and decodes base64-encoded hashes before identification
- **Persistent results log** — all cracked hashes logged to `~/.hashcracker/results.log`
- **Configuration file** — user preferences saved in `~/.hashcracker/config.ini`
- **Color auto-detection** — respects `NO_COLOR`, detects non-TTY pipes, handles Windows Terminal vs legacy CMD
- **Auto-setup prompt** — offers to install missing tools/wordlists when `--crack` is used

### Changed
- Complete rewrite from single-file to modular package
- Hash signatures now use dict format with confidence scores instead of tuples
- Cracking functions return structured result dicts instead of printing directly
- Wordlist discovery returns all found wordlists sorted by size
- John the Ripper detection distinguishes jumbo vs basic versions

## [1.0.0] - 2026-03-31

### Added
- Initial release
- Hash identification for 25+ types
- Cracking via hashcat and John the Ripper
- Cross-platform setup (Linux, macOS, Windows)
- Interactive mode
- Batch file processing
- Wordlist auto-download (rockyou, SecLists)

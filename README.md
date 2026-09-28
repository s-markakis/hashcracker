<p align="center">
  <pre>
    ╔═══════════════════════════════════════════════╗
    ║          HASH CRACKER v2.0                    ║
    ║     Hash Identification & Cracking Tool       ║
    ║   Powered by Hashcat & John the Ripper        ║
    ╚═══════════════════════════════════════════════╝
  </pre>
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python 3.8+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://github.com/sp1r4-r/hashcracker/releases"><img src="https://img.shields.io/badge/version-2.0.0-orange.svg" alt="Version 2.0.0"></a>
  <a href="https://hashcat.net/hashcat/"><img src="https://img.shields.io/badge/hashcat-supported-red.svg" alt="Hashcat"></a>
  <a href="https://www.openwall.com/john/"><img src="https://img.shields.io/badge/john-supported-red.svg" alt="John the Ripper"></a>
</p>

<p align="center">
  <b>Professional hash identification and cracking toolkit for penetration testers and security researchers.</b><br>
  Identifies 60+ hash types with confidence scoring, then cracks them using multiple attack strategies.
</p>

---

## Features

| Feature | Description |
|---------|-------------|
| **60+ Hash Types** | MD5, SHA-1/256/512, SHA3, bcrypt, scrypt, Argon2, NTLM, Kerberos, WordPress, Cisco, Oracle, MSSQL, PostgreSQL, and more |
| **Confidence Scoring** | Ranks identified hash types by probability — no more guessing which MD5 variant it is |
| **4 Attack Modes** | Dictionary, Rule-based, Mask (brute-force), and Combo (auto-chains all strategies) |
| **Online Lookup** | *Opt-in* (`--online`): checks third-party hash databases before spending compute time. Off by default so hashes never leave your machine unless you ask |
| **GPU Auto-Detection** | Automatically detects and uses GPU acceleration when available |
| **Cross-Platform** | Works on Linux (Debian/RHEL/Arch/SUSE), macOS, and Windows |
| **Auto-Installer** | One command to install hashcat, John the Ripper, and wordlists |
| **Multiple Output Formats** | Text (colored), JSON, and CSV for pipeline integration |
| **Session Resume** | Save and resume long-running cracking sessions |
| **Clipboard Input** | Read hashes directly from system clipboard |
| **Base64 Detection** | Automatically detects and decodes base64-encoded hashes |
| **Config File** | Persistent user preferences in `~/.hashcracker/config.ini` |
| **Results Logging** | All cracked hashes are logged to `~/.hashcracker/results.log` |
| **Zero Dependencies** | Pure Python standard library — no `pip install` needed |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/sp1r4-r/hashcracker.git
cd hashcracker

# Install tools and wordlists (hashcat, john, rockyou.txt, etc.)
python3 hash_cracker.py --setup

# Identify a hash
python3 hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99

# Identify and crack
python3 hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 --crack
```

> **Entry points:** the examples use the `hash_cracker.py` convenience shim.
> After `pip install -e .` you can also use the `hashcracker` console script or
> `python -m hashcracker` (recommended, no path juggling). All three are
> equivalent.

---

## Installation

### Option 1: Clone (recommended)
```bash
git clone https://github.com/sp1r4-r/hashcracker.git
cd hashcracker
python3 hash_cracker.py --setup
```

### Option 2: pip install
```bash
pip install .
hashcracker --setup
```

### Option 3: Run as module
```bash
python3 -m hashcracker --setup
```

### Prerequisites

- **Python 3.8+** (uses only standard library)
- **hashcat** and/or **John the Ripper** — installed automatically via `--setup`

---

## Usage

### Hash Identification

```bash
# Identify a single hash
python3 hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99
```

Output:
```
Hash:   5f4dcc3b5aa765d61d8327deb882cf99
Length: 32 characters

[+] Possible hash types:

  #    Type                           Hashcat    John Format          Confidence
  ──── ────────────────────────────── ────────── ──────────────────── ───────────────
  1    MD5                            0          Raw-MD5              Most Likely
  2    NTLM                           1000       NT                   Likely
  3    MD4                            900        Raw-MD4              Unlikely
  4    LM Hash                        3000       LM                   Unlikely
```

### Cracking

```bash
# Dictionary attack (default)
python3 hash_cracker.py -H <hash> --crack

# Rule-based attack (wordlist + character mangling)
python3 hash_cracker.py -H <hash> --crack -a rule

# Mask / brute-force attack
python3 hash_cracker.py -H <hash> --crack -a mask --mask '?d?d?d?d?d?d'

# Combo attack (auto-chains: all wordlists → rules → mask)
python3 hash_cracker.py -H <hash> --crack -a combo

# Use a specific tool
python3 hash_cracker.py -H <hash> --crack --tool hashcat
python3 hash_cracker.py -H <hash> --crack --tool john

# Use a custom wordlist
python3 hash_cracker.py -H <hash> --crack -w /path/to/wordlist.txt
```

### Batch Processing

```bash
# Crack multiple hashes from a file
python3 hash_cracker.py -f hashes.txt --crack

# Export results as JSON
python3 hash_cracker.py -f hashes.txt --crack --output-format json -o results.json

# Export results as CSV
python3 hash_cracker.py -f hashes.txt --crack --output-format csv -o results.csv
```

### Interactive Mode

```bash
python3 hash_cracker.py -i
```

In interactive mode, you can paste hashes one at a time and the tool will identify and optionally crack each one. Type `devices` to see GPU info, `sessions` to list saved sessions, or `quit` to exit.

### Other Features

```bash
# Read hash from clipboard
python3 hash_cracker.py --clipboard --crack

# Online lookup is OFF by default. Opt in explicitly (sends the hash to
# third-party sites: hashtoolkit.com, nitrxgen.net):
python3 hash_cracker.py -H <hash> --crack --online

# Force offline (overrides --online and any config setting):
python3 hash_cracker.py -H <hash> --crack --offline

# Save and resume sessions
python3 hash_cracker.py -H <hash> --crack --session my_session
python3 hash_cracker.py --resume my_session

# Show GPU/CPU device info
python3 hash_cracker.py --devices

# Quiet mode (suppress progress)
python3 hash_cracker.py -H <hash> --crack -q
```

---

## Supported Hash Types

<details>
<summary><b>Click to expand full list (60+ types)</b></summary>

| Category | Hash Types |
|----------|-----------|
| **MD family** | MD4, MD5, MD5 Crypt (Unix), Apache APR1 MD5 |
| **SHA-1** | SHA-1, LDAP SHA1, SSHA, RIPEMD-160 |
| **SHA-2** | SHA-224, SHA-256, SHA-384, SHA-512, SHA-256/512 Crypt (Unix) |
| **SHA-3** | SHA3-224, SHA3-256, SHA3-384, SHA3-512 |
| **Blake** | Blake2b-256, Blake2b-512 |
| **Bcrypt / scrypt / Argon2** | bcrypt, scrypt, Argon2id |
| **Windows** | NTLM, LM Hash, NTLMv1, NTLMv2 (NetNTLM), MS Cache v1/v2 (DCC/DCC2) |
| **Kerberos** | TGS-REP, AS-REP, Pre-Auth (RC4) |
| **MySQL** | MySQL 3.x/4.x, MySQL 5.x+ |
| **PostgreSQL** | PostgreSQL MD5, SCRAM-SHA-256 |
| **Oracle** | Oracle 7-10g (DES), Oracle 11g (SHA1), Oracle 12c (SHA512) |
| **MSSQL** | MSSQL 2005, MSSQL 2012+ |
| **Cisco** | IOS MD5, PIX MD5, IOS Type 8 (PBKDF2), IOS Type 9 (scrypt), ASA MD5 |
| **Web Apps** | WordPress (phpass), phpBB3, Django PBKDF2-SHA256, Joomla, vBulletin |
| **LDAP** | LDAP SHA1, SSHA, SSHA-256, SSHA-512 |
| **Wireless** | WPA/WPA2 PMKID |
| **HMAC** | HMAC-SHA1, HMAC-SHA256 |
| **Salted** | MD5:Salt, Salt:MD5, SHA1:Salt, SHA256:Salt |
| **Other** | CRC-32, Whirlpool |

</details>

---

## Attack Modes

| Mode | Flag | Description | Tools |
|------|------|-------------|-------|
| **Dictionary** | `-a dictionary` | Standard wordlist attack | hashcat, john |
| **Rule** | `-a rule` | Wordlist + mangling rules (e.g., `best64.rule`) | hashcat, john |
| **Mask** | `-a mask` | Brute-force with character class patterns | hashcat |
| **Combo** | `-a combo` | Auto-chains: smallest wordlist → largest → rules → mask | hashcat, john |

### Mask Characters

| Char | Description | Example |
|------|-------------|---------|
| `?d` | Digits (0-9) | `?d?d?d?d` = 4-digit PIN |
| `?l` | Lowercase (a-z) | `?l?l?l?l?l?l` = 6-char lowercase |
| `?u` | Uppercase (A-Z) | `?u?l?l?l?l` = Capitalized word |
| `?s` | Special chars | `?l?l?l?l?s` = 4 chars + special |
| `?a` | All printable | `?a?a?a?a?a?a` = 6-char any |

---

## Configuration

HashCracker stores user preferences in `~/.hashcracker/config.ini`:

```ini
[general]
default_tool = both          # hashcat, john, or both
timeout = 300                # seconds per cracking attempt
output_format = text         # text, json, or csv
auto_setup = true            # prompt to install missing tools

[wordlists]
directory =                  # custom wordlist directory
preferred_order = smallest_first

[hashcat]
extra_args =                 # additional hashcat arguments
rules_dir =                  # custom rules directory
force_cpu = false            # force CPU-only mode

[online]
enabled = false              # opt-in online hash lookup (sends hashes off-host)
timeout = 5                  # API timeout in seconds
```

### Persistent Data

| Path | Purpose |
|------|---------|
| `~/.hashcracker/config.ini` | User configuration |
| `~/.hashcracker/results.log` | Cracked hash history |
| `~/.hashcracker/wordlists/` | Fallback wordlist storage |

---

## Project Structure

```
hashcracker/
├── hash_cracker.py          # Entry point
├── hashcracker/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # python -m hashcracker
│   ├── cli.py               # CLI argument parsing & dispatch
│   ├── config.py            # Configuration & color management
│   ├── utils.py             # Platform detection & clipboard
│   ├── signatures.py        # 60+ hash type signatures
│   ├── identify.py          # Hash identification engine
│   ├── crack.py             # Hashcat & John wrappers
│   ├── attacks.py           # Attack strategy orchestration
│   ├── online.py            # Online hash database lookups
│   ├── output.py            # JSON/CSV/text formatters
│   └── setup.py             # Cross-platform installer
├── tests/                   # Unit tests
├── pyproject.toml           # Python packaging
├── LICENSE                  # MIT License
├── CHANGELOG.md             # Version history
└── README.md                # This file
```

---

## Disclaimer

> **This tool is intended for authorized security testing, penetration testing engagements, CTF competitions, and educational purposes only.**
>
> You must have explicit written permission from the system owner before attempting to crack any password hashes. Unauthorized access to computer systems is illegal in most jurisdictions.
>
> The authors assume no liability for misuse of this software.

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-hash-type`)
3. Commit your changes (`git commit -m 'Add support for ...'`)
4. Push to the branch (`git push origin feature/new-hash-type`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for the security community by <a href="https://github.com/sp1r4-r">sp1r4-r</a></sub>
</p>

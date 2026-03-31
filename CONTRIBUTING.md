# Contributing to HashCracker

Thanks for your interest in contributing! This guide will help you get started.

## How to Contribute

### Reporting Bugs

- Open an [issue](https://github.com/sp1r4-r/hashcracker/issues) with a clear title
- Include your OS, Python version, and hashcat/john version
- Provide the hash (or a sanitized example) and the exact command you ran
- Include the full error output

### Adding New Hash Types

This is the easiest way to contribute. Edit `hashcracker/signatures.py`:

```python
{'pattern': r'^YOUR_REGEX_HERE$',
 'name': 'Hash Type Name', 'hashcat_mode': 12345, 'john_format': 'format-name',
 'confidence': 0.90},
```

- **pattern**: Python regex to match the hash string
- **hashcat_mode**: The hashcat `-m` mode number (check `hashcat --help`)
- **john_format**: The John `--format=` value (check `john --list=formats`)
- **confidence**: 0.0 to 1.0 — use 1.0 for unique prefixes, lower for ambiguous patterns

### Feature Requests

Open an issue with the `enhancement` label describing:
- What you want the tool to do
- Why it would be useful for security work
- Any references or examples

### Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Test your changes manually:
   ```bash
   python3 hash_cracker.py -H <test_hash>
   python3 hash_cracker.py -H <test_hash> --crack --offline
   ```
4. Ensure no regressions in hash identification:
   ```bash
   python3 -m pytest tests/ -v
   ```
5. Open a PR with a clear description of what changed and why

## Code Style

- Follow existing code patterns and structure
- Use descriptive variable names
- Keep functions focused — one function, one job
- Add comments only where the logic isn't self-evident

## Development Setup

```bash
git clone https://github.com/sp1r4-r/hashcracker.git
cd hashcracker
python3 hash_cracker.py --setup    # Install tools & wordlists
python3 -m pytest tests/ -v        # Run tests
```

## Architecture

| Module | Responsibility |
|--------|---------------|
| `cli.py` | Argument parsing, dispatch |
| `signatures.py` | Hash type database |
| `identify.py` | Pattern matching and confidence scoring |
| `crack.py` | Hashcat/John subprocess management |
| `attacks.py` | Attack strategy orchestration |
| `setup.py` | Cross-platform tool installation |
| `output.py` | Result formatting (text/JSON/CSV) |
| `config.py` | User configuration management |
| `online.py` | External API lookups |
| `utils.py` | Shared utilities |

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

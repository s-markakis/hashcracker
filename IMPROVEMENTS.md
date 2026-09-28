# HashCracker — Improvement Suggestions

A review of the v2.0.0 codebase. Findings are grouped by severity. Each item
notes the location and a concrete fix. Nothing here changes behaviour on its
own — it is a punch list.

---

## 1. Critical / correctness

### 1.1 CI `lint` job is currently failing
`flake8 hashcracker/ --max-line-length=120 --ignore=E501,W503` exits **1**
with 19 issues, so the `lint` job in `.github/workflows/ci.yml` is red on
`main`. Breakdown:

| Code | Count | Meaning |
|------|-------|---------|
| F401 | 7 | unused imports |
| E241 | 4 | multiple spaces after comma |
| E127 | 4 | continuation-line indent |
| F541 | 3 | f-string with no placeholders |
| F841 | 1 | assigned-but-unused local |

Unused imports: `time` (`attacks.py:4`, `cli.py:6`),
`format_identification` and `find_wordlists` (`cli.py:10-11`),
`SESSIONS_DIR` (`crack.py` local import), `json` (`online.py:3`),
`sys` (`utils.py:7`). Unused local: `result` in the non-progress branch of
`crack_with_hashcat` (`crack.py`, `subprocess.run(...)` result discarded).
F541: bare `f"..."` strings in `setup.py`.

**Fix:** remove the dead imports/variable, drop the stray `f` prefixes, clean
up the comma/indent whitespace. All are mechanical. Consider adding
`--select` or a `setup.cfg`/`.flake8` so the ignore list lives in one place
rather than being duplicated between the Makefile and the workflow.

### 1.2 Passwords containing `:` are truncated
- `crack.py` (hashcat): `password = content.split(':')[-1]` — hashcat's
  default outfile line is `hash:plain`, so a password like `foo:bar` returns
  only `bar`.
- `crack.py` (john): `parts = line.split(':')` then `parts[1]` — same problem;
  `user:pass:word` yields `pass`.

**Fix:** split on the *first* colon and keep the remainder, e.g.
`content.split(':', 1)[1]` for hashcat, and for john reconstruct
`':'.join(parts[2:])` (john `--show` emits `login:password:...`). Better still,
run hashcat with `--outfile-format 2` (plain only) or `--show` and parse a
known format so the delimiter is unambiguous. Add a regression test with a
colon-bearing password.

---

## 2. Behaviour / defaults worth reconsidering

### 2.1 Hashes are sent to third-party sites *by default*, before local cracking
In `cli._process_hash`, when `--crack` is set the tool does an online lookup
first unless `--offline` is passed (`online_enabled` defaults to `true`). So by
default a hash is POSTed/GET to `hashtoolkit.com` and `nitrxgen.net` before any
local attempt. For a security tool this is a meaningful data-exfiltration
default — the operator may be handling client/engagement hashes that should
never leave the machine.

**Fix options (pick one):**
- Flip the default to offline and add an explicit `--online` opt-in; or
- Keep it on but print a clear one-time notice naming the endpoints, and
  document it prominently in the README; and
- Either way, honour a `NO_NETWORK`/`--offline` flag consistently and mention
  the third-party services in the README/privacy note.

### 2.2 `hashcat -I` is re-run on every single crack attempt
`_get_hashcat_device_args()` calls `detect_hashcat_devices()`, which spawns
`hashcat -I` (15 s timeout) each time it is called. In `combo` mode this fires
once per wordlist, per rules phase, and per mask — many redundant subprocess
launches that each re-probe the GPU.

**Fix:** detect devices once per run and cache the result
(`functools.lru_cache` on `detect_hashcat_devices`, or compute the device args
in the CLI and thread them through). This is a straightforward latency win.

### 2.3 The base64 note always appends `...`
`identify.py`: `f"...Decoded hex: {decoded_hex[:64]}..."` appends `...`
unconditionally, even when the decoded hex is shorter than 64 chars.

**Fix:** only add the ellipsis when `len(decoded_hex) > 64`.

---

## 3. Test coverage

Only `identify` and `output` are tested. Untested modules: `crack`,
`attacks`, `online`, `config`, `cli`, `setup`, `utils`. High-value additions
that need no real hashcat/john binary:

- **Output parsing** — the colon-password cases from §1.2, by feeding known
  outfile/`--show` strings through small helper functions (extract the parsing
  into a pure function first so it is unit-testable without a subprocess).
- **`online_lookup`** — the guard regex `^[a-fA-F0-9]{16,128}$` and the HTML
  scrape, with `urllib` mocked; assert no network call for structured hashes.
- **`config.Config`** — defaults, `getint`/`getboolean`, round-trip
  `set`/`save`/reload.
- **`_is_base64` / `_try_base64_decode`** edge cases.
- **CLI dispatch** — `argparse` wiring and mutually-exclusive input group,
  driven via `main()` with patched collaborators.

`pytest` is invoked in CI but isn't a declared dependency — add a
`[project.optional-dependencies] test = ["pytest"]` (or a `dev` extra) so
`pip install -e '.[test]'` is reproducible, and have CI use it.

---

## 4. Robustness / smaller correctness items

- **Fragile HTML scraping** (`online.py`): `_lookup_hashtoolkit` depends on a
  specific `<span class="res-text">` markup that can change silently. Consider
  a documented JSON API where one exists, and treat these lookups as
  best-effort with clear logging when the shape no longer matches.
- **`_is_john_jumbo`** runs `john` with no args and greps stdout/stderr for
  `jumbo`/`--format`. This is brittle across versions and locales. Prefer
  parsing `john --list=build-info` (jumbo-only) and treating its absence as
  "core".
- **Regex signatures are re-matched from strings** on every `identify_hash`
  call (`signatures.py` / `identify.py`). `re` caches compiled patterns, but
  pre-compiling once at import (store `re.compile(...)` in each signature)
  makes intent explicit and avoids cache eviction with a large table.
- **Bare `except Exception:` / `except:`** appears ~7 times (device detection,
  base64 decode, clipboard, online lookups). Narrow them where practical and
  at minimum log at a debug level so genuine failures aren't swallowed
  silently.
- **Banner width** (`cli.banner`): the box uses a fixed-width border with
  `v{__version__:<22s}`; a longer version string will overflow the drawn box.
  Compute padding from the actual content or accept minor misalignment
  knowingly.

---

## 5. Packaging / project hygiene

- **`hash_cracker.py` shim** mutates `sys.path` and calls `main()` at import.
  The package already exposes a `hashcracker` console script and a
  `__main__.py`; document `python -m hashcracker` as the primary entry point
  and keep the shim only as a convenience.
- **Duplicated lint config** — the flake8 invocation lives in both `Makefile`
  and `ci.yml`. Move it to `.flake8`/`setup.cfg` so they can't drift.
- **Pin/declare dev tooling** — `flake8` and `pytest` are used by CI but not
  declared anywhere; add a `dev` extra.
- **Type hints + docstrings** are partial. Adding return-type hints to the
  public functions in `identify`, `crack`, and `attacks` would make the
  result-dict contracts (`{'password', 'time_elapsed', 'tool', ...}`) explicit
  and enable `mypy` in CI.
- **Consider a `SECURITY.md` / usage-scope note.** The README should state the
  authorized-use scope (owned systems, sanctioned engagements, CTFs) given the
  tool's nature.

---

## 6. Suggested order of work

1. Fix the failing lint (§1.1) — unblocks CI immediately.
2. Fix colon-password truncation + add a regression test (§1.2, §3).
3. Cache device detection (§2.2).
4. Decide the online-lookup default and document it (§2.1).
5. Grow test coverage and declare test deps (§3).
6. The hygiene items in §4–§5 as follow-ups.

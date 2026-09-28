"""Hash identification with confidence scoring and base64 detection."""

import base64
import re
import string
from typing import Optional

from hashcracker.config import C
from hashcracker.signatures import HASH_SIGNATURES

# Pre-compile signature patterns once at import rather than re-matching from
# strings on every identify_hash call.
_COMPILED_SIGNATURES = [(re.compile(sig['pattern']), sig) for sig in HASH_SIGNATURES]
_HEX_RE = re.compile(r'^[a-fA-F0-9]+$')


def _is_base64(s: str) -> bool:
    """Check if a string looks like base64-encoded data."""
    s = s.strip()
    if len(s) < 8 or len(s) % 4 != 0:
        return False
    b64_chars = set(string.ascii_letters + string.digits + '+/=')
    if not all(c in b64_chars for c in s):
        return False
    # Must have a reasonable mix, not just hex
    has_upper = any(c in string.ascii_uppercase for c in s)
    has_lower = any(c in string.ascii_lowercase for c in s)
    has_plus_slash = any(c in '+/' for c in s)
    if has_upper and has_lower and (has_plus_slash or s.endswith('=')):
        return True
    return False


def _try_base64_decode(s: str) -> Optional[str]:
    """Try to base64-decode a string and return the hex representation."""
    try:
        decoded = base64.b64decode(s)
        return decoded.hex()
    except Exception:
        return None


def identify_hash(hash_string: str) -> list:
    """Identify possible hash types based on pattern matching.

    Returns list of dicts sorted by confidence (highest first):
        [{'name': str, 'hashcat_mode': int|None, 'john_format': str|None,
          'confidence': float, 'note': str|None}]
    """
    hash_string = hash_string.strip()
    matches = []
    seen_names = set()
    note = None

    # Try base64 detection
    decoded_hex = None
    if _is_base64(hash_string) and not _HEX_RE.match(hash_string):
        decoded_hex = _try_base64_decode(hash_string)
        if decoded_hex:
            shown = decoded_hex[:64]
            ellipsis = '...' if len(decoded_hex) > 64 else ''
            note = f"Detected base64 encoding. Decoded hex: {shown}{ellipsis}"

    # Match against signatures
    targets = [hash_string]
    if decoded_hex:
        targets.append(decoded_hex)

    for target in targets:
        for pattern, sig in _COMPILED_SIGNATURES:
            if pattern.match(target) and sig['name'] not in seen_names:
                matches.append({
                    'name': sig['name'],
                    'hashcat_mode': sig['hashcat_mode'],
                    'john_format': sig['john_format'],
                    'confidence': sig['confidence'],
                    'note': note if target == decoded_hex else None,
                })
                seen_names.add(sig['name'])

    # Sort by confidence descending
    matches.sort(key=lambda m: m['confidence'], reverse=True)
    return matches


def _confidence_label(conf):
    """Return a human-readable confidence label."""
    if conf >= 0.90:
        return f"{C.GREEN}Most Likely{C.RESET}"
    elif conf >= 0.60:
        return f"{C.YELLOW}Likely{C.RESET}"
    elif conf >= 0.30:
        return f"{C.YELLOW}Possible{C.RESET}"
    else:
        return f"{C.DIM}Unlikely{C.RESET}"


def format_identification(hash_string, matches):
    """Format the identification results as a string."""
    lines = []
    lines.append(f"\n{C.BOLD}Hash:{C.RESET} {hash_string}")
    lines.append(f"{C.BOLD}Length:{C.RESET} {len(hash_string)} characters\n")

    if not matches:
        lines.append(f"{C.RED}[!] No matching hash type found.{C.RESET}")
        return '\n'.join(lines), []

    # Show base64 note if present
    for m in matches:
        if m.get('note'):
            lines.append(f"{C.CYAN}[*] {m['note']}{C.RESET}\n")
            break

    lines.append(f"{C.GREEN}[+] Possible hash types:{C.RESET}\n")
    lines.append(f"  {'#':<4} {'Type':<30} {'Hashcat':<10} {'John Format':<20} {'Confidence':<15}")
    lines.append(f"  {'─'*4} {'─'*30} {'─'*10} {'─'*20} {'─'*15}")

    for i, m in enumerate(matches, 1):
        hc = str(m['hashcat_mode']) if m['hashcat_mode'] is not None else 'N/A'
        jf = m['john_format'] if m['john_format'] else 'N/A'
        conf_label = _confidence_label(m['confidence'])
        lines.append(f"  {i:<4} {m['name']:<30} {hc:<10} {jf:<20} {conf_label}")

    return '\n'.join(lines), matches


def print_identification(hash_string, matches):
    """Pretty-print the identification results."""
    text, _ = format_identification(hash_string, matches)
    print(text)

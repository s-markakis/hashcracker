"""Attack strategies: dictionary, rules, mask, and combo wordlist attacks."""

import os
from typing import Optional

from hashcracker.config import C, cfg
from hashcracker.crack import (
    crack_with_hashcat,
    crack_with_john,
    find_wordlists,
)
from hashcracker.output import log_result, format_result_text


# ─── Rule File Discovery ──────────────────────────────────────────────────────

def find_rules_file():
    """Find the best hashcat rules file available."""
    search_paths = [
        # Hashcat rules
        '/usr/share/hashcat/rules/best64.rule',
        '/usr/share/hashcat/rules/rockyou-30000.rule',
        '/usr/share/hashcat/rules/d3ad0ne.rule',
        '/usr/share/hashcat/rules/dive.rule',
        '/usr/local/share/hashcat/rules/best64.rule',
        '/opt/homebrew/share/hashcat/rules/best64.rule',
    ]

    # Check config for custom rules dir
    rules_dir = cfg.get('hashcat', 'rules_dir', '')
    if rules_dir and os.path.isdir(rules_dir):
        for f in sorted(os.listdir(rules_dir)):
            if f.endswith('.rule'):
                return os.path.join(rules_dir, f)

    for path in search_paths:
        if os.path.isfile(path):
            return path
    return None


# ─── Default Masks ─────────────────────────────────────────────────────────────

DEFAULT_MASKS = [
    ('Digits 1-8', '?d?d?d?d?d?d?d?d'),
    ('Digits 1-6', '?d?d?d?d?d?d'),
    ('Lower 1-6', '?l?l?l?l?l?l'),
    ('Lower+Digit', '?l?l?l?l?l?d?d'),
    ('Upper+Lower+Digit', '?u?l?l?l?l?d?d'),
    ('Common pattern', '?u?l?l?l?l?l?d?d?s'),
    ('All printable 1-4', '?a?a?a?a'),
    ('All printable 1-5', '?a?a?a?a?a'),
    ('All printable 1-6', '?a?a?a?a?a?a'),
]


# ─── Attack Orchestrator ──────────────────────────────────────────────────────

def run_attack(hash_string, match, wordlist, tool='both', timeout=300,
               attack_mode='dictionary', mask=None, rules_file=None,
               session_name=None, show_progress=True) -> Optional[dict]:
    """Run a specific attack against a hash.

    attack_mode: 'dictionary', 'rule', 'mask', 'combo'
    Returns: result dict or None
    """
    name = match['name']
    result = None

    if attack_mode == 'dictionary':
        result = _dictionary_attack(hash_string, match, wordlist, tool, timeout,
                                    session_name, show_progress)

    elif attack_mode == 'rule':
        result = _rule_attack(hash_string, match, wordlist, tool, timeout,
                              rules_file, session_name, show_progress)

    elif attack_mode == 'mask':
        result = _mask_attack(hash_string, match, tool, timeout, mask,
                              session_name, show_progress)

    elif attack_mode == 'combo':
        result = _combo_attack(hash_string, match, tool, timeout,
                               rules_file, session_name, show_progress)

    if result:
        result.update({
            'hash': hash_string,
            'type': name,
            'confidence': match['confidence'],
        })
        log_result(result)
        print(format_result_text(result))

    return result


def _dictionary_attack(hash_string, match, wordlist, tool, timeout,
                       session_name, show_progress):
    """Standard dictionary/wordlist attack."""
    # Try hashcat
    if tool in ('both', 'hashcat') and match['hashcat_mode'] is not None:
        print(f"{C.YELLOW}[*] Hashcat dictionary attack (mode {match['hashcat_mode']})...{C.RESET}")
        result = crack_with_hashcat(
            hash_string, match['hashcat_mode'], wordlist, timeout,
            session_name=session_name, show_progress=show_progress,
        )
        if result:
            result['tool'] = 'hashcat'
            return result

    # Try john
    if tool in ('both', 'john') and match['john_format']:
        print(f"{C.YELLOW}[*] John dictionary attack (format: {match['john_format']})...{C.RESET}")
        result = crack_with_john(hash_string, match['john_format'], wordlist, timeout)
        if result:
            result['tool'] = 'john'
            return result

    return None


def _rule_attack(hash_string, match, wordlist, tool, timeout,
                 rules_file, session_name, show_progress):
    """Dictionary + rules attack (hashcat -r, john --rules)."""
    if not rules_file:
        rules_file = find_rules_file()

    if rules_file:
        print(f"{C.CYAN}[*] Using rules file: {rules_file}{C.RESET}")
    else:
        print(f"{C.YELLOW}[*] No rules file found. Falling back to dictionary attack.{C.RESET}")

    # Hashcat with rules
    if tool in ('both', 'hashcat') and match['hashcat_mode'] is not None:
        print(f"{C.YELLOW}[*] Hashcat rule attack (mode {match['hashcat_mode']})...{C.RESET}")
        result = crack_with_hashcat(
            hash_string, match['hashcat_mode'], wordlist, timeout,
            rules_file=rules_file, session_name=session_name,
            show_progress=show_progress,
        )
        if result:
            result['tool'] = 'hashcat (rules)'
            return result

    # John with rules
    if tool in ('both', 'john') and match['john_format']:
        print(f"{C.YELLOW}[*] John rule attack (format: {match['john_format']})...{C.RESET}")
        result = crack_with_john(
            hash_string, match['john_format'], wordlist, timeout, rules=True,
        )
        if result:
            result['tool'] = 'john (rules)'
            return result

    return None


def _mask_attack(hash_string, match, tool, timeout, mask,
                 session_name, show_progress):
    """Brute-force mask attack (hashcat -a 3)."""
    if tool not in ('both', 'hashcat'):
        print(f"{C.RED}[!] Mask attack requires hashcat.{C.RESET}")
        return None

    if match['hashcat_mode'] is None:
        print(f"{C.RED}[!] No hashcat mode for {match['name']}.{C.RESET}")
        return None

    masks_to_try = []
    if mask:
        masks_to_try = [('Custom', mask)]
    else:
        masks_to_try = DEFAULT_MASKS

    for mask_name, mask_pattern in masks_to_try:
        print(f"{C.YELLOW}[*] Mask: {mask_name} ({mask_pattern})...{C.RESET}")
        result = crack_with_hashcat(
            hash_string, match['hashcat_mode'], None, timeout,
            mask=mask_pattern, attack_mode=3,
            session_name=session_name, show_progress=show_progress,
        )
        if result:
            result['tool'] = f'hashcat (mask: {mask_pattern})'
            return result

    return None


def _combo_attack(hash_string, match, tool, timeout,
                  rules_file, session_name, show_progress):
    """Try multiple wordlists from smallest to largest, then rules, then mask."""
    wordlists = find_wordlists()
    if not wordlists:
        print(f"{C.RED}[!] No wordlists found. Run --setup first.{C.RESET}")
        return None

    print(f"{C.CYAN}[*] Combo attack: {len(wordlists)} wordlist(s), then rules, then mask{C.RESET}")

    # Phase 1: Dictionary attacks with all wordlists (smallest first)
    for wl in wordlists:
        size_mb = os.path.getsize(wl) / (1024 * 1024)
        wl_name = os.path.basename(wl)
        print(f"\n{C.CYAN}[*] Wordlist: {wl_name} ({size_mb:.1f} MB){C.RESET}")

        result = _dictionary_attack(hash_string, match, wl, tool, timeout,
                                    session_name, show_progress)
        if result:
            return result

    # Phase 2: Rules attack with the largest wordlist
    if rules_file or find_rules_file():
        largest_wl = wordlists[-1] if wordlists else None
        if largest_wl:
            print(f"\n{C.CYAN}[*] Phase 2: Rules attack{C.RESET}")
            result = _rule_attack(hash_string, match, largest_wl, tool, timeout,
                                  rules_file, session_name, show_progress)
            if result:
                return result

    # Phase 3: Short mask attack
    if tool in ('both', 'hashcat') and match['hashcat_mode'] is not None:
        print(f"\n{C.CYAN}[*] Phase 3: Mask attack (short patterns){C.RESET}")
        short_masks = DEFAULT_MASKS[:4]  # Only try short masks in combo mode
        for mask_name, mask_pattern in short_masks:
            print(f"{C.YELLOW}[*] Mask: {mask_name} ({mask_pattern})...{C.RESET}")
            result = crack_with_hashcat(
                hash_string, match['hashcat_mode'], None, timeout,
                mask=mask_pattern, attack_mode=3,
                session_name=session_name, show_progress=show_progress,
            )
            if result:
                result['tool'] = f'hashcat (mask: {mask_pattern})'
                result.update({
                    'hash': hash_string,
                    'type': match['name'],
                    'confidence': match['confidence'],
                })
                return result

    return None

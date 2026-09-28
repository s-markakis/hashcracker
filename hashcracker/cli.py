"""CLI entry point: argument parsing, dispatch, interactive mode."""

import argparse
import os
import sys

from hashcracker import __version__
from hashcracker.config import C, cfg, CONFIG_FILE
from hashcracker.identify import identify_hash, print_identification
from hashcracker.crack import (
    find_wordlist, resume_session, list_sessions,
    detect_hashcat_devices,
)
from hashcracker.attacks import run_attack
from hashcracker.online import online_lookup
from hashcracker.output import (
    format_results_json, format_results_csv,
    format_identification_json, format_identification_csv,
    print_summary, save_output, log_result,
)
from hashcracker.setup import run_setup
from hashcracker.utils import check_tool, get_clipboard


def banner():
    width = 47

    def row(text):
        # Center text within the box; truncate if it would overflow the border.
        if len(text) > width:
            text = text[:width]
        return f"    ║{text.center(width)}║"

    lines = [
        f"    ╔{'═' * width}╗",
        row(f"HASH CRACKER v{__version__}"),
        row("Hash Identification & Cracking Tool"),
        row("Powered by Hashcat & John the Ripper"),
        f"    ╚{'═' * width}╝",
    ]
    print(f"{C.CYAN}{C.BOLD}\n" + "\n".join(lines) + f"\n    {C.RESET}")


def _auto_setup_prompt():
    """Prompt user to run setup if tools/wordlists are missing."""
    missing = []
    if not check_tool('hashcat'):
        missing.append('hashcat')
    if not (check_tool('john') or check_tool('john-the-ripper')):
        missing.append('john')
    if not find_wordlist():
        missing.append('wordlists')

    if not missing:
        return True

    if not cfg.auto_setup:
        return False

    print(f"{C.YELLOW}[!] Missing: {', '.join(missing)}{C.RESET}")
    try:
        answer = input(f"{C.BOLD}[?] Run setup to install them? [Y/n]: {C.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False

    if answer in ('', 'y', 'yes'):
        run_setup()
        return True
    return False


def _resolve_wordlist(args):
    """Resolve the wordlist to use, with auto-setup fallback."""
    wordlist = args.wordlist
    if not wordlist:
        wordlist = find_wordlist()
    if not wordlist:
        if hasattr(args, 'crack') and args.crack:
            if not _auto_setup_prompt():
                print(f"{C.RED}[!] No wordlist found. Use --wordlist or run --setup.{C.RESET}")
                sys.exit(1)
            wordlist = find_wordlist()
    if wordlist and not os.path.isfile(wordlist):
        print(f"{C.RED}[!] Wordlist not found: {wordlist}{C.RESET}")
        sys.exit(1)
    return wordlist


def _process_hash(hash_string, args, wordlist):
    """Process a single hash: identify, optional online lookup, optional crack.

    Returns a result dict.
    """
    matches = identify_hash(hash_string)
    output_fmt = args.output_format or cfg.output_format

    # Print identification
    if output_fmt == 'json':
        print(format_identification_json(hash_string, matches))
    elif output_fmt == 'csv':
        print(format_identification_csv(hash_string, matches))
    else:
        print_identification(hash_string, matches)

    if not matches:
        return {'hash': hash_string, 'password': None, 'type': None}

    if args.identify_only or not args.crack:
        return {'hash': hash_string, 'password': None, 'type': matches[0]['name']}

    if not wordlist and args.attack_mode != 'mask':
        print(f"{C.RED}[!] No wordlist available for cracking.{C.RESET}")
        return {'hash': hash_string, 'password': None, 'type': matches[0]['name']}

    # Online lookup first. Opt-in: hashes leave the machine only when the user
    # explicitly asks (--online), or enables it in the config. --offline always
    # wins so it can override a config default.
    online_active = (args.online or cfg.online_enabled) and not args.offline
    if online_active:
        online_result = online_lookup(hash_string)
        if online_result:
            result = {
                'hash': hash_string,
                'type': matches[0]['name'],
                'password': online_result,
                'tool': 'online lookup',
                'confidence': matches[0]['confidence'],
                'time_elapsed': 0,
            }
            log_result(result)
            print(f"\n{C.GREEN}{C.BOLD}[+] FOUND via online lookup!{C.RESET}")
            print(f"{C.GREEN}    Hash:       {hash_string}")
            print(f"    Type:       {matches[0]['name']}")
            print(f"    Password:   {online_result}{C.RESET}")
            return result

    # Crack attempt
    print(f"\n{C.BOLD}{'═'*55}")
    print(f" Cracking Attempt — {args.attack_mode} attack")
    print(f"{'═'*55}{C.RESET}")
    if wordlist:
        print(f"{C.CYAN}[*] Wordlist: {wordlist}{C.RESET}")
    print(f"{C.CYAN}[*] Timeout: {args.timeout}s per attempt{C.RESET}")
    print(f"{C.CYAN}[*] Tool: {args.tool}{C.RESET}\n")

    # Try each matching type by confidence order
    for match in matches:
        print(f"\n{C.MAGENTA}[*] Trying as: {match['name']} "
              f"(confidence: {match['confidence']:.0%}){C.RESET}")

        result = run_attack(
            hash_string, match, wordlist,
            tool=args.tool,
            timeout=args.timeout,
            attack_mode=args.attack_mode,
            mask=args.mask,
            rules_file=args.rules,
            session_name=args.session,
            show_progress=not args.quiet,
        )

        if result:
            return result

        print(f"{C.RED}[-] Failed as {match['name']}.{C.RESET}")

    print(f"\n{C.RED}[!] Could not crack the hash.{C.RESET}")
    print(f"{C.YELLOW}[*] Tips: Try --attack-mode combo, a larger wordlist, "
          f"or --attack-mode mask.{C.RESET}")
    return {'hash': hash_string, 'password': None, 'type': matches[0]['name']}


def interactive_mode(args, wordlist):
    """Run in interactive mode, prompting for hashes."""
    banner()
    print(f"{C.CYAN}[*] Interactive mode. Commands: hash, 'quit', 'devices', 'sessions'{C.RESET}")
    if wordlist:
        print(f"{C.CYAN}[*] Wordlist: {wordlist}{C.RESET}")
    print()

    while True:
        try:
            hash_input = input(f"{C.BOLD}hash> {C.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.CYAN}[*] Goodbye!{C.RESET}")
            break

        if not hash_input:
            continue
        if hash_input.lower() in ('quit', 'exit', 'q'):
            print(f"{C.CYAN}[*] Goodbye!{C.RESET}")
            break
        if hash_input.lower() == 'devices':
            info = detect_hashcat_devices()
            print(f"  GPU: {'Yes' if info['gpu'] else 'No'}")
            for d in info['devices']:
                print(f"  {d}")
            continue
        if hash_input.lower() == 'sessions':
            sessions = list_sessions()
            if sessions:
                for s in sessions:
                    print(f"  - {s}")
            else:
                print("  No saved sessions.")
            continue

        matches = identify_hash(hash_input)
        print_identification(hash_input, matches)

        if matches and wordlist:
            try:
                answer = input(f"\n{C.BOLD}[?] Attempt to crack? [Y/n]: {C.RESET}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                continue

            if answer in ('', 'y', 'yes'):
                for match in matches:
                    result = run_attack(
                        hash_input, match, wordlist,
                        tool=args.tool, timeout=args.timeout,
                        attack_mode=args.attack_mode,
                        show_progress=not args.quiet,
                    )
                    if result:
                        break
                    print(f"{C.RED}[-] Failed as {match['name']}.{C.RESET}")
        elif matches and not wordlist:
            print(f"{C.YELLOW}[*] No wordlist found. Use --wordlist or run --setup.{C.RESET}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description='HashCracker v2.0 - Identify and crack password hashes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Attack modes:
  dictionary  Standard wordlist attack (default)
  rule        Wordlist + mangling rules (hashcat -r / john --rules)
  mask        Brute-force with character masks (hashcat -a 3)
  combo       Auto: tries all wordlists, then rules, then mask

Examples:
  %(prog)s --setup
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99
  %(prog)s -H <hash> --crack
  %(prog)s -H <hash> --crack --attack-mode rule
  %(prog)s -H <hash> --crack --attack-mode mask --mask '?d?d?d?d?d?d'
  %(prog)s -H <hash> --crack --attack-mode combo
  %(prog)s -f hashes.txt --crack --output-format json -o results.json
  %(prog)s --clipboard --crack
  %(prog)s --interactive
  %(prog)s --resume <session-name>
  %(prog)s --devices

Config file: {CONFIG_FILE}
Results log: ~/.hashcracker/results.log
        """,
    )

    # Input sources
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-H', '--hash', help='Single hash to identify/crack')
    input_group.add_argument('-f', '--file', help='File containing hashes (one per line)')
    input_group.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    input_group.add_argument('--clipboard', action='store_true',
                             help='Read hash from system clipboard')
    input_group.add_argument('--setup', action='store_true',
                             help='Install tools (hashcat, john) and wordlists')
    input_group.add_argument('--resume', metavar='SESSION',
                             help='Resume a saved hashcat session')
    input_group.add_argument('--devices', action='store_true',
                             help='Show available hashcat devices (GPU/CPU)')

    # Cracking options
    parser.add_argument('-c', '--crack', action='store_true',
                        help='Attempt to crack the hash(es)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('--wordlist-dir',
                        help='Custom wordlist directory (for --setup)')
    parser.add_argument('-t', '--tool', choices=['hashcat', 'john', 'both'],
                        default=cfg.default_tool,
                        help=f'Cracking tool (default: {cfg.default_tool})')
    parser.add_argument('--timeout', type=int, default=cfg.timeout,
                        help=f'Timeout per attempt in seconds (default: {cfg.timeout})')

    # Attack modes
    parser.add_argument('-a', '--attack-mode',
                        choices=['dictionary', 'rule', 'mask', 'combo'],
                        default='dictionary',
                        help='Attack strategy (default: dictionary)')
    parser.add_argument('--mask', help='Custom mask for mask attack (e.g. ?a?a?a?a?a?a)')
    parser.add_argument('--rules', help='Path to hashcat rules file')
    parser.add_argument('--session', help='Hashcat session name for resume support')

    # Output options
    parser.add_argument('--output-format', choices=['text', 'json', 'csv'],
                        default=None, help='Output format (default: text)')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress progress output')
    parser.add_argument('--identify-only', action='store_true',
                        help='Only identify hash type, do not crack')
    parser.add_argument('--offline', action='store_true',
                        help='Never query online databases (overrides --online and config)')
    parser.add_argument('--online', action='store_true',
                        help='Opt in to online hash lookup (sends the hash to third-party sites)')

    parser.add_argument('--version', action='version', version=f'HashCracker {__version__}')

    args = parser.parse_args()

    # ── Special modes ──

    if args.setup:
        run_setup(args.wordlist_dir)
        return

    if args.resume:
        banner()
        resume_session(args.resume)
        return

    if args.devices:
        banner()
        info = detect_hashcat_devices()
        print(f"{C.BOLD}Hashcat Device Info:{C.RESET}")
        print(f"  GPU available: {'Yes' if info['gpu'] else 'No'}")
        for d in info['devices']:
            print(f"  {d}")
        return

    # ── Clipboard input ──
    if args.clipboard:
        clip = get_clipboard()
        if clip:
            print(f"{C.CYAN}[*] Read from clipboard: {clip[:60]}{'...' if len(clip) > 60 else ''}{C.RESET}")
            args.hash = clip
        else:
            print(f"{C.RED}[!] Could not read from clipboard.{C.RESET}")
            sys.exit(1)

    # ── Interactive mode ──
    if args.interactive:
        wordlist = _resolve_wordlist(args) if args.crack or args.wordlist else find_wordlist()
        interactive_mode(args, wordlist)
        return

    # ── No input ──
    if not args.hash and not args.file:
        banner()
        parser.print_help()
        return

    # Keep stdout clean for machine-readable formats so it can be piped/parsed.
    if (args.output_format or cfg.output_format) == 'text':
        banner()

    # ── Auto-setup check ──
    if args.crack:
        _auto_setup_prompt()

    wordlist = _resolve_wordlist(args) if (args.crack and args.attack_mode != 'mask') else None

    # ── Collect hashes ──
    hashes = []
    if args.hash:
        hashes.append(args.hash.strip())
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"{C.RED}[!] File not found: {args.file}{C.RESET}")
            sys.exit(1)
        with open(args.file) as f:
            hashes = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    # ── Process hashes ──
    results = []
    for h in hashes:
        result = _process_hash(h, args, wordlist)
        results.append(result)
        print()

    # ── Output ──
    output_fmt = args.output_format or cfg.output_format

    if len(results) > 1 and output_fmt == 'text':
        print_summary(results)

    # Save to file
    if args.output and results:
        if output_fmt == 'json':
            save_output(format_results_json(results), args.output)
        elif output_fmt == 'csv':
            save_output(format_results_csv(results), args.output)
        else:
            # Text summary to file
            lines = []
            for r in results:
                pw = r.get('password', '')
                lines.append(f"{r.get('hash','')}:{pw if pw else '???'}")
            save_output('\n'.join(lines), args.output)

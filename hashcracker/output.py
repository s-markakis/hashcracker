"""Output formatting: text, JSON, CSV, file logging, and progress display."""

import csv
import io
import json
import os
from datetime import datetime

from hashcracker.config import C, CONFIG_DIR, RESULTS_LOG


def format_result_text(result):
    """Format a single crack result as colored text."""
    lines = []
    if result.get('password'):
        lines.append(f"\n{C.GREEN}{C.BOLD}[+] CRACKED with {result['tool']}!{C.RESET}")
        lines.append(f"{C.GREEN}    Hash:       {result['hash']}")
        lines.append(f"    Type:       {result['type']}")
        lines.append(f"    Password:   {result['password']}")
        if result.get('time_elapsed'):
            lines.append(f"    Time:       {result['time_elapsed']:.1f}s")
        lines.append(C.RESET)
    return '\n'.join(lines)


def format_results_json(results):
    """Format results as JSON."""
    output = []
    for r in results:
        output.append({
            'hash': r.get('hash', ''),
            'type': r.get('type', ''),
            'password': r.get('password'),
            'tool': r.get('tool', ''),
            'confidence': r.get('confidence', 0),
            'time_elapsed': r.get('time_elapsed'),
            'cracked': r.get('password') is not None,
        })
    return json.dumps(output, indent=2)


def format_results_csv(results):
    """Format results as CSV."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        'hash', 'type', 'password', 'tool', 'confidence', 'time_elapsed', 'cracked'
    ])
    writer.writeheader()
    for r in results:
        writer.writerow({
            'hash': r.get('hash', ''),
            'type': r.get('type', ''),
            'password': r.get('password', ''),
            'tool': r.get('tool', ''),
            'confidence': r.get('confidence', 0),
            'time_elapsed': r.get('time_elapsed', ''),
            'cracked': r.get('password') is not None,
        })
    return buf.getvalue()


def format_identification_json(hash_string, matches):
    """Format identification results as JSON."""
    return json.dumps({
        'hash': hash_string,
        'length': len(hash_string),
        'matches': [
            {
                'type': m['name'],
                'hashcat_mode': m['hashcat_mode'],
                'john_format': m['john_format'],
                'confidence': m['confidence'],
            }
            for m in matches
        ]
    }, indent=2)


def format_identification_csv(hash_string, matches):
    """Format identification results as CSV."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        'hash', 'type', 'hashcat_mode', 'john_format', 'confidence'
    ])
    writer.writeheader()
    for m in matches:
        writer.writerow({
            'hash': hash_string,
            'type': m['name'],
            'hashcat_mode': m['hashcat_mode'] if m['hashcat_mode'] is not None else '',
            'john_format': m['john_format'] or '',
            'confidence': m['confidence'],
        })
    return buf.getvalue()


def log_result(result):
    """Append a cracked result to the results log file."""
    if not result.get('password'):
        return
    os.makedirs(CONFIG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(RESULTS_LOG, 'a') as f:
        f.write(f"[{timestamp}] {result['hash']}  |  {result['type']}  |  {result['password']}  |  {result['tool']}\n")


def save_output(content, filepath):
    """Save output content to a file."""
    with open(filepath, 'w') as f:
        f.write(content)
    print(f"{C.GREEN}[+] Results saved to: {filepath}{C.RESET}")


def print_summary(results):
    """Print a summary table for batch results."""
    cracked_count = sum(1 for r in results if r.get('password'))
    print(f"\n{C.BOLD}{'═'*55}")
    print(f" Summary: {cracked_count}/{len(results)} hashes cracked")
    print(f"{'═'*55}{C.RESET}")
    for r in results:
        h = r['hash']
        if len(h) > 40:
            h = h[:40] + '...'
        if r.get('password'):
            status = f"{C.GREEN}+ {r['password']}{C.RESET}"
        else:
            status = f"{C.RED}x{C.RESET}"
        print(f"  {h:<44} {status}")

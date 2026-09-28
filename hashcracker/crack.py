"""Core cracking functions for hashcat and John the Ripper."""

import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
from functools import lru_cache
from typing import Optional

from hashcracker.config import C, cfg
from hashcracker.utils import check_tool

log = logging.getLogger('hashcracker')


# ─── GPU / Device Detection ───────────────────────────────────────────────────

@lru_cache(maxsize=1)
def detect_hashcat_devices():
    """Detect available hashcat devices. Returns a dict with device info.

    Cached: probing with ``hashcat -I`` is expensive and the device set does
    not change within a single run, so it is only executed once.
    """
    if not check_tool('hashcat'):
        return {'gpu': False, 'cpu': True, 'devices': []}

    try:
        result = subprocess.run(
            ['hashcat', '-I'],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout + result.stderr
        has_gpu = any(t in output.lower() for t in ['gpu', 'cuda', 'opencl', 'metal'])
        devices = []
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('* Device') or 'Type' in line:
                devices.append(line)
        return {'gpu': has_gpu, 'cpu': True, 'devices': devices}
    except Exception as e:
        log.debug('hashcat device detection failed: %s', e)
        return {'gpu': False, 'cpu': True, 'devices': []}


def _get_hashcat_device_args():
    """Get the appropriate device arguments for hashcat."""
    if cfg.force_cpu:
        return ['-D', '1']  # CPU only

    info = detect_hashcat_devices()
    if info['gpu']:
        return []  # Let hashcat auto-select (prefers GPU)
    else:
        print(f"{C.YELLOW}[*] No GPU detected. Using CPU mode.{C.RESET}")
        return ['-D', '1', '--force']


# ─── John Version Detection ───────────────────────────────────────────────────

def _find_john():
    """Find john binary and return path, or None."""
    for name in ['john', 'john-the-ripper']:
        path = shutil.which(name)
        if path:
            return path
    return None


def _is_john_jumbo(john_bin: str) -> bool:
    """Check if the installed john is the jumbo version.

    ``--list=build-info`` is a jumbo-only option; if it succeeds and mentions
    jumbo we are confident. Fall back to scanning the banner for older builds.
    """
    try:
        result = subprocess.run(
            [john_bin, '--list=build-info'],
            capture_output=True, text=True, timeout=5,
        )
        info = (result.stdout + result.stderr).lower()
        if 'jumbo' in info:
            return True
    except Exception as e:
        log.debug('john build-info probe failed: %s', e)

    try:
        result = subprocess.run([john_bin], capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        return 'jumbo' in output.lower() or '--format' in output
    except Exception as e:
        log.debug('john version probe failed: %s', e)
        return False


# ─── Wordlist Discovery ───────────────────────────────────────────────────────

def find_wordlists() -> list:
    """Find all available wordlists, sorted by size (smallest first).

    Returns list of file paths.
    """
    from hashcracker.setup import get_wordlist_dir
    from hashcracker.utils import get_platform

    plat = get_platform()
    home_wl = os.path.join(os.path.expanduser('~'), '.hashcracker', 'wordlists')

    search_dirs = [
        get_wordlist_dir(plat),
        home_wl,
        '/usr/share/wordlists',
        '/usr/share/seclists/Passwords/Common-Credentials',
        '/usr/share/john',
        '/usr/local/share/wordlists',
        '/opt/homebrew/share/wordlists',
    ]

    wordlist_files = set()
    extensions = ('.txt', '.lst', '.dict')

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for f in os.listdir(d):
                full = os.path.join(d, f)
                if os.path.isfile(full) and any(f.endswith(ext) for ext in extensions):
                    wordlist_files.add(full)
        except PermissionError:
            continue

    # Sort by file size (smallest first for combo mode)
    return sorted(wordlist_files, key=lambda f: os.path.getsize(f))


def find_wordlist() -> Optional[str]:
    """Find the best single wordlist (largest available)."""
    wordlists = find_wordlists()
    if not wordlists:
        return None
    # Prefer rockyou if available, otherwise largest
    for wl in reversed(wordlists):
        if 'rockyou' in os.path.basename(wl).lower():
            return wl
    return wordlists[-1]  # largest


# ─── Output Parsing ───────────────────────────────────────────────────────────

def _parse_hashcat_outfile(content: str) -> Optional[str]:
    """Extract the plaintext from a hashcat ``--outfile-format 2`` file.

    Format 2 writes the plaintext only (one per line), so the whole line is the
    password — including any ':' it may contain.
    """
    for line in content.splitlines():
        if line:
            return line
    return None


def _parse_john_show(stdout: str) -> Optional[str]:
    """Extract the plaintext from ``john --show`` output.

    Lines look like ``login:password[:extra fields]``. The password may itself
    contain ':', so everything after the first field is preserved.
    """
    for line in stdout.strip().splitlines():
        line = line.rstrip('\n')
        if ':' not in line or 'password hash' in line.lower():
            continue
        _, _, password = line.partition(':')
        if password:
            return password
    return None


# ─── Hashcat Cracking ─────────────────────────────────────────────────────────

def _stream_hashcat_output(proc):
    """Read and display hashcat status output in real-time."""
    try:
        for line in iter(proc.stdout.readline, ''):
            line = line.strip()
            if not line:
                continue
            # Display status lines
            if any(k in line for k in ['Speed', 'Progress', 'Recovered', 'Time.Est']):
                print(f"\r{C.DIM}    {line}{C.RESET}", end='', flush=True)
            elif 'Cracking' in line or 'Status' in line:
                print(f"\r{C.DIM}    {line}{C.RESET}", end='', flush=True)
    except (ValueError, OSError):
        pass


def crack_with_hashcat(hash_string, mode, wordlist, timeout_sec=300,
                       rules_file=None, mask=None, attack_mode=0,
                       session_name=None, show_progress=True) -> Optional[dict]:
    """Attempt to crack hash using hashcat.

    Returns: dict with 'password', 'time_elapsed' keys, or None.
    """
    if not check_tool('hashcat'):
        print(f"{C.RED}[!] hashcat not found on system.{C.RESET}")
        return None

    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='hc_hash_') as f:
        f.write(hash_string + '\n')
        hash_file = f.name

    outfile = hash_file + '.cracked'
    start_time = time.time()

    try:
        cmd = [
            'hashcat',
            '-m', str(mode),
            '-a', str(attack_mode),
            hash_file,
        ]

        # Dictionary or combo attack needs a wordlist
        if attack_mode in (0, 1, 6, 7) and wordlist:
            cmd.append(wordlist)

        # Mask attack
        if attack_mode == 3 and mask:
            cmd.append(mask)

        # Rules
        if rules_file and os.path.isfile(rules_file):
            cmd.extend(['-r', rules_file])

        cmd.extend([
            '-o', outfile,
            '--outfile-format', '2',  # plaintext only — avoids hash:plain colon ambiguity
            '--potfile-disable',
            '--quiet',
        ])

        # Device args (GPU/CPU)
        cmd.extend(_get_hashcat_device_args())

        # Session support
        if session_name:
            cmd.extend(['--session', session_name])

        # Progress display
        if show_progress:
            cmd.extend(['--status', '--status-timer=5'])

        # Extra args from config
        cmd.extend(cfg.hashcat_extra_args)

        print(f"{C.BLUE}[*] Running: {' '.join(cmd)}{C.RESET}")

        if show_progress:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
            reader = threading.Thread(target=_stream_hashcat_output, args=(proc,), daemon=True)
            reader.start()

            try:
                proc.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                proc.kill()
                print(f"\n{C.YELLOW}[!] Hashcat timed out after {timeout_sec}s.{C.RESET}")
                return None
            finally:
                print()  # newline after progress
        else:
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_sec,
            )

        elapsed = time.time() - start_time

        # Check output file
        if os.path.exists(outfile):
            with open(outfile) as f:
                content = f.read()
            password = _parse_hashcat_outfile(content)
            if password is not None:
                return {'password': password, 'time_elapsed': elapsed}

        return None

    except subprocess.TimeoutExpired:
        print(f"{C.YELLOW}[!] Hashcat timed out after {timeout_sec}s.{C.RESET}")
        return None
    except Exception as e:
        print(f"{C.RED}[!] Hashcat error: {e}{C.RESET}")
        return None
    finally:
        for f in [hash_file, outfile]:
            if os.path.exists(f):
                os.unlink(f)


# ─── John Cracking ────────────────────────────────────────────────────────────

def crack_with_john(hash_string, john_format, wordlist, timeout_sec=300,
                    rules=False) -> Optional[dict]:
    """Attempt to crack hash using John the Ripper.

    Returns: dict with 'password', 'time_elapsed' keys, or None.
    """
    john_bin = _find_john()
    if not john_bin:
        print(f"{C.RED}[!] John the Ripper not found on system.{C.RESET}")
        return None

    is_jumbo = _is_john_jumbo(john_bin)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, prefix='john_hash_') as f:
        f.write(hash_string + '\n')
        hash_file = f.name

    start_time = time.time()

    try:
        cmd = [john_bin, hash_file]

        if is_jumbo and john_format:
            cmd.append(f'--format={john_format}')
        elif not is_jumbo:
            print(f"{C.YELLOW}[*] Basic John detected (not jumbo). Running without --format.{C.RESET}")

        cmd.append(f'--wordlist={wordlist}')

        if rules and is_jumbo:
            cmd.append('--rules')

        print(f"{C.BLUE}[*] Running: {' '.join(cmd)}{C.RESET}")

        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        elapsed = time.time() - start_time

        # Show the cracked password
        show_cmd = [john_bin, '--show', hash_file]
        if is_jumbo and john_format:
            show_cmd.append(f'--format={john_format}')
        show_result = subprocess.run(show_cmd, capture_output=True, text=True, timeout=30)

        if show_result.stdout:
            password = _parse_john_show(show_result.stdout)
            if password is not None:
                return {'password': password, 'time_elapsed': elapsed}

        return None

    except subprocess.TimeoutExpired:
        print(f"{C.YELLOW}[!] John timed out after {timeout_sec}s.{C.RESET}")
        return None
    except Exception as e:
        print(f"{C.RED}[!] John error: {e}{C.RESET}")
        return None
    finally:
        if os.path.exists(hash_file):
            os.unlink(hash_file)


# ─── Session / Resume ─────────────────────────────────────────────────────────

def resume_session(session_name):
    """Resume a hashcat session by name."""
    if not check_tool('hashcat'):
        print(f"{C.RED}[!] hashcat not found.{C.RESET}")
        return False

    cmd = ['hashcat', '--session', session_name, '--restore']
    print(f"{C.BLUE}[*] Resuming session: {session_name}{C.RESET}")
    print(f"{C.BLUE}[*] Running: {' '.join(cmd)}{C.RESET}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        reader = threading.Thread(target=_stream_hashcat_output, args=(proc,), daemon=True)
        reader.start()
        proc.wait()
        return proc.returncode == 0
    except Exception as e:
        print(f"{C.RED}[!] Resume failed: {e}{C.RESET}")
        return False


def list_sessions():
    """List saved hashcat sessions."""
    sessions = []

    # Check hashcat's default session directory
    home = os.path.expanduser('~')
    hashcat_dir = os.path.join(home, '.hashcat', 'sessions')
    for d in [hashcat_dir, os.path.join(home, '.local', 'share', 'hashcat', 'sessions')]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith('.restore'):
                    sessions.append(f.replace('.restore', ''))

    return sessions

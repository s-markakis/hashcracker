"""Core cracking functions for hashcat and John the Ripper."""

import os
import shutil
import subprocess
import tempfile
import threading
import time

from hashcracker.config import C, cfg
from hashcracker.utils import check_tool


# ─── GPU / Device Detection ───────────────────────────────────────────────────

def detect_hashcat_devices():
    """Detect available hashcat devices. Returns a dict with device info."""
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
    except Exception:
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


def _is_john_jumbo(john_bin):
    """Check if the installed john is the jumbo version."""
    try:
        result = subprocess.run([john_bin], capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        return 'jumbo' in output.lower() or '--format' in output
    except Exception:
        return False


# ─── Wordlist Discovery ───────────────────────────────────────────────────────

def find_wordlists():
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


def find_wordlist():
    """Find the best single wordlist (largest available)."""
    wordlists = find_wordlists()
    if not wordlists:
        return None
    # Prefer rockyou if available, otherwise largest
    for wl in reversed(wordlists):
        if 'rockyou' in os.path.basename(wl).lower():
            return wl
    return wordlists[-1]  # largest


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
                       session_name=None, show_progress=True):
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
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_sec,
            )

        elapsed = time.time() - start_time

        # Check output file
        if os.path.exists(outfile):
            with open(outfile) as f:
                content = f.read().strip()
            if content:
                password = content.split(':')[-1]
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
                    rules=False):
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
            for line in show_result.stdout.strip().split('\n'):
                if ':' in line and 'password hashes cracked' not in line.lower():
                    parts = line.split(':')
                    if len(parts) >= 2 and parts[1]:
                        return {'password': parts[1], 'time_elapsed': elapsed}

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
    from hashcracker.config import SESSIONS_DIR
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

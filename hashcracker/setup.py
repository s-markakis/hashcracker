"""Cross-platform installation of tools (hashcat, john) and wordlists."""

import gzip
import os
import platform
import subprocess
import tempfile
import urllib.request
import zipfile

from hashcracker.config import C, cfg
from hashcracker.utils import (
    check_tool, detect_linux_distro, get_platform, is_admin, run_cmd,
)

# ─── Wordlist Config ──────────────────────────────────────────────────────────

WORDLIST_DIR_DEFAULTS = {
    'linux': '/usr/share/wordlists',
    'macos': '/usr/local/share/wordlists',
    'windows': os.path.join(os.environ.get('LOCALAPPDATA', 'C:\\Tools'), 'wordlists'),
}

WORDLIST_SOURCES = {
    'rockyou': {
        'url': 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
        'filename': 'rockyou.txt',
        'description': 'RockYou (~14M passwords, 134MB)',
    },
    'common': {
        'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt',
        'filename': '10k-most-common.txt',
        'description': '10K Most Common Passwords (small, fast)',
    },
    'darkweb-top10k': {
        'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt',
        'filename': 'darkweb2017_top-10000.txt',
        'description': 'Dark Web Top 10K (2017)',
    },
    'xato-1m': {
        'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt',
        'filename': 'xato-net-10-million-passwords-1000000.txt',
        'description': 'Xato 1M Passwords (8MB, medium)',
    },
}


def get_wordlist_dir(plat=None):
    """Get the wordlist directory for the current platform."""
    if cfg.wordlist_dir:
        return cfg.wordlist_dir
    if plat is None:
        plat = get_platform()
    return WORDLIST_DIR_DEFAULTS.get(plat, '/usr/share/wordlists')


# ─── Tool Installation ────────────────────────────────────────────────────────

def install_hashcat(plat):
    """Install hashcat for the given platform."""
    if check_tool('hashcat'):
        print(f"{C.GREEN}  [+] hashcat is already installed.{C.RESET}")
        return True

    print(f"{C.YELLOW}  [*] Installing hashcat...{C.RESET}")
    try:
        if plat == 'linux':
            distro = detect_linux_distro()
            if distro == 'debian':
                run_cmd(['sudo', 'apt-get', 'update', '-qq'])
                run_cmd(['sudo', 'apt-get', 'install', '-y', '-qq', 'hashcat'])
            elif distro == 'rhel':
                run_cmd(['sudo', 'dnf', 'install', '-y', 'hashcat'])
            elif distro == 'arch':
                run_cmd(['sudo', 'pacman', '-S', '--noconfirm', 'hashcat'])
            elif distro == 'suse':
                run_cmd(['sudo', 'zypper', 'install', '-y', 'hashcat'])
            else:
                print(f"{C.RED}  [!] Unknown Linux distro. Install hashcat manually.{C.RESET}")
                return False
        elif plat == 'macos':
            if not check_tool('brew'):
                print(f"{C.RED}  [!] Homebrew not found. Install it first: https://brew.sh{C.RESET}")
                return False
            run_cmd(['brew', 'install', 'hashcat'])
        elif plat == 'windows':
            if check_tool('winget'):
                try:
                    run_cmd(['winget', 'install', '--id', 'hashcat.hashcat',
                             '--accept-source-agreements', '--accept-package-agreements'])
                except subprocess.CalledProcessError:
                    pass
            if not check_tool('hashcat'):
                if check_tool('choco'):
                    run_cmd(['choco', 'install', 'hashcat', '-y'])
                else:
                    _download_hashcat_windows()
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"{C.RED}  [!] Failed to install hashcat: {e}{C.RESET}")
        return False

    ok = check_tool('hashcat')
    print(f"{C.GREEN}  [+] hashcat installed.{C.RESET}" if ok
          else f"{C.RED}  [!] hashcat installation could not be verified.{C.RESET}")
    return ok


def install_john(plat):
    """Install John the Ripper (jumbo preferred) for the given platform."""
    if check_tool('john') or check_tool('john-the-ripper'):
        print(f"{C.GREEN}  [+] John the Ripper is already installed.{C.RESET}")
        return True

    print(f"{C.YELLOW}  [*] Installing John the Ripper...{C.RESET}")
    try:
        if plat == 'linux':
            distro = detect_linux_distro()
            if distro == 'debian':
                run_cmd(['sudo', 'apt-get', 'update', '-qq'])
                try:
                    run_cmd(['sudo', 'apt-get', 'install', '-y', '-qq', 'john-jumbo'])
                except subprocess.CalledProcessError:
                    run_cmd(['sudo', 'apt-get', 'install', '-y', '-qq', 'john'])
            elif distro == 'rhel':
                run_cmd(['sudo', 'dnf', 'install', '-y', 'john'])
            elif distro == 'arch':
                run_cmd(['sudo', 'pacman', '-S', '--noconfirm', 'john'])
            elif distro == 'suse':
                run_cmd(['sudo', 'zypper', 'install', '-y', 'john'])
            else:
                print(f"{C.RED}  [!] Unknown Linux distro. Install john manually.{C.RESET}")
                return False
        elif plat == 'macos':
            if not check_tool('brew'):
                print(f"{C.RED}  [!] Homebrew not found. Install it first: https://brew.sh{C.RESET}")
                return False
            run_cmd(['brew', 'install', 'john-jumbo'])
        elif plat == 'windows':
            if check_tool('winget'):
                try:
                    run_cmd(['winget', 'install', '--id', 'openwall.john',
                             '--accept-source-agreements', '--accept-package-agreements'])
                except subprocess.CalledProcessError:
                    pass
            if not (check_tool('john') or check_tool('john-the-ripper')):
                if check_tool('choco'):
                    run_cmd(['choco', 'install', 'johntheripper', '-y'])
                else:
                    _download_john_windows()
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"{C.RED}  [!] Failed to install John: {e}{C.RESET}")
        return False

    ok = check_tool('john') or check_tool('john-the-ripper')
    print(f"{C.GREEN}  [+] John installed.{C.RESET}" if ok
          else f"{C.RED}  [!] John installation could not be verified.{C.RESET}")
    return ok


def _download_hashcat_windows():
    """Download hashcat binary on Windows."""
    import json as _json
    install_dir = os.path.join(os.environ.get('LOCALAPPDATA', 'C:\\Tools'), 'hashcat')
    os.makedirs(install_dir, exist_ok=True)
    try:
        req = urllib.request.Request(
            'https://api.github.com/repos/hashcat/hashcat/releases/latest',
            headers={'User-Agent': 'HashCracker/2.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.loads(resp.read().decode())
        zip_url = None
        for asset in data.get('assets', []):
            n = asset['name']
            if (n.endswith('.7z') or n.endswith('.zip')) and 'source' not in n.lower():
                zip_url = asset['browser_download_url']
                break
        if not zip_url:
            print(f"{C.RED}  [!] Could not find hashcat download.{C.RESET}")
            return
        zip_path = os.path.join(install_dir, 'hashcat.zip')
        urllib.request.urlretrieve(zip_url, zip_path)
        if zip_path.endswith('.zip'):
            with zipfile.ZipFile(zip_path, 'r') as z:
                z.extractall(install_dir)
            os.unlink(zip_path)
        for root, dirs, files in os.walk(install_dir):
            if 'hashcat.exe' in files:
                os.environ['PATH'] = root + os.pathsep + os.environ['PATH']
                print(f"{C.GREEN}  [+] hashcat extracted to: {root}{C.RESET}")
                print(f"{C.YELLOW}  [*] Add to PATH permanently: {root}{C.RESET}")
                return
    except Exception as e:
        print(f"{C.RED}  [!] Download failed: {e}{C.RESET}")


def _download_john_windows():
    """Download John the Ripper on Windows."""
    import json as _json
    install_dir = os.path.join(os.environ.get('LOCALAPPDATA', 'C:\\Tools'), 'john')
    os.makedirs(install_dir, exist_ok=True)
    try:
        req = urllib.request.Request(
            'https://api.github.com/repos/openwall/john-packages/releases/latest',
            headers={'User-Agent': 'HashCracker/2.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.loads(resp.read().decode())
        zip_url = None
        for asset in data.get('assets', []):
            n = asset['name'].lower()
            if 'win' in n and n.endswith('.zip'):
                zip_url = asset['browser_download_url']
                break
        if not zip_url:
            print(f"{C.RED}  [!] Could not find John download.{C.RESET}")
            return
        zip_path = os.path.join(install_dir, 'john.zip')
        urllib.request.urlretrieve(zip_url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(install_dir)
        os.unlink(zip_path)
        for root, dirs, files in os.walk(install_dir):
            if 'john.exe' in files:
                os.environ['PATH'] = root + os.pathsep + os.environ['PATH']
                print(f"{C.GREEN}  [+] John extracted to: {root}{C.RESET}")
                print(f"{C.YELLOW}  [*] Add to PATH permanently: {root}{C.RESET}")
                return
    except Exception as e:
        print(f"{C.RED}  [!] Download failed: {e}{C.RESET}")


# ─── Wordlist Installation ────────────────────────────────────────────────────

def install_wordlists(plat, wordlist_dir=None):
    """Download and install common wordlists."""
    wl_dir = wordlist_dir or get_wordlist_dir(plat)

    print(f"\n{C.BOLD}{'─'*50}")
    print(" Wordlist Installation")
    print(f"{'─'*50}{C.RESET}")
    print(f"{C.CYAN}  [*] Wordlist directory: {wl_dir}{C.RESET}\n")

    # Create directory
    try:
        os.makedirs(wl_dir, exist_ok=True)
    except PermissionError:
        try:
            run_cmd(['sudo', 'mkdir', '-p', wl_dir])
            run_cmd(['sudo', 'chmod', '755', wl_dir])
        except (subprocess.CalledProcessError, OSError):
            wl_dir = os.path.join(os.path.expanduser('~'), '.hashcracker', 'wordlists')
            os.makedirs(wl_dir, exist_ok=True)
            print(f"{C.YELLOW}  [*] Using fallback: {wl_dir}{C.RESET}")

    installed = []
    for key, info in WORDLIST_SOURCES.items():
        dest = os.path.join(wl_dir, info['filename'])
        if os.path.exists(dest):
            size_mb = os.path.getsize(dest) / (1024 * 1024)
            print(f"{C.GREEN}  [+] {info['filename']} already exists ({size_mb:.1f} MB){C.RESET}")
            installed.append(dest)
            continue

        print(f"{C.YELLOW}  [*] Downloading {info['description']}...{C.RESET}")
        try:
            tmp_file = dest + '.tmp'
            try:
                _download_file(info['url'], tmp_file)
            except PermissionError:
                if plat in ('linux', 'macos'):
                    user_tmp = os.path.join(tempfile.gettempdir(), info['filename'])
                    _download_file(info['url'], user_tmp)
                    run_cmd(['sudo', 'mv', user_tmp, dest])
                    installed.append(dest)
                    continue
                raise
            os.rename(tmp_file, dest)
            size_mb = os.path.getsize(dest) / (1024 * 1024)
            print(f"{C.GREEN}  [+] Saved: {dest} ({size_mb:.1f} MB){C.RESET}")
            installed.append(dest)
        except Exception as e:
            print(f"{C.RED}  [!] Failed to download {info['filename']}: {e}{C.RESET}")
            tmp = dest + '.tmp'
            if os.path.exists(tmp):
                os.unlink(tmp)

    # Decompress rockyou.txt.gz if present
    gz_path = os.path.join(wl_dir, 'rockyou.txt.gz')
    txt_path = os.path.join(wl_dir, 'rockyou.txt')
    if os.path.exists(gz_path) and not os.path.exists(txt_path):
        print(f"{C.YELLOW}  [*] Decompressing rockyou.txt.gz...{C.RESET}")
        try:
            with gzip.open(gz_path, 'rb') as gz_in:
                with open(txt_path, 'wb') as f_out:
                    while True:
                        chunk = gz_in.read(8192)
                        if not chunk:
                            break
                        f_out.write(chunk)
            print(f"{C.GREEN}  [+] Decompressed: {txt_path}{C.RESET}")
            installed.append(txt_path)
        except Exception as e:
            print(f"{C.RED}  [!] Failed to decompress: {e}{C.RESET}")

    print(f"\n{C.GREEN}  [+] {len(installed)} wordlist(s) ready.{C.RESET}")
    return installed


def _download_file(url, dest):
    """Download a file with progress indication."""
    req = urllib.request.Request(url, headers={'User-Agent': 'HashCracker/2.0'})
    with urllib.request.urlopen(req, timeout=120) as resp:
        total = resp.headers.get('Content-Length')
        total = int(total) if total else None
        downloaded = 0
        with open(dest, 'wb') as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 / total
                    mb = downloaded / (1024 * 1024)
                    total_mb = total / (1024 * 1024)
                    print(f"\r{C.CYAN}      {mb:.1f}/{total_mb:.1f} MB ({pct:.0f}%){C.RESET}",
                          end='', flush=True)
        if total:
            print()


# ─── Full Setup ────────────────────────────────────────────────────────────────

def run_setup(wordlist_dir=None):
    """Run the full setup: install tools + wordlists."""
    plat = get_platform()

    print(f"""{C.CYAN}{C.BOLD}
    ╔═══════════════════════════════════════════════╗
    ║          HASH CRACKER v2.0 — SETUP            ║
    ║     Cross-Platform Dependency Installer       ║
    ╚═══════════════════════════════════════════════╝
    {C.RESET}""")

    print(f"{C.BOLD}  Platform:{C.RESET}  {platform.system()} {platform.release()}")
    print(f"{C.BOLD}  Arch:{C.RESET}      {platform.machine()}")
    if plat == 'linux':
        print(f"{C.BOLD}  Distro:{C.RESET}    {detect_linux_distro()}")
    print(f"{C.BOLD}  Python:{C.RESET}    {platform.python_version()}")
    print(f"{C.BOLD}  Elevated:{C.RESET}  {'Yes' if is_admin() else 'No'}")

    print(f"\n{C.BOLD}{'─'*50}")
    print(" Tool Installation")
    print(f"{'─'*50}{C.RESET}")

    hc_ok = install_hashcat(plat)
    john_ok = install_john(plat)
    wl_files = install_wordlists(plat, wordlist_dir)

    # Summary
    print(f"\n{C.BOLD}{'═'*50}")
    print(" Setup Summary")
    print(f"{'═'*50}{C.RESET}")

    hc_s = f"{C.GREEN}OK{C.RESET}" if check_tool('hashcat') else f"{C.RED}MISSING{C.RESET}"
    john_s = f"{C.GREEN}OK{C.RESET}" if (check_tool('john') or check_tool('john-the-ripper')) else f"{C.RED}MISSING{C.RESET}"
    print(f"  hashcat:          {hc_s}")
    print(f"  John the Ripper:  {john_s}")
    print(f"  Wordlists:        {len(wl_files)} installed")

    if wl_files:
        print(f"\n{C.CYAN}  Wordlist locations:{C.RESET}")
        for wl in wl_files:
            print(f"    - {wl}")

    if check_tool('hashcat') and (check_tool('john') or check_tool('john-the-ripper')):
        print(f"\n{C.GREEN}  [+] Setup complete! Ready to crack hashes.{C.RESET}")
    else:
        print(f"\n{C.YELLOW}  [!] Some tools could not be installed automatically.{C.RESET}")

    return hc_ok, john_ok, wl_files

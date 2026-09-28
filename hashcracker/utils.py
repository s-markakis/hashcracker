"""Shared utilities: command execution, platform detection, clipboard."""

import logging
import os
import platform
import shutil
import subprocess

from hashcracker.config import C

log = logging.getLogger('hashcracker')


def get_platform():
    """Detect the current OS platform."""
    system = platform.system().lower()
    if system == 'linux':
        return 'linux'
    elif system == 'darwin':
        return 'macos'
    elif system == 'windows':
        return 'windows'
    return system


def is_admin():
    """Check if running with elevated privileges."""
    if get_platform() == 'windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            log.debug('is_admin check failed: %s', e)
            return False
    else:
        return os.geteuid() == 0


def detect_linux_distro():
    """Detect the Linux distribution family."""
    try:
        with open('/etc/os-release') as f:
            content = f.read().lower()
        if any(d in content for d in ['ubuntu', 'debian', 'kali', 'parrot', 'mint', 'pop']):
            return 'debian'
        elif any(d in content for d in ['fedora', 'rhel', 'centos', 'rocky', 'alma']):
            return 'rhel'
        elif 'arch' in content or 'manjaro' in content:
            return 'arch'
        elif 'suse' in content or 'opensuse' in content:
            return 'suse'
    except FileNotFoundError:
        pass
    return 'unknown'


def check_tool(tool_name):
    """Check if a tool is available on the system."""
    return shutil.which(tool_name) is not None


def run_cmd(cmd, shell=False, check=True, capture=True):
    """Run a command and return the result."""
    print(f"{C.BLUE}  [>] {cmd if isinstance(cmd, str) else ' '.join(cmd)}{C.RESET}")
    try:
        result = subprocess.run(
            cmd, shell=shell, check=check,
            capture_output=capture, text=True, timeout=600,
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"{C.RED}  [!] Command failed: {e}{C.RESET}")
        if e.stderr:
            print(f"{C.RED}      {e.stderr.strip()}{C.RESET}")
        raise
    except FileNotFoundError:
        print(f"{C.RED}  [!] Command not found: {cmd}{C.RESET}")
        raise


def get_clipboard():
    """Read text from system clipboard. Returns None on failure."""
    plat = get_platform()
    commands = {
        'linux': [
            ['xclip', '-selection', 'clipboard', '-o'],
            ['xsel', '--clipboard', '--output'],
            ['wl-paste'],
        ],
        'macos': [['pbpaste']],
        'windows': [['powershell', '-command', 'Get-Clipboard']],
    }

    for cmd in commands.get(plat, []):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return None

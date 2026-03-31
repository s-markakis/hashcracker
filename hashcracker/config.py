"""Configuration management, color support, and defaults."""

import configparser
import os
import platform
import sys

CONFIG_DIR = os.path.join(os.path.expanduser('~'), '.hashcracker')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.ini')
RESULTS_LOG = os.path.join(CONFIG_DIR, 'results.log')
SESSIONS_DIR = os.path.join(CONFIG_DIR, 'sessions')

DEFAULTS = {
    'general': {
        'default_tool': 'both',
        'timeout': '300',
        'output_format': 'text',
        'auto_setup': 'true',
    },
    'wordlists': {
        'directory': '',
        'preferred_order': 'smallest_first',
    },
    'hashcat': {
        'extra_args': '',
        'rules_dir': '',
        'force_cpu': 'false',
    },
    'online': {
        'enabled': 'true',
        'timeout': '5',
    },
}


def _detect_color_support():
    """Detect whether the terminal supports ANSI colors."""
    if os.environ.get('NO_COLOR'):
        return False
    if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
        return False
    if platform.system() == 'Windows':
        # Windows Terminal and modern PowerShell support ANSI
        if os.environ.get('WT_SESSION') or os.environ.get('TERM_PROGRAM'):
            return True
        # Try to enable ANSI on Windows 10+
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True


class Colors:
    """ANSI color codes with auto-detection."""

    def __init__(self, enabled=None):
        if enabled is None:
            enabled = _detect_color_support()
        self.enabled = enabled
        self._set_codes()

    def _set_codes(self):
        if self.enabled:
            self.RED = '\033[91m'
            self.GREEN = '\033[92m'
            self.YELLOW = '\033[93m'
            self.BLUE = '\033[94m'
            self.MAGENTA = '\033[95m'
            self.CYAN = '\033[96m'
            self.BOLD = '\033[1m'
            self.DIM = '\033[2m'
            self.RESET = '\033[0m'
        else:
            self.RED = self.GREEN = self.YELLOW = self.BLUE = ''
            self.MAGENTA = self.CYAN = self.BOLD = self.DIM = self.RESET = ''


# Global colors instance
C = Colors()


class Config:
    """Load and manage configuration from ~/.hashcracker/config.ini"""

    def __init__(self):
        self._parser = configparser.ConfigParser()
        # Set defaults
        for section, values in DEFAULTS.items():
            self._parser[section] = values
        # Load from file if exists
        if os.path.exists(CONFIG_FILE):
            self._parser.read(CONFIG_FILE)

    def get(self, section, key, fallback=None):
        return self._parser.get(section, key, fallback=fallback)

    def getint(self, section, key, fallback=0):
        return self._parser.getint(section, key, fallback=fallback)

    def getboolean(self, section, key, fallback=False):
        return self._parser.getboolean(section, key, fallback=fallback)

    def save(self):
        """Save current config to file."""
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            self._parser.write(f)

    def set(self, section, key, value):
        if section not in self._parser:
            self._parser[section] = {}
        self._parser[section][key] = str(value)

    @property
    def default_tool(self):
        return self.get('general', 'default_tool', 'both')

    @property
    def timeout(self):
        return self.getint('general', 'timeout', 300)

    @property
    def output_format(self):
        return self.get('general', 'output_format', 'text')

    @property
    def auto_setup(self):
        return self.getboolean('general', 'auto_setup', True)

    @property
    def wordlist_dir(self):
        val = self.get('wordlists', 'directory', '')
        return val if val else None

    @property
    def online_enabled(self):
        return self.getboolean('online', 'enabled', True)

    @property
    def online_timeout(self):
        return self.getint('online', 'timeout', 5)

    @property
    def force_cpu(self):
        return self.getboolean('hashcat', 'force_cpu', False)

    @property
    def hashcat_extra_args(self):
        val = self.get('hashcat', 'extra_args', '')
        return val.split() if val else []


# Global config instance
cfg = Config()

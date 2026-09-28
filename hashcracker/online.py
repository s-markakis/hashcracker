"""Online hash lookup against free databases before local cracking."""

import logging
import re
import urllib.request
import urllib.parse

from hashcracker.config import C, cfg

log = logging.getLogger('hashcracker')

# Third-party services queried by online_lookup. Surfaced to the operator so
# they know where a hash is sent before any lookup happens.
ONLINE_SERVICES = ('hashtoolkit.com', 'nitrxgen.net')


def online_lookup(hash_string, timeout=None):
    """Try to find the hash in online databases.

    Returns the plaintext password if found, None otherwise.
    """
    if timeout is None:
        timeout = cfg.online_timeout

    # Only look up simple hex hashes (not structured hashes with prefixes)
    if not re.match(r'^[a-fA-F0-9]{16,128}$', hash_string):
        return None

    print(f"{C.CYAN}[*] Checking online databases "
          f"(sending hash to: {', '.join(ONLINE_SERVICES)})...{C.RESET}")

    result = _lookup_hashtoolkit(hash_string, timeout)
    if result:
        return result

    result = _lookup_nitrxgen(hash_string, timeout)
    if result:
        return result

    print(f"{C.DIM}    No results found online.{C.RESET}")
    return None


def _lookup_hashtoolkit(hash_string, timeout):
    """Query hashtoolkit.com API."""
    try:
        url = f'https://hashtoolkit.com/reverse-hash?hash={urllib.parse.quote(hash_string)}'
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; HashCracker/2.0)',
            'Accept': 'text/html',
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode('utf-8', errors='ignore')

        # Look for the plaintext in the response
        match = re.search(r'<span class="res-text">\s*([^<]+?)\s*</span>', html)
        if match:
            plaintext = match.group(1).strip()
            if plaintext and plaintext != hash_string:
                print(f"{C.GREEN}    [+] Found on hashtoolkit.com{C.RESET}")
                return plaintext
    except Exception as e:
        log.debug('hashtoolkit lookup failed: %s', e)
    return None


def _lookup_nitrxgen(hash_string, timeout):
    """Query nitrxgen.net API."""
    try:
        url = f'https://www.nitrxgen.net/md5db/{urllib.parse.quote(hash_string)}'
        req = urllib.request.Request(url, headers={
            'User-Agent': 'HashCracker/2.0',
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = resp.read().decode('utf-8', errors='ignore').strip()
        if result and result != hash_string and len(result) < 100:
            print(f"{C.GREEN}    [+] Found on nitrxgen.net{C.RESET}")
            return result
    except Exception as e:
        log.debug('nitrxgen lookup failed: %s', e)
    return None

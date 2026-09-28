"""Tests for the online lookup guard (no real network calls)."""
from unittest import mock

from hashcracker import online


def test_structured_hash_never_hits_network():
    """Non-hex/structured hashes must not trigger any HTTP request."""
    with mock.patch('urllib.request.urlopen') as urlopen:
        assert online.online_lookup('$2a$10$abcdefghijklmnopqrstuv') is None
        urlopen.assert_not_called()


def test_short_hex_rejected():
    with mock.patch('urllib.request.urlopen') as urlopen:
        assert online.online_lookup('abc123') is None
        urlopen.assert_not_called()


def test_valid_md5_attempts_lookup():
    """A 32-hex hash is eligible; both providers are queried when nothing hits."""
    with mock.patch.object(online, '_lookup_hashtoolkit', return_value=None) as ht, \
            mock.patch.object(online, '_lookup_nitrxgen', return_value=None) as nx:
        result = online.online_lookup('5f4dcc3b5aa765d61d8327deb882cf99', timeout=1)
        assert result is None
        ht.assert_called_once()
        nx.assert_called_once()


def test_first_provider_short_circuits():
    with mock.patch.object(online, '_lookup_hashtoolkit', return_value='password') as ht, \
            mock.patch.object(online, '_lookup_nitrxgen') as nx:
        result = online.online_lookup('5f4dcc3b5aa765d61d8327deb882cf99', timeout=1)
        assert result == 'password'
        ht.assert_called_once()
        nx.assert_not_called()

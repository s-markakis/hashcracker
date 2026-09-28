"""Tests for crack-output parsing (colon-safe password extraction)."""
from hashcracker.crack import _parse_hashcat_outfile, _parse_john_show


class TestHashcatOutfile:
    def test_simple_password(self):
        assert _parse_hashcat_outfile('password\n') == 'password'

    def test_password_with_colon(self):
        # --outfile-format 2 writes plaintext only, so colons are preserved.
        assert _parse_hashcat_outfile('foo:bar:baz\n') == 'foo:bar:baz'

    def test_empty(self):
        assert _parse_hashcat_outfile('') is None

    def test_blank_lines_skipped(self):
        assert _parse_hashcat_outfile('\n\nsecret\n') == 'secret'


class TestJohnShow:
    def test_simple(self):
        assert _parse_john_show('?:password\n') == 'password'

    def test_password_with_colon(self):
        assert _parse_john_show('admin:pa:ss:word\n') == 'pa:ss:word'

    def test_summary_line_ignored(self):
        out = '?:secret\n\n1 password hash cracked, 0 left\n'
        assert _parse_john_show(out) == 'secret'

    def test_nothing_cracked(self):
        assert _parse_john_show('0 password hashes cracked\n') is None

    def test_empty(self):
        assert _parse_john_show('') is None

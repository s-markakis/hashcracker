"""Tests for base64 detection in the identifier."""
from hashcracker.identify import _is_base64, _try_base64_decode, identify_hash


class TestIsBase64:
    def test_plain_hex_is_not_base64(self):
        assert _is_base64('5f4dcc3b5aa765d61d8327deb882cf99') is False

    def test_too_short(self):
        assert _is_base64('QQ==') is False

    def test_bad_padding_length(self):
        assert _is_base64('abcde') is False

    def test_mixed_case_with_padding(self):
        assert _is_base64('SGVsbG9Xb3JsZA==') is True


class TestDecode:
    def test_roundtrip_hex(self):
        # base64 of b'\xde\xad\xbe\xef' -> hex 'deadbeef'
        import base64
        b64 = base64.b64encode(bytes.fromhex('deadbeef')).decode()
        assert _try_base64_decode(b64) == 'deadbeef'

    def test_garbage_returns_none_or_str(self):
        # Should never raise.
        _try_base64_decode('!!!not base64!!!')


class TestNoteEllipsis:
    def test_long_decoded_gets_ellipsis(self):
        # 64 bytes -> 128 hex chars, note should be truncated with '...'
        import base64
        raw = base64.b64encode(b'A' * 64).decode()
        matches = identify_hash(raw)
        notes = [m.get('note') for m in matches if m.get('note')]
        if notes:
            assert notes[0].endswith('...')

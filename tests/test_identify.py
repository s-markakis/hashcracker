"""Tests for hash identification engine."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hashcracker.identify import identify_hash


class TestMD5:
    def test_md5_identified(self):
        matches = identify_hash('5f4dcc3b5aa765d61d8327deb882cf99')
        names = [m['name'] for m in matches]
        assert 'MD5' in names

    def test_md5_is_top_result(self):
        matches = identify_hash('5f4dcc3b5aa765d61d8327deb882cf99')
        assert matches[0]['name'] == 'MD5'

    def test_md5_hashcat_mode(self):
        matches = identify_hash('5f4dcc3b5aa765d61d8327deb882cf99')
        md5 = next(m for m in matches if m['name'] == 'MD5')
        assert md5['hashcat_mode'] == 0

    def test_md5_highest_confidence(self):
        matches = identify_hash('5f4dcc3b5aa765d61d8327deb882cf99')
        assert matches[0]['confidence'] > matches[-1]['confidence']


class TestSHA:
    def test_sha1(self):
        matches = identify_hash('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d')
        assert matches[0]['name'] == 'SHA-1'

    def test_sha256(self):
        h = '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
        matches = identify_hash(h)
        assert matches[0]['name'] == 'SHA-256'

    def test_sha512(self):
        h = 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86'
        matches = identify_hash(h)
        assert matches[0]['name'] == 'SHA-512'

    def test_sha224(self):
        h = 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'
        matches = identify_hash(h)
        assert matches[0]['name'] == 'SHA-224'

    def test_sha384(self):
        h = '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'
        matches = identify_hash(h)
        assert matches[0]['name'] == 'SHA-384'


class TestStructuredHashes:
    def test_bcrypt(self):
        h = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
        matches = identify_hash(h)
        assert matches[0]['name'] == 'bcrypt'
        assert matches[0]['confidence'] == 1.0

    def test_md5_crypt(self):
        h = '$1$etNnh7FA$OlM7eljE/B7F1J4XYNnk81'
        matches = identify_hash(h)
        assert matches[0]['name'] == 'MD5 Crypt (Unix)'

    def test_sha512_crypt(self):
        h = '$6$rounds=5000$saltsalt$' + 'a' * 86
        matches = identify_hash(h)
        assert matches[0]['name'] == 'SHA-512 Crypt (Unix)'

    def test_argon2(self):
        matches = identify_hash('$argon2id$v=19$m=65536')
        assert matches[0]['name'] == 'Argon2'

    def test_phpass_wordpress(self):
        matches = identify_hash('$P$BjKg5awEvqWMp3YMnQdP4RADmIGJxR0')
        assert matches[0]['name'] == 'phpass (WordPress)'

    def test_phpass_phpbb(self):
        matches = identify_hash('$H$BjKg5awEvqWMp3YMnQdP4RADmIGJxR0')
        assert matches[0]['name'] == 'phpass (phpBB3)'


class TestDatabaseHashes:
    def test_mysql5(self):
        matches = identify_hash('*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9')
        assert matches[0]['name'] == 'MySQL 5.x+'

    def test_postgresql_md5(self):
        matches = identify_hash('md5' + 'a' * 32)
        assert matches[0]['name'] == 'PostgreSQL MD5'

    def test_oracle_11g(self):
        matches = identify_hash('S:' + 'A' * 60)
        assert matches[0]['name'] == 'Oracle 11g (SHA1)'

    def test_mssql_2005(self):
        matches = identify_hash('0x0100' + 'A' * 88)
        assert matches[0]['name'] == 'MSSQL 2005'


class TestNetworkHashes:
    def test_kerberos_tgs(self):
        matches = identify_hash('$krb5tgs$23$something')
        assert matches[0]['name'] == 'Kerberos 5 TGS-REP'

    def test_kerberos_asrep(self):
        matches = identify_hash('$krb5asrep$23$something')
        assert matches[0]['name'] == 'Kerberos 5 AS-REP'

    def test_netntlmv2(self):
        h = 'user::domain:1234567890abcdef:' + 'a' * 32 + ':' + 'b' * 16
        matches = identify_hash(h)
        assert matches[0]['name'] == 'NetNTLMv2'

    def test_dcc2(self):
        h = '$DCC2$10240#admin#' + 'a' * 32
        matches = identify_hash(h)
        assert matches[0]['name'] == 'MS Cache v2 (DCC2)'


class TestCiscoHashes:
    def test_cisco_type8(self):
        matches = identify_hash('$8$salt$hash')
        assert matches[0]['name'] == 'Cisco IOS Type 8 (PBKDF2-SHA256)'

    def test_cisco_type9(self):
        matches = identify_hash('$9$salt$hash')
        assert matches[0]['name'] == 'Cisco IOS Type 9 (scrypt)'


class TestLDAPHashes:
    def test_ssha(self):
        matches = identify_hash('{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=')
        assert matches[0]['name'] == 'SSHA (LDAP)'

    def test_ldap_sha1(self):
        matches = identify_hash('{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=')
        assert matches[0]['name'] == 'LDAP SHA1'


class TestSaltedHashes:
    def test_md5_salt(self):
        matches = identify_hash('5f4dcc3b5aa765d61d8327deb882cf99:salt123')
        assert matches[0]['name'] == 'MD5:Salt'

    def test_salt_md5(self):
        matches = identify_hash('salt123:5f4dcc3b5aa765d61d8327deb882cf99')
        assert matches[0]['name'] == 'Salt:MD5'


class TestEdgeCases:
    def test_empty_string(self):
        matches = identify_hash('')
        assert matches == []

    def test_whitespace(self):
        matches = identify_hash('   5f4dcc3b5aa765d61d8327deb882cf99   ')
        assert matches[0]['name'] == 'MD5'

    def test_unknown_hash(self):
        matches = identify_hash('not_a_hash_at_all!!!')
        assert matches == []

    def test_results_sorted_by_confidence(self):
        matches = identify_hash('5f4dcc3b5aa765d61d8327deb882cf99')
        confidences = [m['confidence'] for m in matches]
        assert confidences == sorted(confidences, reverse=True)

    def test_all_matches_have_required_keys(self):
        matches = identify_hash('5f4dcc3b5aa765d61d8327deb882cf99')
        for m in matches:
            assert 'name' in m
            assert 'hashcat_mode' in m
            assert 'john_format' in m
            assert 'confidence' in m

"""Hash type signatures with confidence scoring and priority ranking."""

# Each entry: dict with keys:
#   pattern:      regex to match the hash string
#   name:         human-readable hash type name
#   hashcat_mode: hashcat -m mode number (None if unsupported)
#   john_format:  john --format= value (None if unsupported)
#   confidence:   0.0-1.0 likelihood when regex matches (higher = more likely)
#                 Structured hashes with unique prefixes get 1.0
#                 Length-only matches ranked by real-world frequency

HASH_SIGNATURES = [
    # ── MD5 family (32 hex chars — ambiguous) ──────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{32}$',
     'name': 'MD5', 'hashcat_mode': 0, 'john_format': 'Raw-MD5',
     'confidence': 0.95},
    {'pattern': r'^[a-fA-F0-9]{32}$',
     'name': 'NTLM', 'hashcat_mode': 1000, 'john_format': 'NT',
     'confidence': 0.70},
    {'pattern': r'^[a-fA-F0-9]{32}$',
     'name': 'MD4', 'hashcat_mode': 900, 'john_format': 'Raw-MD4',
     'confidence': 0.15},
    {'pattern': r'^[a-fA-F0-9]{32}$',
     'name': 'LM Hash', 'hashcat_mode': 3000, 'john_format': 'LM',
     'confidence': 0.10},

    # MD5 Crypt / APR1 (unique prefix → 1.0)
    {'pattern': r'^\$1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}$',
     'name': 'MD5 Crypt (Unix)', 'hashcat_mode': 500, 'john_format': 'md5crypt',
     'confidence': 1.0},
    {'pattern': r'^\$apr1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}$',
     'name': 'Apache APR1 MD5', 'hashcat_mode': 1600, 'john_format': 'md5crypt-opencl',
     'confidence': 1.0},

    # ── SHA-1 (40 hex chars — ambiguous) ───────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{40}$',
     'name': 'SHA-1', 'hashcat_mode': 100, 'john_format': 'Raw-SHA1',
     'confidence': 0.90},
    {'pattern': r'^[a-fA-F0-9]{40}$',
     'name': 'RIPEMD-160', 'hashcat_mode': 6000, 'john_format': 'ripemd-160',
     'confidence': 0.10},
    {'pattern': r'^\{SHA\}[a-zA-Z0-9+/]{27}=$',
     'name': 'LDAP SHA1', 'hashcat_mode': 101, 'john_format': 'nsldap',
     'confidence': 1.0},
    {'pattern': r'^\*[a-fA-F0-9]{40}$',
     'name': 'MySQL 5.x+', 'hashcat_mode': 300, 'john_format': 'mysql-sha1',
     'confidence': 1.0},

    # ── SHA-224 ────────────────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{56}$',
     'name': 'SHA-224', 'hashcat_mode': 1300, 'john_format': 'Raw-SHA224',
     'confidence': 0.85},

    # ── SHA-256 (64 hex chars) ─────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{64}$',
     'name': 'SHA-256', 'hashcat_mode': 1400, 'john_format': 'Raw-SHA256',
     'confidence': 0.90},
    {'pattern': r'^[a-fA-F0-9]{64}$',
     'name': 'SHA3-256', 'hashcat_mode': 17400, 'john_format': 'Raw-SHA3',
     'confidence': 0.10},
    {'pattern': r'^[a-fA-F0-9]{64}$',
     'name': 'Blake2b-256', 'hashcat_mode': 600, 'john_format': None,
     'confidence': 0.05},
    {'pattern': r'^\$5\$(rounds=\d+\$)?[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{43}$',
     'name': 'SHA-256 Crypt (Unix)', 'hashcat_mode': 7400, 'john_format': 'sha256crypt',
     'confidence': 1.0},

    # ── SHA-384 ────────────────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{96}$',
     'name': 'SHA-384', 'hashcat_mode': 10800, 'john_format': 'Raw-SHA384',
     'confidence': 0.85},
    {'pattern': r'^[a-fA-F0-9]{96}$',
     'name': 'SHA3-384', 'hashcat_mode': 17500, 'john_format': None,
     'confidence': 0.10},

    # ── SHA-512 (128 hex chars) ────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{128}$',
     'name': 'SHA-512', 'hashcat_mode': 1700, 'john_format': 'Raw-SHA512',
     'confidence': 0.85},
    {'pattern': r'^[a-fA-F0-9]{128}$',
     'name': 'SHA3-512', 'hashcat_mode': 17600, 'john_format': None,
     'confidence': 0.08},
    {'pattern': r'^[a-fA-F0-9]{128}$',
     'name': 'Whirlpool', 'hashcat_mode': 6100, 'john_format': 'whirlpool',
     'confidence': 0.05},
    {'pattern': r'^[a-fA-F0-9]{128}$',
     'name': 'Blake2b-512', 'hashcat_mode': 600, 'john_format': None,
     'confidence': 0.02},
    {'pattern': r'^\$6\$(rounds=\d+\$)?[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{86}$',
     'name': 'SHA-512 Crypt (Unix)', 'hashcat_mode': 1800, 'john_format': 'sha512crypt',
     'confidence': 1.0},

    # ── Bcrypt ─────────────────────────────────────────────────────────────────
    {'pattern': r'^\$2[aby]?\$\d{2}\$[a-zA-Z0-9./]{52,53}$',
     'name': 'bcrypt', 'hashcat_mode': 3200, 'john_format': 'bcrypt',
     'confidence': 1.0},

    # ── scrypt ─────────────────────────────────────────────────────────────────
    {'pattern': r'^\$s[12]\$\d+\$\d+\$\d+\$[a-zA-Z0-9+/]+\$[a-zA-Z0-9+/]+$',
     'name': 'scrypt', 'hashcat_mode': 8900, 'john_format': None,
     'confidence': 1.0},

    # ── Argon2 ─────────────────────────────────────────────────────────────────
    {'pattern': r'^\$argon2i[d]?\$',
     'name': 'Argon2', 'hashcat_mode': None, 'john_format': 'argon2',
     'confidence': 1.0},

    # ── MySQL ──────────────────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{16}$',
     'name': 'MySQL 3.x/4.x', 'hashcat_mode': 200, 'john_format': 'mysql',
     'confidence': 0.40},

    # ── CRC32 ──────────────────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{8}$',
     'name': 'CRC-32', 'hashcat_mode': None, 'john_format': None,
     'confidence': 0.50},

    # ── Salted hashes ──────────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]+$',
     'name': 'MD5:Salt', 'hashcat_mode': 10, 'john_format': 'dynamic_4',
     'confidence': 0.85},
    {'pattern': r'^[a-zA-Z0-9]+:[a-fA-F0-9]{32}$',
     'name': 'Salt:MD5', 'hashcat_mode': 20, 'john_format': 'dynamic_4',
     'confidence': 0.85},
    {'pattern': r'^[a-fA-F0-9]{40}:[a-zA-Z0-9]+$',
     'name': 'SHA1:Salt', 'hashcat_mode': 110, 'john_format': 'dynamic_24',
     'confidence': 0.85},
    {'pattern': r'^[a-fA-F0-9]{64}:[a-zA-Z0-9]+$',
     'name': 'SHA256:Salt', 'hashcat_mode': 1410, 'john_format': None,
     'confidence': 0.85},

    # ── Kerberos ───────────────────────────────────────────────────────────────
    {'pattern': r'^\$krb5tgs\$',
     'name': 'Kerberos 5 TGS-REP', 'hashcat_mode': 13100, 'john_format': 'krb5tgs',
     'confidence': 1.0},
    {'pattern': r'^\$krb5asrep\$',
     'name': 'Kerberos 5 AS-REP', 'hashcat_mode': 18200, 'john_format': 'krb5asrep',
     'confidence': 1.0},
    {'pattern': r'^\$krb5pa\$23\$',
     'name': 'Kerberos 5 Pre-Auth (RC4)', 'hashcat_mode': 7500, 'john_format': 'krb5pa-md5',
     'confidence': 1.0},

    # ── PBKDF2 / Django ────────────────────────────────────────────────────────
    {'pattern': r'^pbkdf2_sha256\$',
     'name': 'Django PBKDF2-SHA256', 'hashcat_mode': 10000, 'john_format': 'django',
     'confidence': 1.0},

    # ── NTLMv2 / NetNTLM ──────────────────────────────────────────────────────
    {'pattern': r'^[a-zA-Z0-9._-]+::\S+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$',
     'name': 'NetNTLMv2', 'hashcat_mode': 5600, 'john_format': 'netntlmv2',
     'confidence': 1.0},
    {'pattern': r'^[a-zA-Z0-9._-]+::\S+:[a-fA-F0-9]{48}:[a-fA-F0-9]{48}$',
     'name': 'NetNTLMv1', 'hashcat_mode': 5500, 'john_format': 'netntlm',
     'confidence': 1.0},

    # ── MS Cache / DCC2 ───────────────────────────────────────────────────────
    {'pattern': r'^\$DCC2\$\d+#[^#]+#[a-fA-F0-9]{32}$',
     'name': 'MS Cache v2 (DCC2)', 'hashcat_mode': 2100, 'john_format': 'mscash2',
     'confidence': 1.0},
    {'pattern': r'^[a-fA-F0-9]{32}:[a-zA-Z0-9._-]+$',
     'name': 'MS Cache v1 (DCC)', 'hashcat_mode': 1100, 'john_format': 'mscash',
     'confidence': 0.40},

    # ── Cisco ──────────────────────────────────────────────────────────────────
    {'pattern': r'^\$1\$[a-zA-Z0-9./]{4}\$[a-zA-Z0-9./]{22}$',
     'name': 'Cisco IOS MD5', 'hashcat_mode': 500, 'john_format': 'md5crypt',
     'confidence': 0.90},
    {'pattern': r'^[a-fA-F0-9]{4,}(\.[a-fA-F0-9]{4}){2,}$',
     'name': 'Cisco PIX MD5', 'hashcat_mode': 2400, 'john_format': 'pix-md5',
     'confidence': 0.80},
    {'pattern': r'^\$8\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$',
     'name': 'Cisco IOS Type 8 (PBKDF2-SHA256)', 'hashcat_mode': 9200, 'john_format': None,
     'confidence': 1.0},
    {'pattern': r'^\$9\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$',
     'name': 'Cisco IOS Type 9 (scrypt)', 'hashcat_mode': 9300, 'john_format': None,
     'confidence': 1.0},
    {'pattern': r'^[a-zA-Z0-9+/]{43}=$',
     'name': 'Cisco ASA MD5', 'hashcat_mode': 2410, 'john_format': None,
     'confidence': 0.30},

    # ── Oracle ─────────────────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{16}$',
     'name': 'Oracle 7-10g (DES)', 'hashcat_mode': 3100, 'john_format': 'oracle',
     'confidence': 0.20},
    {'pattern': r'^S:[a-fA-F0-9]{60}$',
     'name': 'Oracle 11g (SHA1)', 'hashcat_mode': 112, 'john_format': 'oracle11',
     'confidence': 1.0},
    {'pattern': r'^T:[a-fA-F0-9]{160}$',
     'name': 'Oracle 12c (SHA512)', 'hashcat_mode': 12300, 'john_format': 'oracle12c',
     'confidence': 1.0},

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    {'pattern': r'^md5[a-fA-F0-9]{32}$',
     'name': 'PostgreSQL MD5', 'hashcat_mode': 12, 'john_format': 'postgres',
     'confidence': 1.0},
    {'pattern': r'^SCRAM-SHA-256\$\d+:',
     'name': 'PostgreSQL SCRAM-SHA-256', 'hashcat_mode': 28600, 'john_format': None,
     'confidence': 1.0},

    # ── phpass (WordPress, phpBB, Joomla) ──────────────────────────────────────
    {'pattern': r'^\$P\$[a-zA-Z0-9./]{31}$',
     'name': 'phpass (WordPress)', 'hashcat_mode': 400, 'john_format': 'phpass',
     'confidence': 1.0},
    {'pattern': r'^\$H\$[a-zA-Z0-9./]{31}$',
     'name': 'phpass (phpBB3)', 'hashcat_mode': 400, 'john_format': 'phpass',
     'confidence': 1.0},

    # ── WPA/WPA2 ───────────────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:.*:[a-fA-F0-9]+$',
     'name': 'WPA/WPA2 PMKID', 'hashcat_mode': 22000, 'john_format': 'wpapsk',
     'confidence': 0.90},

    # ── SHA3 standalone ────────────────────────────────────────────────────────
    # SHA3-224 (56 hex chars, same as SHA-224)
    {'pattern': r'^[a-fA-F0-9]{56}$',
     'name': 'SHA3-224', 'hashcat_mode': 17300, 'john_format': None,
     'confidence': 0.10},

    # ── HMAC variants ──────────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{40}:[a-fA-F0-9]+$',
     'name': 'HMAC-SHA1', 'hashcat_mode': 160, 'john_format': 'hmac-sha1',
     'confidence': 0.30},
    {'pattern': r'^[a-fA-F0-9]{64}:[a-fA-F0-9]+$',
     'name': 'HMAC-SHA256', 'hashcat_mode': 1450, 'john_format': 'hmac-sha256',
     'confidence': 0.30},

    # ── SSHA (salted SHA for LDAP) ─────────────────────────────────────────────
    {'pattern': r'^\{SSHA\}[a-zA-Z0-9+/]+=*$',
     'name': 'SSHA (LDAP)', 'hashcat_mode': 111, 'john_format': 'nsldaps',
     'confidence': 1.0},
    {'pattern': r'^\{SSHA256\}[a-zA-Z0-9+/]+=*$',
     'name': 'SSHA-256 (LDAP)', 'hashcat_mode': 1411, 'john_format': None,
     'confidence': 1.0},
    {'pattern': r'^\{SSHA512\}[a-zA-Z0-9+/]+=*$',
     'name': 'SSHA-512 (LDAP)', 'hashcat_mode': 1711, 'john_format': 'ssha512',
     'confidence': 1.0},

    # ── Joomla / vBulletin ─────────────────────────────────────────────────────
    {'pattern': r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{32}$',
     'name': 'Joomla MD5', 'hashcat_mode': 11, 'john_format': None,
     'confidence': 0.50},
    {'pattern': r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{3}$',
     'name': 'vBulletin < v3.8.5', 'hashcat_mode': 2611, 'john_format': None,
     'confidence': 0.60},

    # ── MSSQL ──────────────────────────────────────────────────────────────────
    {'pattern': r'^0x0100[a-fA-F0-9]{88}$',
     'name': 'MSSQL 2005', 'hashcat_mode': 132, 'john_format': 'mssql05',
     'confidence': 1.0},
    {'pattern': r'^0x0200[a-fA-F0-9]{136}$',
     'name': 'MSSQL 2012+', 'hashcat_mode': 1731, 'john_format': 'mssql12',
     'confidence': 1.0},
]

"""Found data: identifiers recognised in the text of evidence files, each one validated so a random run of digits
is not reported as a card number.

Kinds and how a value is accepted:
  email     an address with a domain that has a dot and a 2-24 letter top-level label
  url       http, https or ftp with a host
  ip        IPv4, every part 0-255 (shown as private or public)
  phone     international format with a leading +, 8 to 15 digits
  card      13-19 digits of a known card brand's prefix and length that pass the Luhn check
  iban      the country's IBAN length and a valid mod-97 check
  crypto    Bitcoin (Base58Check P2PKH/P2SH, or Bech32/Bech32m bc1) and Ethereum (0x + 40 hex; a mixed-case
            address must pass its EIP-55 checksum)
  aadhaar   12 digits grouped 4-4-4, first digit 2-9, valid Verhoeff check digit

Card and Aadhaar numbers are sensitive: lists show them masked, and showing one in full is recorded in the
audit log.
"""
from __future__ import annotations
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

KINDS = ('email', 'url', 'ip', 'phone', 'card', 'iban', 'crypto', 'aadhaar')
SENSITIVE = {'card', 'aadhaar'}
LABELS = {'email': 'Email addresses', 'url': 'Web addresses', 'ip': 'IP addresses', 'phone': 'Phone numbers',
          'card': 'Card numbers', 'iban': 'Bank accounts (IBAN)', 'crypto': 'Cryptocurrency addresses', 'aadhaar': 'Aadhaar numbers'}

# ------------------------------------------------------------------ check digits
def luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


IBAN_LENGTHS = {
    'AD': 24, 'AE': 23, 'AL': 28, 'AT': 20, 'AZ': 28, 'BA': 20, 'BE': 16, 'BG': 22, 'BH': 22, 'BR': 29, 'BY': 28, 'CH': 21,
    'CR': 22, 'CY': 28, 'CZ': 24, 'DE': 22, 'DK': 18, 'DO': 28, 'EE': 20, 'EG': 29, 'ES': 24, 'FI': 18, 'FO': 18, 'FR': 27,
    'GB': 22, 'GE': 22, 'GI': 23, 'GL': 18, 'GR': 27, 'GT': 28, 'HR': 21, 'HU': 28, 'IE': 22, 'IL': 23, 'IQ': 23, 'IS': 26,
    'IT': 27, 'JO': 30, 'KW': 30, 'KZ': 20, 'LB': 28, 'LC': 32, 'LI': 21, 'LT': 20, 'LU': 20, 'LV': 21, 'LY': 25, 'MC': 27,
    'MD': 24, 'ME': 22, 'MK': 19, 'MR': 27, 'MT': 31, 'MU': 30, 'NL': 18, 'NO': 15, 'PK': 24, 'PL': 28, 'PS': 29, 'PT': 25,
    'QA': 29, 'RO': 24, 'RS': 22, 'SA': 24, 'SC': 31, 'SD': 18, 'SE': 24, 'SI': 19, 'SK': 24, 'SM': 27, 'ST': 25, 'SV': 28,
    'TL': 23, 'TN': 24, 'TR': 26, 'UA': 29, 'VA': 22, 'VG': 24, 'XK': 20,
}


def iban_valid(iban: str) -> bool:
    if IBAN_LENGTHS.get(iban[:2]) != len(iban) or not iban[2:4].isdigit():
        return False
    rearranged = iban[4:] + iban[:4]
    return int(''.join(str(int(c, 36)) for c in rearranged)) % 97 == 1


_VD = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
       [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
       [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VP = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
       [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return c == 0


# Keccak-256 (the original Keccak padding Ethereum uses, not NIST SHA3-256), for EIP-55 address checksums.
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _rol(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b'\x01'
    msg += b'\x00' * (-len(msg) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], 'little')
        a = _keccak_f(a)
    return b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(4))


def eip55(address_hex: str) -> str:
    """The EIP-55 mixed-case form of a 40-digit hex address (without 0x)."""
    lower = address_hex.lower()
    h = keccak256(lower.encode()).hex()
    return ''.join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(lower))


_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58check_valid(s: str) -> bool:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            return False
        n = n * 58 + i
    pad = len(s) - len(s.lstrip('1'))
    raw = b'\x00' * pad + (n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b'')
    return len(raw) == 25 and raw[0] in (0x00, 0x05) and hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


_BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def _polymod(values) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def bech32_valid(addr: str) -> bool:
    """A bc1 segwit address: Bech32 for witness version 0, Bech32m for later versions (BIP173/BIP350)."""
    if addr.lower() != addr and addr.upper() != addr:
        return False
    addr = addr.lower()
    if not addr.startswith('bc1') or not 14 <= len(addr) <= 74:
        return False
    data = [_BECH32.find(c) for c in addr[3:]]
    if min(data) < 0 or len(data) < 7:
        return False
    const = _polymod([3, 3, 0, 2, 3] + data)  # 'bc' expanded: [ord>>5]*2 + [0] + [ord&31]*2
    return (data[0] == 0 and const == 1) or (1 <= data[0] <= 16 and const == 0x2BC830A3)


# ------------------------------------------------------------------ card brands
_BRANDS = [  # (brand, prefix ranges as (low, high, digits of prefix), lengths)
    ('Visa', [(4, 4, 1)], {13, 16, 19}),
    ('Mastercard', [(51, 55, 2), (2221, 2720, 4)], {16}),
    ('American Express', [(34, 34, 2), (37, 37, 2)], {15}),
    ('Discover', [(6011, 6011, 4), (65, 65, 2), (644, 649, 3), (622126, 622925, 6)], {16, 17, 18, 19}),
    ('JCB', [(3528, 3589, 4)], {16, 17, 18, 19}),
    ('Diners Club', [(300, 305, 3), (36, 36, 2), (38, 39, 2)], {14, 15, 16, 17, 18, 19}),
    ('UnionPay', [(62, 62, 2)], {16, 17, 18, 19}),
]


def card_brand(digits: str) -> str | None:
    for brand, ranges, lengths in _BRANDS:
        if len(digits) in lengths and any(lo <= int(digits[:k]) <= hi for lo, hi, k in ranges):
            return brand
    return None


# ------------------------------------------------------------------ patterns
_EMAIL = re.compile(r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}\.[A-Za-z]{2,24}(?![A-Za-z0-9])')
_URL = re.compile(r'\b(?:https?|ftp)://[^\s<>"\'`\x00-\x1f\\^{}|]{3,2048}', re.I)
_IPV4 = re.compile(r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)')
_PHONE = re.compile(r'(?<![\w+])\+[1-9]\d{0,2}(?:[ .-]?\(\d{1,4}\))?(?:[ .-]?\d{1,5}){1,6}(?![\d])')
_CARD = re.compile(r'(?<![\d-])\d{4}(?:[ -]?\d{2,4}){2,4}(?:[ -]?\d{1,3})?(?![\d-])')
_IBAN = re.compile(r'(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])')
_BTC = re.compile(r'(?<![A-Za-z0-9])(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[02-9ac-hj-np-z]{11,71}|BC1[02-9AC-HJ-NP-Z]{11,71})(?![A-Za-z0-9])')
_ETH = re.compile(r'(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])')
_AADHAAR = re.compile(r'(?<![\d-])[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?![\d-])')
_TRAIL = '.,;:!?)]}\'"'


def _email(m):
    v = m.group()
    local, _, domain = v.rpartition('@')
    if local.startswith('.') or local.endswith('.') or '..' in v or any(not lab or lab[0] == '-' or lab[-1] == '-' for lab in domain.split('.')):
        return None
    return v.lower(), v, {}


def _url(m):
    v = m.group().rstrip(_TRAIL)
    try:
        parts = urlsplit(v)
    except ValueError:
        return None
    host = (parts.hostname or '')
    if not host or ('.' not in host and host != 'localhost'):
        return None
    key = f'{parts.scheme.lower()}://{parts.netloc.lower()}{v[len(parts.scheme) + 3 + len(parts.netloc):]}'
    return key, v, {'host': host.lower()}


def _ip(m):
    v = m.group()
    addr = ipaddress.ip_address(v)
    if addr.is_unspecified or addr.is_reserved:  # 240.0.0.0/4 also holds netmasks such as 255.255.255.0
        return None
    scope = 'loopback' if addr.is_loopback else 'private' if addr.is_private else 'public'
    return v, v, {'scope': scope}


def _phone(m):
    v = m.group()
    digits = re.sub(r'\D', '', v)
    if not 8 <= len(digits) <= 15:
        return None
    return '+' + digits, re.sub(r'\s+', ' ', v), {}


def _card(m):
    v = m.group()
    digits = re.sub(r'[ -]', '', v)
    if not 13 <= len(digits) <= 19 or not luhn(digits):
        return None
    brand = card_brand(digits)
    if not brand:
        return None
    return digits, f'{brand} •••• {digits[-4:]}', {'brand': brand, 'last4': digits[-4:]}


def _iban(m):
    v = m.group()
    iban = v.replace(' ', '')
    if not iban_valid(iban):
        return None
    return iban, ' '.join(iban[i:i + 4] for i in range(0, len(iban), 4)), {'country': iban[:2]}


def _btc(m):
    v = m.group()
    if v[0] in '13':
        return (v, v, {'network': 'Bitcoin'}) if base58check_valid(v) else None
    return (v.lower(), v, {'network': 'Bitcoin'}) if bech32_valid(v) else None


def _eth(m):
    v = m.group()
    body = v[2:]
    mixed = body.lower() != body and body.upper() != body
    if mixed and eip55(body) != body:
        return None
    return '0x' + body.lower(), v, {'network': 'Ethereum', 'checksum': 'valid' if mixed else 'none'}


def _aadhaar(m):
    v = m.group()
    digits = re.sub(r'\D', '', v)
    if not verhoeff(digits):
        return None
    return digits, f'•••• •••• {digits[-4:]}', {'last4': digits[-4:]}


EXTRACTORS = [('email', _EMAIL, _email), ('url', _URL, _url), ('ip', _IPV4, _ip), ('phone', _PHONE, _phone),
              ('card', _CARD, _card), ('iban', _IBAN, _iban), ('crypto', _BTC, _btc), ('crypto', _ETH, _eth),
              ('aadhaar', _AADHAAR, _aadhaar)]


def find_all(text: str):
    """(kind, value, display, details, start, end) for every validated identifier in a text."""
    for kind, rx, accept in EXTRACTORS:
        for m in rx.finditer(text):
            try:
                found = accept(m)
            except (ValueError, OverflowError):
                found = None
            if found:
                value, display, details = found
                end = m.start() + len(display) if kind == 'url' else m.end()
                yield kind, value, display, details, m.start(), end


def key_of(kind: str, value: str) -> str:
    return hashlib.sha256(f'{kind}:{value}'.encode()).hexdigest()[:32]

"""Found data: each kind's validation against published test vectors, and what is not reported."""
import pytest

from app.forensic.found_data import (base58check_valid, bech32_valid, card_brand, eip55, find_all, iban_valid, keccak256, key_of,
                                     luhn, verhoeff)


def test_keccak256_and_eip55_vectors():
    assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    assert keccak256(b'abc').hex() == '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    for addr in ('5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', 'fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
                 'dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', 'D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb'):
        assert eip55(addr.lower()) == addr  # the EIP-55 specification's examples


def test_check_digit_algorithms():
    assert luhn('4111111111111111') and luhn('378282246310005') and not luhn('4111111111111112')
    assert verhoeff('2363') and verhoeff('1428570') and not verhoeff('2364')
    assert verhoeff('234567890124') and not verhoeff('234567890125')
    assert iban_valid('DE89370400440532013000') and iban_valid('GB82WEST12345698765432') and not iban_valid('GB82WEST12345698765433')
    assert not iban_valid('DE8937040044053201300')  # one digit short for Germany
    assert base58check_valid('1BoatSLRHtKNngkdXEeobR76b53LETtpyT') and base58check_valid('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')
    assert not base58check_valid('1BoatSLRHtKNngkdXEeobR76b53LETtpyU')
    assert bech32_valid('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4') and bech32_valid('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4')
    assert bech32_valid('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0')  # Bech32m (taproot)
    assert not bech32_valid('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5')
    assert card_brand('4111111111111111') == 'Visa' and card_brand('5555555555554444') == 'Mastercard'
    assert card_brand('378282246310005') == 'American Express' and card_brand('6011111111111117') == 'Discover'
    assert card_brand('9111111111111111') is None


TEXT = """Personal contacts
Zoë Martin <zoe.martin@example.org>, +44 20 7946 0958, alice.personal@example.net.
Bank: GB82 WEST 1234 5698 7654 32 (personal). Old account DE89370400440532013001.
Card on file: 4111 1111 1111 1111. Typo: 4111 1111 1111 1112. Amex 378282246310005.
Aadhaar 2345 6789 0124 (not 2345 6789 0125).
BTC 1BoatSLRHtKNngkdXEeobR76b53LETtpyT, bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 and 1BoatSLRHtKNngkdXEeobR76b53LETtpyU.
ETH 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed (bad: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD).
Server 10.20.30.40, public 8.8.8.8, version 1.2.3.4.5, see https://intranet.corp.example/hr/payroll).
"""


def _found(text=TEXT):
    out = {}
    for kind, value, display, details, start, end in find_all(text):
        out.setdefault(kind, []).append((value, display, details, text[start:end]))
    return out


def test_every_kind_is_found_and_only_valid_values():
    f = _found()
    assert [v for v, *_ in f['email']] == ['zoe.martin@example.org', 'alice.personal@example.net']
    assert [v for v, *_ in f['phone']] == ['+442079460958']
    assert [v for v, *_ in f['iban']] == ['GB82WEST12345698765432']  # the DE one fails its check digits
    assert [(v, d) for v, d, *_ in f['card']] == [('4111111111111111', 'Visa •••• 1111'), ('378282246310005', 'American Express •••• 0005')]
    assert [(v, d) for v, d, *_ in f['aadhaar']] == [('234567890124', '•••• •••• 0124')]
    assert [v for v, *_ in f['crypto']] == ['1BoatSLRHtKNngkdXEeobR76b53LETtpyT', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
                                            '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed']
    assert {v: d['scope'] for v, _, d, _ in f['ip']} == {'10.20.30.40': 'private', '8.8.8.8': 'public'}  # not the 5-part version
    assert [(v, raw) for v, _, _, raw in f['url']] == [('https://intranet.corp.example/hr/payroll', 'https://intranet.corp.example/hr/payroll')]


def test_payroll_export_has_one_valid_iban_of_sixty():
    payroll = ''.join(f'emp{i:03d},DE89370400440532013{i:03d},{50000 + i * 1000}\n' for i in range(60))
    assert [v for v, *_ in _found(payroll).get('iban', [])] == ['DE89370400440532013000']
    assert 'card' not in _found(payroll)  # 20-digit runs are not card numbers


def test_positions_cover_the_text_as_found():
    for kind, value, display, details, start, end in find_all('mail ZOE@Example.ORG now'):
        assert (kind, value, 'mail ZOE@Example.ORG now'[start:end]) == ('email', 'zoe@example.org', 'ZOE@Example.ORG')


@pytest.mark.parametrize('text', ['x@y', 'a..b@example.com', '+1 23', '1234 5678 9012 3456', 'FR00 0000 0000 0000 0000 0000 000',
                                  '0x123', '999.1.1.1', 'http://nohost', 'mask 255.255.255.0', '0.0.0.0'])
def test_lookalikes_are_not_reported(text):
    assert not list(find_all(text))


def test_keys_are_stable():
    assert key_of('email', 'a@b.cd') == key_of('email', 'a@b.cd') != key_of('url', 'a@b.cd') and len(key_of('ip', '1.2.3.4')) == 32

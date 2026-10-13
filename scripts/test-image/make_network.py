"""A network capture for the scenario (written with scapy): on 1 September 2026 the laptop (192.168.1.57) looks up
filetransfer.example.net, uploads payroll-export.csv to it over plain HTTP (14:20:02 UTC), fetches the site's logo,
looks up pastebin.com and opens a TLS connection to it (server name in the ClientHello). TCP sequence numbers are
consistent, so Wireshark reassembles both HTTP exchanges.

Usage: make_network.py OUT.pcap OUT-expected.json. Every value the tests check is written to the JSON file.
"""
import hashlib
import json
import struct
import sys
from datetime import datetime, timezone

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

PAYROLL = ('employee,iban,salary\n' + ''.join(f'emp{i:03d},DE89370400440532013{i:03d},{50000 + i * 1000}\n' for i in range(60))).encode()
LAPTOP, ROUTER = '192.168.1.57', '192.168.1.1'
FILE_HOST, FILE_IP = 'filetransfer.example.net', '203.0.113.80'
PASTE_HOST, PASTE_IP = 'pastebin.com', '203.0.113.81'
MAC_L, MAC_R = '00:1a:2b:3c:4d:5e', '00:11:22:33:44:55'
PNG = bytes.fromhex('89504e470d0a1a0a0000000d4948445200000001000000010806000000'
                    '1f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a4be0000000049454e44ae426082')


def at(h, m, s, us=0):
    return datetime(2026, 9, 1, h, m, s, us, tzinfo=timezone.utc).timestamp()


packets = []


def add(pkt, t):
    pkt.time = t
    packets.append(pkt)


def eth(src, dst):
    return Ether(src=MAC_L if src == LAPTOP else MAC_R, dst=MAC_R if src == LAPTOP else MAC_L)


def dns(t, sport, name, ip, txid):
    q = eth(LAPTOP, ROUTER) / IP(src=LAPTOP, dst=ROUTER) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=name))
    r = eth(ROUTER, LAPTOP) / IP(src=ROUTER, dst=LAPTOP) / UDP(sport=53, dport=sport) / DNS(
        id=txid, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type='A', ttl=300, rdata=ip))
    add(q, t)
    add(r, t + 0.012)


class Tcp:
    """One TCP connection with consistent sequence numbers."""

    def __init__(self, client, sport, server, dport, t):
        self.c, self.s, self.sp, self.dp, self.t = client, server, sport, dport, t
        self.last_data = None  # when the last data segment was sent (Wireshark reports a request once it is complete)
        self.cseq, self.sseq = 1000, 50000
        self._send(self.c, 'S', b'', syn=True)
        self._send(self.s, 'SA', b'', syn=True)
        self._send(self.c, 'A', b'')

    def _send(self, src, flags, data, syn=False):
        client = src == self.c
        ip = IP(src=src, dst=self.s if client else self.c)
        tcp = TCP(sport=self.sp if client else self.dp, dport=self.dp if client else self.sp, flags=flags,
                  seq=self.cseq if client else self.sseq, ack=(self.sseq if client else self.cseq) if 'A' in flags else 0, window=64240)
        add(eth(src, ip.dst) / ip / tcp / Raw(data) if data else eth(src, ip.dst) / ip / tcp, self.t)
        if data:
            self.last_data = self.t
        self.t += 0.004
        n = len(data) + (1 if syn or 'F' in flags else 0)
        if client:
            self.cseq += n
        else:
            self.sseq += n

    def send(self, client: bool, data: bytes, mss=1400):
        for i in range(0, len(data), mss):
            self._send(self.c if client else self.s, 'PA', data[i:i + mss])
            self._send(self.s if client else self.c, 'A', b'')

    def close(self):
        self._send(self.c, 'FA', b'')
        self._send(self.s, 'FA', b'')
        self._send(self.c, 'A', b'')


def client_hello(server_name: str) -> bytes:
    """A TLS 1.2 ClientHello with the server name extension (enough for Wireshark to dissect it)."""
    sni = server_name.encode()
    sni_ext = struct.pack('>HHHBH', 0x0000, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    ciphers = struct.pack('>H', 4) + bytes.fromhex('c02fc030')
    body = b'\x03\x03' + bytes(range(32)) + b'\x00' + ciphers + b'\x01\x00' + struct.pack('>H', len(sni_ext)) + sni_ext
    hs = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs


def main(out_pcap, out_json):
    dns(at(14, 20, 1), 53001, FILE_HOST, FILE_IP, 0x1a2b)
    boundary = '----dfipBoundary7Hq2xK'
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="payroll-export.csv"\r\nContent-Type: text/csv\r\n\r\n').encode() \
        + PAYROLL + f'\r\n--{boundary}--\r\n'.encode()
    up = Tcp(LAPTOP, 49812, FILE_IP, 80, at(14, 20, 2))
    up.send(True, (f'POST /upload HTTP/1.1\r\nHost: {FILE_HOST}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0\r\n'
                   f'Content-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {len(body)}\r\n\r\n').encode() + body)
    post_time = up.last_data
    reply = b'{"status":"ok","link":"https://filetransfer.example.net/d/7Hq2xK"}'
    up.send(False, b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(reply)).encode() + b'\r\n\r\n' + reply)
    up.close()
    logo = Tcp(LAPTOP, 49813, FILE_IP, 80, at(14, 20, 5))
    logo.send(True, f'GET /assets/logo.png HTTP/1.1\r\nHost: {FILE_HOST}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0\r\n\r\n'.encode())
    get_time = logo.last_data
    logo.send(False, b'HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: ' + str(len(PNG)).encode() + b'\r\n\r\n' + PNG)
    logo.close()
    dns(at(14, 22, 30), 53002, PASTE_HOST, PASTE_IP, 0x3c4d)
    tls = Tcp(LAPTOP, 49820, PASTE_IP, 443, at(14, 22, 31))
    tls.send(True, client_hello(PASTE_HOST))
    tls.close()
    packets.sort(key=lambda p: p.time)
    wrpcap(out_pcap, packets)
    expected = {
        'packets': len(packets), 'first': datetime.fromtimestamp(packets[0].time, timezone.utc).isoformat(),
        'last': datetime.fromtimestamp(packets[-1].time, timezone.utc).isoformat(),
        'dns': [{'name': FILE_HOST, 'answer': FILE_IP, 'time': datetime.fromtimestamp(at(14, 20, 1), timezone.utc).isoformat()},
                {'name': PASTE_HOST, 'answer': PASTE_IP, 'time': datetime.fromtimestamp(at(14, 22, 30), timezone.utc).isoformat()}],
        'http': [{'method': 'POST', 'host': FILE_HOST, 'uri': '/upload', 'time': datetime.fromtimestamp(post_time, timezone.utc).isoformat()},
                 {'method': 'GET', 'host': FILE_HOST, 'uri': '/assets/logo.png', 'time': datetime.fromtimestamp(get_time, timezone.utc).isoformat()}],
        'sni': [{'server_name': PASTE_HOST, 'ip': PASTE_IP, 'port': 443}],
        'payroll_sha256': hashlib.sha256(PAYROLL).hexdigest(), 'png_sha256': hashlib.sha256(PNG).hexdigest(),
        'conversations': [{'a': LAPTOP, 'b': ROUTER, 'proto': 'UDP'}, {'a': LAPTOP, 'b': FILE_IP, 'proto': 'TCP'}, {'a': LAPTOP, 'b': PASTE_IP, 'proto': 'TCP'}],
    }
    with open(out_json, 'w') as f:
        json.dump(expected, f, indent=1)
    print('Built', out_pcap, len(packets), 'packets')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

"""A test certificate authority and an RFC 3161 timestamp authority for signed-report tests.

make_pki(dir) writes ca.crt (the root), org.p12 (an organisation signing certificate issued by it, password
ORG_P12_PASSWORD), tsa.crt/tsa.key (a timestamping certificate issued by it: extendedKeyUsage timeStamping, critical) and
the `openssl ts` configuration. TsaServer answers timestamp queries over HTTP with `openssl ts -reply`, so the
timestamps come from OpenSSL, not from pyHanko which signs and checks them."""
from __future__ import annotations
import datetime as dt
import http.server
import subprocess
import tempfile
import threading
from pathlib import Path

ORG_P12_PASSWORD = 'org-test-pass'
TS_CONF = """[ tsa ]
default_tsa = tsa_config1

[ tsa_config1 ]
dir = {dir}
serial = $dir/tsa-serial
crypto_device = builtin
signer_cert = $dir/tsa.crt
certs = $dir/ca.crt
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


def make_pki(d: Path) -> Path:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    d = Path(d)
    d.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'DFIP Test Lab')])

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def usage(**on):
        flags = dict(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False,
                     key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
        flags.update(on)
        return x509.KeyUsage(**flags)

    ca_key = key()
    ca = (x509.CertificateBuilder().subject_name(name('DFIP Test Root CA')).issuer_name(name('DFIP Test Root CA'))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(usage(key_cert_sign=True, crl_sign=True), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))

    def issue(cn, k, ku, eku, eku_critical):
        b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject).public_key(k.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(days=90))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(ku, critical=True)
             .add_extension(x509.ExtendedKeyUsage(eku), critical=eku_critical)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
        return b.sign(ca_key, hashes.SHA256())

    org_key, tsa_key = key(), key()
    org = issue('DFIP Test Lab report signing', org_key, usage(digital_signature=True, content_commitment=True),
                [ExtendedKeyUsageOID.EMAIL_PROTECTION], False)
    tsa = issue('DFIP Test TSA', tsa_key, usage(digital_signature=True, content_commitment=True), [ExtendedKeyUsageOID.TIME_STAMPING], True)
    pem = serialization.Encoding.PEM
    (d / 'ca.crt').write_bytes(ca.public_bytes(pem))
    (d / 'tsa.crt').write_bytes(tsa.public_bytes(pem))
    (d / 'tsa.key').write_bytes(tsa_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (d / 'org.p12').write_bytes(pkcs12.serialize_key_and_certificates(b'org', org_key, org, [ca],
                                                                      serialization.BestAvailableEncryption(ORG_P12_PASSWORD.encode())))
    (d / 'tsa-serial').write_text('01\n')
    (d / 'ts.cnf').write_text(TS_CONF.format(dir=d))
    return d


class TsaServer:
    """`openssl ts -reply` behind HTTP POST (application/timestamp-query), on 127.0.0.1 or any address; counts requests."""

    def __init__(self, pki: Path, host: str = '127.0.0.1', port: int = 0):
        self.pki, self.requests = Path(pki), 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
                outer.requests += 1
                with tempfile.TemporaryDirectory() as t:
                    (Path(t) / 'q.tsq').write_bytes(body)
                    r = subprocess.run(['openssl', 'ts', '-reply', '-config', str(outer.pki / 'ts.cnf'), '-queryfile', f'{t}/q.tsq',
                                        '-out', f'{t}/r.tsr'], capture_output=True, timeout=30)
                    reply = (Path(t) / 'r.tsr').read_bytes() if r.returncode == 0 else b''
                self.send_response(200 if reply else 500)
                self.send_header('Content-Type', 'application/timestamp-reply')
                self.send_header('Content-Length', str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *a):
                pass
        self.httpd = http.server.ThreadingHTTPServer((host, port), Handler)
        self.url = f'http://127.0.0.1:{self.httpd.server_address[1]}/tsa'

    def start(self) -> 'TsaServer':
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.httpd.shutdown()

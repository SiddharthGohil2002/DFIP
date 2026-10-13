"""Signed report PDFs (PAdES, with pyHanko): every report PDF is signed when it is generated, with the organisation's
certificate (REPORT_SIGNING_P12 and its password) or, without one, with a self-signed certificate DFIP makes once (its
key kept encrypted under DATA_ENCRYPTION_KEY) and which verification reports as not trusted. With REPORT_TSA_URL the
signature carries an RFC 3161 timestamp from that authority (PAdES-B-T); without one it is PAdES-B-B.

Verification checks that the signature is intact and covers the whole file (nothing was changed or added after
signing), who signed and whether that certificate chains to a trusted root (REPORT_TRUST_ROOTS), and the timestamp
(REPORT_TSA_TRUST_ROOTS).
"""
from __future__ import annotations
import base64
import datetime as dt
import io
from pathlib import Path

from ..core.config import settings

SELF_SIGNED_CN = 'DFIP report signing (self-signed)'


def _name(cert) -> str:
    """A certificate's subject as people read it: its common name and organisation."""
    n = cert.subject.native
    parts = [n.get(k) for k in ('common_name', 'organization_name') if isinstance(n.get(k), str)]
    return ', '.join(parts) or cert.subject.human_friendly


def _store() -> Path:
    return Path(settings.storage_path).resolve() / 'signing'


def _self_signed() -> tuple[bytes, bytes]:
    """The self-signed PKCS#12 (made once) and its passphrase, derived from DATA_ENCRYPTION_KEY (or JWT_SECRET)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    material = (settings.data_encryption_key or settings.jwt_secret).encode()
    passphrase = base64.urlsafe_b64encode(HKDF(algorithm=hashes.SHA256(), length=32, salt=b'dfip-report-signing', info=b'p12 v1').derive(material))
    path = _store() / 'self-signed.p12'
    if path.is_file():
        return path.read_bytes(), passphrase
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SELF_SIGNED_CN), x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'DFIP')])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
            .sign(key, hashes.SHA256()))
    data = pkcs12.serialize_key_and_certificates(b'dfip-report-signing', key, cert, None,
                                                 serialization.BestAvailableEncryption(passphrase))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)
    return data, passphrase


def _signer():
    from pyhanko.sign import signers
    if settings.report_signing_p12:
        return signers.SimpleSigner.load_pkcs12(settings.report_signing_p12, passphrase=(settings.report_signing_p12_password or '').encode() or None), False
    data, passphrase = _self_signed()
    tmp = _store() / '.signer.p12'
    tmp.write_bytes(data)
    tmp.chmod(0o600)
    try:
        return signers.SimpleSigner.load_pkcs12(str(tmp), passphrase=passphrase), True
    finally:
        tmp.unlink(missing_ok=True)


def sign(pdf: bytes, report_id: str, location: str | None = None) -> tuple[bytes, dict]:
    """The PDF signed (and timestamped when a TSA is configured), and what was done."""
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers, timestamps
    from pyhanko.sign.fields import SigSeedSubFilter
    signer, self_signed = _signer()
    meta = signers.PdfSignatureMetadata(field_name='DFIPReportSignature', md_algorithm='sha256', subfilter=SigSeedSubFilter.PADES,
                                        reason=f'DFIP case report {report_id}: this signature seals the report as generated',
                                        location=location or None, name=_name(signer.signing_cert))
    info = {'signed': True, 'self_signed': self_signed, 'signer': _name(signer.signing_cert), 'level': 'PAdES-B-B',
            'timestamped': False, 'tsa_url': settings.report_tsa_url or None, 'timestamp_error': None,
            'signed_at': dt.datetime.now(dt.timezone.utc).isoformat()}
    tst = timestamps.HTTPTimeStamper(settings.report_tsa_url, timeout=20) if settings.report_tsa_url else None
    for attempt in ((tst,) if tst else ()) + (None,):
        try:
            out = io.BytesIO()
            signers.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(pdf)), meta, signer=signer, timestamper=attempt, output=out)
            info.update(timestamped=attempt is not None, level='PAdES-B-T' if attempt is not None else 'PAdES-B-B')
            return out.getvalue(), info
        except Exception as exc:  # the timestamp authority is unreachable or refused: sign without a timestamp, and say so
            if attempt is None:
                raise
            info['timestamp_error'] = f'{type(exc).__name__}: {exc}'[:500]
    raise RuntimeError('unreachable')


def _roots(path: str | None) -> list:
    from asn1crypto import pem, x509 as asn1_x509
    if not path or not Path(path).is_file():
        return []
    out = []
    for _, _, der in pem.unarmor(Path(path).read_bytes(), multiple=True):
        out.append(asn1_x509.Certificate.load(der))
    return out


def verify(pdf: bytes) -> dict:
    """Every signature in a PDF, checked: intact, covering the whole file, the signer and whether it is trusted, the timestamp."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.general import SigningError
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    try:
        reader = PdfFileReader(io.BytesIO(pdf), strict=False)
        sigs = list(reader.embedded_signatures)
    except Exception as exc:
        return {'valid': False, 'signatures': [], 'error': f'Not a readable PDF: {exc}'[:300]}
    if not sigs:
        return {'valid': False, 'signatures': [], 'error': 'The PDF is not signed'}
    import logging
    for name in ('pyhanko', 'pyhanko_certvalidator'):  # an untrusted (self-signed) signer is reported below, not logged as an error
        logging.getLogger(name).setLevel(logging.CRITICAL)
    signer_ctx = ValidationContext(trust_roots=_roots(settings.report_trust_roots), allow_fetching=False)
    ts_ctx = ValidationContext(trust_roots=_roots(settings.report_tsa_trust_roots), allow_fetching=False)
    out = []
    for s in sigs:
        try:
            st = validate_pdf_signature(s, signer_validation_context=signer_ctx, ts_validation_context=ts_ctx)
        except (SigningError, ValueError, KeyError) as exc:
            out.append({'field': s.field_name, 'intact': False, 'error': f'{type(exc).__name__}: {exc}'[:300]})
            continue
        ts = st.timestamp_validity
        out.append({'field': s.field_name, 'intact': bool(st.intact), 'cryptographically_valid': bool(st.valid),
                    'covers_whole_file': str(st.coverage.name) == 'ENTIRE_FILE', 'coverage': st.coverage.name,
                    'modification_level': getattr(st.modification_level, 'name', None), 'trusted': bool(st.trusted),
                    'signer': _name(st.signing_cert), 'self_signed': SELF_SIGNED_CN in _name(st.signing_cert),
                    'signing_time': st.signer_reported_dt.isoformat() if st.signer_reported_dt else None,
                    'timestamp': None if ts is None else {'time': ts.timestamp.isoformat(), 'intact': bool(ts.intact), 'valid': bool(ts.valid),
                                                          'trusted': bool(ts.trusted)},
                    'bottom_line': bool(st.bottom_line)})
    ok = all(x.get('intact') and x.get('cryptographically_valid') and x.get('covers_whole_file') for x in out)
    error = None
    if not ok:
        error = ('The file was changed after it was signed' if any(x.get('intact') and not x.get('covers_whole_file') for x in out)
                 else 'A signature is broken or does not match the file')
    return {'valid': ok, 'signatures': out, 'error': error}

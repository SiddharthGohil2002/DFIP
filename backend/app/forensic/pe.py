"""Windows programs (PE files): structure, version information, signature and what stands out.

pefile reads the headers, sections (with their entropy), imports, version information and debug path; signify checks the
Authenticode signature against Microsoft's trusted roots (mscerts, with the roots signify can't read left out: post-quantum
TLS pilot roots, not used for code signing); capa (Mandiant) lists capabilities, with ATT&CK techniques, for programs
that stand out. Nothing here runs the program.

What stands out is a lead, not a verdict: packers, a name that differs from the one the program was built with, a
system program's name outside the Windows folders, a Microsoft claim without a valid Microsoft signature, and imports
in groups that wipers, injectors, keyloggers and downloaders use.
"""
from __future__ import annotations
import io
import json
import re
from datetime import datetime, timezone

MAX_BYTES = 128 << 20
CAPA_TIMEOUT = 600
SYSTEM_BINARIES = {'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'explorer.exe', 'spoolsv.exe',
                   'taskhost.exe', 'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'rundll32.exe', 'wininit.exe', 'lsm.exe', 'userinit.exe',
                   'ctfmon.exe', 'dwm.exe', 'sihost.exe', 'runtimebroker.exe', 'searchindexer.exe', 'wuauclt.exe', 'msiexec.exe'}
SYSTEM_FOLDERS = re.compile(r'^/Windows/(System32|SysWOW64|WinSxS|servicing|Microsoft\.NET)/|^/Windows/[^/]+\.exe$', re.I)
USER_FOLDERS = re.compile(r'^/(Users|Documents and Settings)/[^/]+/(AppData|Local Settings|Downloads|Desktop)/|^/(ProgramData|Windows/Temp)/', re.I)
PACKER_SECTIONS = {'upx0': 'UPX', 'upx1': 'UPX', 'upx2': 'UPX', '.aspack': 'ASPack', '.adata': 'ASPack', '.mpress1': 'MPRESS',
                   '.mpress2': 'MPRESS', '.petite': 'Petite', '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.themida': 'Themida',
                   '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.enigma1': 'Enigma', 'pec2': 'PECompact', '.packed': 'generic'}
# Import groups (function names without the A/W suffix). A group counts when `need` of its functions are imported.
API_GROUPS = [
    ('file_wiping', 'Overwrites and deletes files', 3, {'DeleteFile', 'WriteFile', 'SetFilePointer', 'SetFilePointerEx', 'FlushFileBuffers',
                                                         'SetEndOfFile', 'MoveFileEx', 'SetFileInformationByHandle'}),
    ('process_injection', 'Writes into other processes', 2, {'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx',
                                                              'NtUnmapViewOfSection', 'QueueUserAPC', 'SetThreadContext', 'NtWriteVirtualMemory'}),
    ('keylogging', 'Watches the keyboard', 1, {'SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyboardState', 'GetRawInputData'}),
    ('anti_analysis', 'Looks for debuggers', 1, {'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'}),
    ('download', 'Downloads from the internet', 1, {'URLDownloadToFile', 'InternetOpenUrl', 'InternetReadFile', 'WinHttpOpen',
                                                    'WinHttpSendRequest', 'HttpSendRequest'}),
    ('persistence', 'Creates services or registry autostarts', 1, {'CreateService', 'RegSetValueEx', 'RegSetKeyValue'}),
    ('credentials', 'Reads stored credentials', 1, {'CredEnumerate', 'CredRead', 'LsaRetrievePrivateData', 'CryptUnprotectData',
                                                    'SamIConnect'}),
    ('privileges', 'Changes its privileges', 1, {'AdjustTokenPrivileges'}),
    ('encryption', 'Encrypts data', 1, {'CryptEncrypt', 'BCryptEncrypt'}),
    ('screen_capture', 'Captures the screen', 2, {'BitBlt', 'GetDC', 'GetDesktopWindow', 'CreateCompatibleBitmap'}),
]
SEVERITY = {'high': 3, 'medium': 2, 'low': 1}


def _base(name: str) -> str:
    """A Windows API name without its ANSI/Unicode suffix: DeleteFileW -> DeleteFile, MoveFileExW -> MoveFileEx."""
    return re.sub(r'(?<=[a-z0-9])[AW]$', '', name)


def _time(v):
    if not v or v in (0xFFFFFFFF,):
        return None
    try:
        return datetime.fromtimestamp(v, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def analyse(data: bytes) -> dict:
    """The structure of a PE file's bytes; raises ValueError when they are not a PE file."""
    import pefile
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY[d] for d in (
            'IMAGE_DIRECTORY_ENTRY_IMPORT', 'IMAGE_DIRECTORY_ENTRY_RESOURCE', 'IMAGE_DIRECTORY_ENTRY_DEBUG',
            'IMAGE_DIRECTORY_ENTRY_SECURITY')])
    except pefile.PEFormatError as exc:
        raise ValueError(f'not a valid PE file: {exc}') from exc
    try:
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        out = {
            'machine': pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine)).replace('IMAGE_FILE_MACHINE_', ''),
            'bits': 64 if oh.Magic == 0x20B else 32, 'dll': bool(fh.Characteristics & 0x2000),
            'compiled': _time(fh.TimeDateStamp), 'compiled_raw': fh.TimeDateStamp,
            'subsystem': pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem)).replace('IMAGE_SUBSYSTEM_', ''),
            'entry_point': hex(oh.AddressOfEntryPoint), 'image_base': hex(oh.ImageBase),
            'checksum_declared': oh.CheckSum, 'sections': [], 'imports': {}, 'version_info': {},
        }
        for s in pe.sections:
            out['sections'].append({
                'name': s.Name.rstrip(b'\0').decode('latin-1'), 'virtual_size': s.Misc_VirtualSize, 'raw_size': s.SizeOfRawData,
                'entropy': round(s.get_entropy(), 3), 'executable': bool(s.Characteristics & 0x20000000),
                'writable': bool(s.Characteristics & 0x80000000)})
        n = 0
        for imp in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) or []:
            dll = (imp.dll or b'').decode('latin-1')
            names = [(i.name or b'').decode('latin-1') or f'ordinal {i.ordinal}' for i in imp.imports]
            out['imports'][dll] = names[:500]
            n += len(names)
        out['import_count'] = n
        try:
            out['imphash'] = pe.get_imphash() or None
        except Exception:
            out['imphash'] = None
        for fi in getattr(pe, 'FileInfo', None) or []:
            for entry in fi:
                for st in getattr(entry, 'StringTable', None) or []:
                    for k, v in st.entries.items():
                        out['version_info'].setdefault(k.decode('latin-1', 'replace'), v.decode('utf-8', 'replace')[:300])
        for dbg in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', None) or []:
            entry = getattr(dbg, 'entry', None)
            pdb = getattr(entry, 'PdbFileName', None)
            if pdb:
                out['pdb_path'] = pdb.rstrip(b'\0').decode('utf-8', 'replace')[:500]
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        out['has_signature'] = bool(sec.VirtualAddress and sec.Size)
        # Data after the last section (the signature, which sits there, not counted): installers and droppers carry payloads there.
        start = pe.get_overlay_data_start_offset()
        extra = (len(data) - start) if start else 0
        if extra and out['has_signature'] and sec.VirtualAddress >= start:
            extra -= sec.Size
        out['overlay_size'] = max(0, extra)
        return out
    finally:
        pe.close()


def signature(data: bytes) -> dict:
    """The Authenticode signature: signed or not, valid (trusted chain), untrusted (a chain that does not end in a trusted
    root, e.g. self-signed), or invalid (the file was changed after signing, or a broken signature); with the signers."""
    from signify.authenticode import AuthenticodeFile
    try:
        af = AuthenticodeFile.from_stream(io.BytesIO(data))
        result, exc = af.explain_verify(trusted_certificate_store=_trust_store())
        signers = []
        for sd in af.iter_signatures():
            si = sd.signer_info
            chain = [{'subject': c.subject.dn, 'issuer': c.issuer.dn, 'serial': format(c.serial_number, 'X'),
                      'valid_from': c.valid_from, 'valid_to': c.valid_to, 'sha1': c.sha1_fingerprint} for c in sd.certificates][:10]
            own = next((c for c in chain if c['serial'] == format(si.serial_number, 'X')), chain[0] if chain else None)
            signers.append({'program': si.program_name, 'more_info': si.more_info, 'signing_time': si.signing_time,
                             'digest': getattr(sd.digest_algorithm, '__name__', str(sd.digest_algorithm)).replace('openssl_', ''),
                             'signer': own['subject'] if own else si.issuer.dn, 'certificates': chain})
    except Exception as exc:  # a malformed signature table: report, never crash the analysis
        return {'status': 'error', 'detail': str(exc)[:300], 'signers': []}
    status = {'OK': 'valid', 'NOT_SIGNED': 'unsigned', 'CERTIFICATE_ERROR': 'untrusted', 'VERIFY_ERROR': 'invalid',
              'INCONSISTENT_DIGEST_ALGORITHM': 'invalid', 'INVALID_DIGEST': 'invalid', 'PARSE_ERROR': 'invalid'}.get(result.name, 'error')
    if status == 'untrusted' and exc and 'expired' in str(exc).lower():
        status = 'expired'
    return {'status': status, 'detail': None if status in ('valid', 'unsigned') else str(exc)[:500], 'signers': signers}


_STORE = None


def _trust_store():
    """Microsoft's trusted roots as signify ships them, without the few its ASN.1 parser can't read (post-quantum TLS
    pilot roots), which would otherwise make every verification fail."""
    global _STORE
    if _STORE is None:
        from signify.authenticode.cert_store import CERTIFICATE_LOCATION, LEGACY_TRUSTED_CERTIFICATE_STORE
        from signify.authenticode.trust_list import CertificateTrustList
        from signify.x509 import Certificate, CertificateStore
        good = []
        for c in Certificate.from_pems(CERTIFICATE_LOCATION.read_bytes()):
            try:
                c.asn1['tbs_certificate']['subject_public_key_info'].native
                good.append(c)
            except Exception:
                continue
        _STORE = CertificateStore(good, trusted=True, ctl=CertificateTrustList.from_stl_file()) | LEGACY_TRUSTED_CERTIFICATE_STORE
    return _STORE


def api_groups(imports: dict) -> list[dict]:
    have = {}
    for dll, names in imports.items():
        for n in names:
            have.setdefault(_base(n), n)
    out = []
    for key, label, need, funcs in API_GROUPS:
        found = sorted(have[f] for f in funcs if f in have)
        if len(found) >= need:
            out.append({'group': key, 'label': label, 'functions': found})
    return out


def assess(info: dict, sig: dict, path: str) -> list[dict]:
    """Why a program stands out, each with a severity (high, medium, low)."""
    flags = []
    name = path.rsplit('!/', 1)[-1].rsplit('/', 1)[-1]
    add = lambda code, severity, label, detail=None: flags.append({'code': code, 'severity': severity, 'label': label, 'detail': detail})
    packers = sorted({PACKER_SECTIONS[s['name'].lower()] for s in info['sections'] if s['name'].lower() in PACKER_SECTIONS})
    if packers:
        add('PACKED', 'high', f'Packed ({", ".join(packers)})', ', '.join(s['name'] for s in info['sections']))
    hot = [s for s in info['sections'] if s['executable'] and s['entropy'] > 7.2 and s['raw_size'] > 1024]
    if hot and not packers:
        add('HIGH_ENTROPY', 'medium', 'Compressed or encrypted code', ', '.join(f'{s["name"]} {s["entropy"]:.2f}' for s in hot))
    loaders = {_base(n) for names in info['imports'].values() for n in names} & {'LoadLibrary', 'GetProcAddress'}
    if info.get('import_count', 0) < 10 and len(loaders) == 2 and not packers:
        add('FEW_IMPORTS', 'medium', 'Imports almost nothing but loads functions at run time', f'{info.get("import_count")} imports')
    vi = info.get('version_info') or {}
    original = (vi.get('OriginalFilename') or '').strip()
    if original and not original.lower().endswith('.mui') and original.lower() != name.lower():
        add('NAME_MISMATCH', 'high', f'Built as {original}, named {name}', vi.get('FileDescription'))
    if name.lower() in SYSTEM_BINARIES and not SYSTEM_FOLDERS.search(path.split('!/', 1)[0]):
        add('SYSTEM_NAME', 'high', f'A Windows system program\'s name outside the Windows folders', path)
    claims_ms = 'microsoft' in (vi.get('CompanyName') or '').lower()
    ms_signed = sig.get('status') == 'valid' and any('microsoft' in (c['subject'] or '').lower()
                                                       for s in sig.get('signers', []) for c in s['certificates'][:1])
    if claims_ms and not ms_signed:
        add('MICROSOFT_CLAIM', 'high', 'Claims to be from Microsoft without a valid Microsoft signature', vi.get('CompanyName'))
    if sig.get('status') in ('invalid', 'error'):
        add('BAD_SIGNATURE', 'high', 'The signature does not match the file', sig.get('detail'))
    elif sig.get('status') in ('untrusted', 'expired'):
        add('UNTRUSTED_SIGNATURE', 'medium', 'Signed, but not by a trusted publisher' if sig['status'] == 'untrusted'
            else 'Signed with an expired certificate', sig.get('detail'))
    for g in api_groups(info['imports']):
        add('APIS_' + g['group'].upper(), 'high' if g['group'] in ('process_injection', 'keylogging', 'credentials', 'file_wiping') else 'low',
            g['label'], ', '.join(g['functions']))
    if USER_FOLDERS.search(path.split('!/', 1)[0]) and not info.get('dll'):
        add('USER_FOLDER', 'low', 'Program in a user or temporary folder', path)
    return flags


def score(flags: list[dict]) -> int:
    return sum(SEVERITY[f['severity']] for f in flags)


def run_capa(path, run_tool) -> dict:
    """Capabilities capa finds (its own rules, built into the pinned release), with their ATT&CK techniques. Library and
    internal rules are left out; a packed program is reported as such (capa reads unpacked code only)."""
    r = run_tool(['capa', '-j', '-q', str(path)], timeout=CAPA_TIMEOUT, max_output=20_000_000, memory_bytes=6 << 30)
    if r.get('status') == 'TOOL_UNAVAILABLE':
        return {'status': 'unavailable', 'detail': 'capa is not installed'}
    if r.get('status') != 'COMPLETED' or not (r.get('stdout') or '').strip():
        return {'status': 'failed', 'detail': ((r.get('stderr') or r.get('status') or '')[-500:]).strip()}
    try:
        doc = json.loads(r['stdout'])
    except ValueError as exc:
        return {'status': 'failed', 'detail': f'unreadable capa output: {exc}'}
    caps, attack, limitations = [], set(), []
    for rname, rule in (doc.get('rules') or {}).items():
        meta = rule.get('meta') or {}
        ns = meta.get('namespace') or ''
        if meta.get('lib'):
            continue
        if ns.startswith('internal/limitation'):
            limitations.append(rname)
            continue
        ids = [a.get('id') for a in meta.get('attack') or [] if a.get('id')]
        attack.update(ids)
        caps.append({'name': rname, 'namespace': ns or None, 'attack': ids,
                     'mbc': [m.get('id') for m in meta.get('mbc') or [] if m.get('id')], 'matches': len(rule.get('matches') or [])})
    caps.sort(key=lambda c: (c['namespace'] or '~', c['name']))
    version = ((doc.get('meta') or {}).get('version'))
    return {'status': 'limited' if limitations else 'completed', 'capabilities': caps, 'attack': sorted(attack), 'version': version,
            'limitations': limitations}

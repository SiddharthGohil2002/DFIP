"""Review and teamwork: mentions, retention dates, the link graph's path helpers, the custody form, and the Claude mode's
request (sent through the Anthropic SDK to a local stand-in)."""
import http.server
import io
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.services import assistant_llm, graph, retention
from app.services.team import MENTION

UTC = timezone.utc


def test_mentions_are_email_addresses():
    text = 'Thanks @analyst@dfip.local and @Jane.Doe@corp.example, see bob@example.org (no @) and @notanemail'
    assert MENTION.findall(text) == ['analyst@dfip.local', 'Jane.Doe@corp.example']
    assert MENTION.findall('mail@x.org@y.org') == []  # an @ inside a word is not a mention


def test_retention_starts_when_a_case_closes(monkeypatch):
    now = datetime(2026, 10, 1, tzinfo=UTC)
    monkeypatch.setattr(retention, 'policy', lambda: {'enabled': True, 'days': 30})
    set_, unset = retention.on_status_change('IN_PROGRESS', 'COMPLETED', now)
    assert set_ == {'closed_at': now, 'retention': {'days': 30, 'due_at': now + timedelta(days=30), 'set_at': now}} and unset == {}
    assert retention.on_status_change('COMPLETED', 'ARCHIVED', now) == ({}, {})  # still closed: the date stands
    assert retention.on_status_change('ARCHIVED', 'OPEN', now) == ({}, {'closed_at': '', 'retention': ''})
    monkeypatch.setattr(retention, 'policy', lambda: {'enabled': False, 'days': 30})
    assert retention.on_status_change('OPEN', 'COMPLETED', now) == ({'closed_at': now}, {})


def test_graph_helpers():
    assert graph._path('file:///C:/Users/alice/Downloads/archiver%20v2.zip') == 'C:\\Users\\alice\\Downloads\\archiver v2.zip'
    assert graph._path('file:///home/bob/x.tgz') == '/home/bob/x.tgz' and graph._path('C:\\a.txt') == 'C:\\a.txt'
    assert graph._host('https://Files.Example.NET:8443/up?x=1') == 'files.example.net' and graph._host('not a url') is None
    assert graph._base('E:\\Exports\\payroll.csv') == 'payroll.csv' and graph._base('/a/b/') == 'b'
    assert graph._user_of({'source_path': '/Users/alice/AppData/x'}) == 'alice' and graph._user_of({'source_path': '/home/bob/.x'}) == 'bob'
    g = graph.Graph()
    a, b = g.node('person', 'alice', 'alice'), g.node('domain', 'x.org', 'x.org')
    for when in ('2026-09-01T10:00:00', '2026-09-01T09:00:00', '2026-09-02T08:00:00', '2026-09-01T11:00:00'):
        g.edge(a, b, 'visited', {'collection': 'c', 'id': when}, when)
    g.edge(a, a, 'self', {'collection': 'c', 'id': 'x'})  # no loops
    g.edge(a, None, 'nothing', {'collection': 'c', 'id': 'x'})
    e = g.edges[(a, b, 'visited')]
    assert (e['count'], len(e['refs']), e['first'], e['last']) == (4, 3, '2026-09-01T09:00:00', '2026-09-02T08:00:00') and len(g.edges) == 1


def test_custody_form_pdf(tmp_path):
    import subprocess
    from PIL import Image
    from app.services.custody_form import build
    Image.new('RGB', (40, 30), (200, 30, 30)).save(tmp_path / 'abc.jpg')
    now = datetime(2026, 9, 2, 10, 0, tzinfo=UTC)
    item = {'item_id': 'PHY-0007', 'description': 'Dell laptop', 'kind': 'Laptop', 'serial_number': 'SN-1', 'bag_number': 'B-12', 'seal_number': 'S-99',
            'status': 'CHECKED_OUT', 'holder': {'person': 'Lab tech'}, 'location': 'Room A', 'evidence_ids': ['EVID-001'],
            'photos': [{'file': 'abc.jpg', 'sha256': 'ab' * 32, 'caption': 'front', 'name': 'front.jpg'}],
            'custody': [{'action': 'RECEIVED', 'at': now, 'by_name': 'Ann', 'location': 'Room A', 'seal_number': 'S-98'},
                        {'action': 'CHECK_IN', 'at': now, 'by_name': 'Ann', 'location': 'Room A', 'seal_intact': False}]}
    pdf = build(item, {'case_id': 'CASE-1', 'name': 'Test'}, {'name': 'Ann'}, tmp_path)
    text = ' '.join(subprocess.run(['pdftotext', '-', '-'], input=pdf, capture_output=True, check=True).stdout.decode().split())
    assert pdf[:5] == b'%PDF-' and all(x in text for x in ('PHY-0007', 'Dell laptop', 'B-12', 'S-99', 'SEAL BROKEN', 'Received into storage',
                                                             'Released by (name, signature)', 'Printed by Ann'))


class _Claude(http.server.BaseHTTPRequestHandler):
    seen: list = []
    reply: dict = {}

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        _Claude.seen.append({'path': self.path, 'headers': dict(self.headers), 'body': body})
        out = json.dumps(_Claude.reply).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture
def claude(monkeypatch):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Claude)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(assistant_llm.settings, 'anthropic_api_key', 'sk-test')
    monkeypatch.setattr(assistant_llm.settings, 'anthropic_base_url', f'http://127.0.0.1:{server.server_address[1]}')
    monkeypatch.setattr(assistant_llm.settings, 'anthropic_model', 'claude-opus-5-5')
    _Claude.seen = []
    yield _Claude
    server.shutdown()


def _message(text, stop='end_turn'):
    return {'id': 'msg_test', 'type': 'message', 'role': 'assistant', 'model': 'claude-opus-5-5', 'content': [{'type': 'text', 'text': text}] if text else [],
            'stop_reason': stop, 'stop_sequence': None, 'usage': {'input_tokens': 120, 'output_tokens': 30}}


def test_claude_mode_sends_only_the_selected_facts(claude):
    facts = [{'id': 'F2', 'text': 'payroll-export.csv was moved to the Recycle Bin at 2026-09-01 14:15 UTC.'},
             {'id': 'F7', 'text': 'A SanDisk drive was connected at 14:12 UTC.'}]
    claude.reply = _message('The file was recycled after the drive was connected [F7][F2]; it was also emailed [F9].')
    r = assistant_llm.ask('What happened to the payroll export?', facts)
    sent = claude.seen[0]
    body, headers = sent['body'], {k.lower(): v for k, v in sent['headers'].items()}
    assert sent['path'].startswith('/v1/messages') and headers['x-api-key'] == 'sk-test' and 'server-side-fallback-2026-07-01' in headers['anthropic-beta']
    assert body['model'] == 'claude-opus-5-5' and body['fallbacks'] == 'default' and body['output_config'] == {'effort': 'medium'} and 'thinking' not in body
    user = body['messages'][0]['content']
    assert body['messages'][0]['role'] == 'user' and '[F2] payroll-export.csv' in user and '[F7] A SanDisk' in user and user.count('[F') == 2
    assert 'cite' in body['system'] and user.endswith('Question: What happened to the payroll export?')
    assert (r['status'], r['citations'], r['unknown_citations'], r['usage']) == ('ANSWERED', ['F7', 'F2'], ['F9'], {'input_tokens': 120, 'output_tokens': 30})


def test_claude_mode_refusal_and_errors(claude, monkeypatch):
    claude.reply = {**_message(''), 'stop_reason': 'refusal', 'stop_details': {'type': 'refusal', 'category': 'cyber', 'explanation': 'x'}}
    r = assistant_llm.ask('q?', [{'id': 'F1', 'text': 't'}])
    assert (r['status'], r['answer'], r['refusal_category']) == ('REFUSED', '', 'cyber')
    monkeypatch.setattr(assistant_llm.settings, 'anthropic_api_key', '')
    with pytest.raises(assistant_llm.AssistantError) as e:
        assistant_llm.ask('q?', [{'id': 'F1', 'text': 't'}])
    assert e.value.status == 503
    monkeypatch.setattr(assistant_llm.settings, 'anthropic_api_key', 'k')
    monkeypatch.setattr(assistant_llm.settings, 'anthropic_base_url', 'http://127.0.0.1:9')  # nothing listens
    with pytest.raises(assistant_llm.AssistantError) as e:
        assistant_llm.ask('q?', [{'id': 'F1', 'text': 't'}])
    assert e.value.status == 503 and 'could not be reached' in str(e.value)

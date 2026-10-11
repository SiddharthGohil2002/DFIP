"""A small Sigma rule engine for Windows event records: enough of the Sigma specification to run curated detection
rules over the records of one analysis, without converting them to another query language.

Supported:
  logsource   product: windows with a service (security, system, application, powershell, powershell-classic,
              taskscheduler, windefend, terminalservices-localsessionmanager, driver-framework, sysmon, bits-client)
              or a category (ps_script, ps_module, ps_classic_start)
  detection   search identifiers that are maps (field: value | [values], all fields must match) or lists of maps
              (any map), and keyword lists (any value of the event contains the keyword)
  values      strings with Sigma wildcards (* and ?, \\ escapes), compared case-insensitively; numbers; null
  modifiers   contains, startswith, endswith, all, re (RE2; with i for case-insensitive), cased, windash
  condition   and, or, not, parentheses, "1 of x*", "all of x*", "1 of them", "all of them", and one aggregation
              "| count([field]) [by field] > n" (or >=) with an optional timeframe (30s, 10m, 1h, 1d)

Fields are an event's EventData / UserData names, a few System fields (EventID, Channel, Provider_Name, Computer, Level,
Task, Opcode, Keywords, SecurityUserID / UserID), "Data" (the unnamed values of classic events) and the key=value details
of classic PowerShell events (HostApplication, CommandLine...). Rule regular expressions run on RE2 (linear time).
"""
from __future__ import annotations
import re
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parents[2] / 'rules' / 'sigma'
LEVELS = ('informational', 'low', 'medium', 'high', 'critical')
SERVICES = {
    'security': ['Security'], 'system': ['System'], 'application': ['Application'],
    'powershell': ['Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational'],
    'powershell-classic': ['Windows PowerShell'],
    'taskscheduler': ['Microsoft-Windows-TaskScheduler/Operational'],
    'windefend': ['Microsoft-Windows-Windows Defender/Operational'],
    'terminalservices-localsessionmanager': ['Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'],
    'driver-framework': ['Microsoft-Windows-DriverFrameworks-UserMode/Operational'],
    'sysmon': ['Microsoft-Windows-Sysmon/Operational'],
    'bits-client': ['Microsoft-Windows-Bits-Client/Operational'],
}
CATEGORIES = {  # category -> (channels, event IDs it implies)
    'ps_script': (SERVICES['powershell'], {4104}),
    'ps_module': (SERVICES['powershell'], {4103}),
    'ps_classic_start': (SERVICES['powershell-classic'], {400}),
}
SYSTEM_FIELDS = {'EventID': 'event_id', 'Channel': 'channel', 'Provider_Name': 'provider', 'Computer': 'computer',
                 'Level': 'level', 'Task': 'task', 'Opcode': 'opcode', 'Keywords': 'keywords', 'SecurityUserID': 'user_sid',
                 'UserID': 'user_sid', 'EventRecordID': 'record_id'}
MODIFIERS = {'contains', 'startswith', 'endswith', 'all', 're', 'i', 'cased', 'windash'}
MAX_TIMEFRAME = 30 * 86_400
_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86_400}


class RuleError(ValueError):
    """A rule uses something this engine does not support, or is malformed."""


def _re2(pattern: str, flags: str = ''):
    import re2
    opts = re2.Options()
    opts.max_mem = 16 << 20
    try:
        return re2.compile(f'(?{flags}){pattern}' if flags else pattern, opts)
    except Exception as exc:
        raise RuleError(f'not a valid RE2 regular expression {pattern!r}: {exc}')


ANY, ONE = object(), object()   # the * and ? wildcards of a parsed Sigma string


def _sigma_string(value: str) -> list:
    """A Sigma string as literal characters and wildcards. A backslash escapes a following *, ? or backslash; any other
    backslash is literal (so C:\\Users\\ needs no escaping)."""
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == '\\' and i + 1 < len(value) and value[i + 1] in '*?\\':
            out.append(value[i + 1])
            i += 2
            continue
        out.append(ANY if c == '*' else ONE if c == '?' else c)
        i += 1
    return out


def _windash(value: str) -> list[str]:
    """windash: a leading - or / of a command-line switch may be written with either (or an en/em dash)."""
    if not re.search(r'(^|\s)[-/]', value):
        return [value]
    return list(dict.fromkeys(re.sub(r'(^|\s)[-/]', lambda m: m.group(1) + d, value) for d in ('-', '/', '–', '—', '―')))


class _Value:
    """One compiled value of a field: a predicate on a string."""

    def __init__(self, raw, mods: set[str]):
        self.raw = raw
        if raw is None:
            self.kind = 'null'
            return
        if isinstance(raw, bool):
            raw = str(raw).lower()
        if isinstance(raw, (int, float)) and not mods & {'contains', 'startswith', 'endswith', 're'}:
            self.kind, self.number = 'number', raw
            return
        text = str(raw)
        if 're' in mods:  # sub-modifiers i, m and s are RE2's inline flags
            self.kind, self.rx = 'regex', _re2(text, ''.join(f for f in 'ims' if f in mods))
            return
        tokens = _sigma_string(text)
        if 'contains' in mods:
            tokens = [ANY] + tokens + [ANY]
        elif 'startswith' in mods:
            tokens = tokens + [ANY]
        elif 'endswith' in mods:
            tokens = [ANY] + tokens
        self.cased = 'cased' in mods
        lead = bool(tokens) and tokens[0] is ANY
        trail = len(tokens) > 1 and tokens[-1] is ANY
        core = tokens[int(lead):len(tokens) - int(trail)]
        if all(isinstance(t, str) for t in core):  # plain text, at most a * at either end: no regular expression needed
            literal = ''.join(core)
            self.text = literal if self.cased else literal.casefold()
            self.kind = {(False, False): 'equals', (True, True): 'contains', (False, True): 'startswith', (True, False): 'endswith'}[(lead, trail)]
            return
        pattern = ''.join('.*' if t is ANY else '.' if t is ONE else re.escape(t) for t in tokens)
        self.kind, self.rx = 'regex', _re2(f'^{pattern}$', 's' if self.cased else 'is')

    def test(self, v) -> bool:
        if self.kind == 'null':
            return v is None or v == ''
        if v is None:
            return False
        if self.kind == 'number':  # EventID: 4625 matches "4625"; a hex value such as 0x10 matches 16
            s = str(v).strip()
            try:
                return (int(s, 16) if s.lower().startswith('0x') else float(s)) == self.number
            except ValueError:
                return False
        s = str(v)
        if self.kind == 'regex':
            return self.rx.search(s) is not None
        s = s if self.cased else s.casefold()
        if self.kind == 'equals':
            return s == self.text
        if self.kind == 'contains':
            return self.text in s
        return s.startswith(self.text) if self.kind == 'startswith' else s.endswith(self.text)


def lookup(rec: dict, name: str):
    """A field of an event record: a value, a list (the unnamed Data values) or None."""
    data = rec.get('data') or {}
    if name in data:
        return data[name]
    if name == 'Data':
        return rec.get('data_values') or None
    if name in SYSTEM_FIELDS:
        return rec.get(SYSTEM_FIELDS[name])
    details = rec.get('details') or {}
    if name in details:
        return details[name]
    low = name.lower()  # Sigma field names are matched exactly first, then case-insensitively
    for source in (data, details):
        for k, v in source.items():
            if k.lower() == low:
                return v
    return None


class _FieldTest:
    def __init__(self, key: str, values):
        name, *mods = key.split('|')
        unknown = set(mods) - MODIFIERS
        if unknown:
            raise RuleError(f'unsupported modifier(s) {", ".join(sorted(unknown))} on {name}')
        self.name, mods = name, set(mods)
        self.all = 'all' in mods
        raw = values if isinstance(values, list) else [values]
        if 'windash' in mods:
            raw = [w for v in raw for w in (_windash(v) if isinstance(v, str) else [v])]
        if not raw:
            raise RuleError(f'{name} has no values')
        self.values = [_Value(v, mods) for v in raw]

    def test(self, rec: dict) -> bool:
        v = lookup(rec, self.name)
        candidates = v if isinstance(v, list) else [v]
        hit = lambda val: any(val.test(c) for c in candidates)
        return all(hit(val) for val in self.values) if self.all else any(hit(val) for val in self.values)


def _strings(rec: dict):
    for v in (rec.get('data') or {}).values():
        yield str(v)
    yield from (str(v) for v in rec.get('data_values') or [])
    for v in (rec.get('details') or {}).values():
        yield str(v)


class _Search:
    """One search identifier: a map, a list of maps, or a keyword list."""

    def __init__(self, name: str, spec):
        self.name = name
        if isinstance(spec, dict):
            self.maps = [[_FieldTest(k, v) for k, v in spec.items()]]
            self.keywords = None
        elif isinstance(spec, list) and spec and all(isinstance(x, dict) for x in spec):
            self.maps = [[_FieldTest(k, v) for k, v in m.items()] for m in spec]
            self.keywords = None
        elif isinstance(spec, list) and spec and all(isinstance(x, (str, int)) for x in spec):
            self.maps = None
            self.keywords = [_Value(str(x), {'contains'}) for x in spec]
        else:
            raise RuleError(f'search identifier {name} must be a map, a list of maps or a list of keywords')

    def test(self, rec: dict) -> bool:
        if self.keywords is not None:
            return any(k.test(s) for s in _strings(rec) for k in self.keywords)
        return any(all(t.test(rec) for t in m) for m in self.maps)


# ------------------------------------------------------------------------------- condition
_TOKEN = re.compile(r'\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[A-Za-z_][A-Za-z0-9_*]*|\*)', re.I)


def _tokens(text: str) -> list[str]:
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise RuleError(f'cannot parse condition near {text[pos:pos + 20]!r}')
        out.append(m.group(1))
        pos = m.end()
    return out


def _parse_condition(text: str, searches: dict[str, _Search]):
    toks, i = _tokens(text), 0

    def peek():
        return toks[i].lower() if i < len(toks) else None

    def take():
        nonlocal i
        i += 1
        return toks[i - 1]

    def names(pattern):
        if pattern.lower() == 'them':
            found = list(searches)
        else:
            rx = re.compile('^' + re.escape(pattern).replace('\\*', '.*') + '$')
            found = [n for n in searches if rx.match(n)]
        if not found:
            raise RuleError(f'condition refers to {pattern}, which matches no search identifier')
        return found

    def atom():
        t = peek()
        if t is None:
            raise RuleError('condition ends unexpectedly')
        if t == '(':
            take()
            node = expr()
            if peek() != ')':
                raise RuleError('missing ) in condition')
            take()
            return node
        if t in ('1 of', 'all of'):
            take()
            target = take() if i < len(toks) else ''
            group = [searches[n] for n in names(target)]
            return (lambda rec: any(s.test(rec) for s in group)) if t == '1 of' else (lambda rec: all(s.test(rec) for s in group))
        if t in ('and', 'or', ')'):
            raise RuleError(f'unexpected {t} in condition')
        name = take()
        if name not in searches:
            raise RuleError(f'condition refers to unknown search identifier {name}')
        s = searches[name]
        return s.test

    def negation():
        if peek() == 'not':
            take()
            inner = negation()
            return lambda rec: not inner(rec)
        return atom()

    def conj():
        node = negation()
        while peek() == 'and':
            take()
            left, right = node, negation()
            node = lambda rec, a=left, b=right: a(rec) and b(rec)
        return node

    def expr():
        node = conj()
        while peek() == 'or':
            take()
            left, right = node, conj()
            node = lambda rec, a=left, b=right: a(rec) or b(rec)
        return node

    node = expr()
    if i != len(toks):
        raise RuleError(f'unexpected {toks[i]} in condition')
    return node


_AGG = re.compile(r'^count\(\s*([A-Za-z0-9_.]*)\s*\)(?:\s+by\s+([A-Za-z0-9_.]+))?\s*(>=|>)\s*(\d+)$', re.I)


def _timeframe(text) -> int | None:
    if text in (None, ''):
        return None
    m = re.fullmatch(r'(\d+)\s*([smhd])', str(text).strip())
    if not m:
        raise RuleError(f'timeframe must look like 30s, 10m, 1h or 1d, not {text!r}')
    seconds = int(m.group(1)) * _UNITS[m.group(2)]
    if not 0 < seconds <= MAX_TIMEFRAME:
        raise RuleError('timeframe must be between 1 second and 30 days')
    return seconds


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    status: str
    tags: list[str]
    references: list[str]
    falsepositives: list[str]
    channels: set[str]
    event_ids: set[int] | None
    match: object
    aggregation: dict | None = None
    timeframe: int | None = None
    source: str = ''

    def summary(self) -> dict:
        return {'rule_id': self.id, 'title': self.title, 'level': self.level, 'description': self.description, 'status': self.status,
                'tags': self.tags, 'references': self.references, 'falsepositives': self.falsepositives, 'rule_file': self.source,
                'aggregation': self.aggregation, 'timeframe_seconds': self.timeframe}


def _list(v) -> list[str]:
    if v is None:
        return []
    return [str(x) for x in (v if isinstance(v, list) else [v])]


def compile_rule(doc: dict, source: str = '') -> Rule:
    if not isinstance(doc, dict):
        raise RuleError('a rule must be a YAML map')
    for key in ('title', 'id', 'logsource', 'detection'):
        if not doc.get(key):
            raise RuleError(f'rule has no {key}')
    level = str(doc.get('level', 'medium')).lower()
    if level not in LEVELS:
        raise RuleError(f'level must be one of {", ".join(LEVELS)}')
    ls = doc['logsource']
    if str(ls.get('product', '')).lower() != 'windows':
        raise RuleError('only logsource product: windows is supported')
    event_ids = None
    if ls.get('category'):
        cat = str(ls['category']).lower()
        if cat not in CATEGORIES:
            raise RuleError(f'unsupported logsource category {cat}')
        channels, event_ids = CATEGORIES[cat]
    elif ls.get('service'):
        svc = str(ls['service']).lower()
        if svc not in SERVICES:
            raise RuleError(f'unsupported logsource service {svc}')
        channels = SERVICES[svc]
    else:
        raise RuleError('logsource needs a service or a category')
    det = dict(doc['detection'])
    condition = det.pop('condition', None)
    if isinstance(condition, list):
        if len(condition) != 1:
            raise RuleError('only one condition is supported')
        condition = condition[0]
    if not condition or not isinstance(condition, str):
        raise RuleError('detection has no condition')
    timeframe = _timeframe(det.pop('timeframe', None) or doc.get('timeframe'))
    searches = {name: _Search(name, spec) for name, spec in det.items()}
    if not searches:
        raise RuleError('detection has no search identifiers')
    main, _, agg_text = condition.partition('|')
    aggregation = None
    if agg_text.strip():
        m = _AGG.match(agg_text.strip())
        if not m:
            raise RuleError('only "count([field]) [by field] > n" (or >=) aggregations are supported')
        aggregation = {'field': m.group(1) or None, 'by': m.group(2), 'op': m.group(3), 'value': int(m.group(4))}
    elif timeframe:
        raise RuleError('timeframe needs an aggregation')
    return Rule(id=str(doc['id']), title=str(doc['title']), level=level, description=str(doc.get('description', '')).strip(),
                status=str(doc.get('status', 'experimental')), tags=_list(doc.get('tags')), references=_list(doc.get('references')),
                falsepositives=_list(doc.get('falsepositives')), channels={c.lower() for c in channels}, event_ids=event_ids,
                match=_parse_condition(main, searches), aggregation=aggregation, timeframe=timeframe, source=source)


def load_rules(folder: Path = RULES_DIR) -> list[Rule]:
    """Every *.yml rule in a folder (a rule that does not compile raises RuleError naming the file)."""
    import yaml
    rules, seen = [], set()
    for path in sorted(Path(folder).glob('*.yml')):
        try:
            for doc in yaml.safe_load_all(path.read_text(encoding='utf-8')):
                if doc is None:
                    continue
                rule = compile_rule(doc, path.name)
                if rule.id in seen:
                    raise RuleError(f'duplicate rule id {rule.id}')
                seen.add(rule.id)
                rules.append(rule)
        except RuleError as exc:
            raise RuleError(f'{path.name}: {exc}') from None
        except yaml.YAMLError as exc:
            raise RuleError(f'{path.name}: not valid YAML: {exc}') from None
    return rules


@dataclass
class _Hits:
    times: list = field(default_factory=list)       # (time, value, record key)


class Engine:
    """Runs rules over records one at a time; `finish()` evaluates the aggregations (counts over time windows)."""

    MAX_KEYS = 200   # matched records kept per detection

    def __init__(self, rules: list[Rule]):
        self.by_channel: dict[str, list[Rule]] = defaultdict(list)
        for r in rules:
            for c in r.channels:
                self.by_channel[c].append(r)
        self.plain: dict[str, dict] = {}
        self.groups: dict[str, dict[str, _Hits]] = defaultdict(lambda: defaultdict(_Hits))
        self.rules = {r.id: r for r in rules}

    def match(self, rec: dict, key: str) -> list[str]:
        """The ids of the non-aggregating rules this record matches (aggregating rules collect it for finish())."""
        out = []
        for rule in self.by_channel.get((rec.get('channel') or '').lower(), ()):
            if rule.event_ids is not None and rec.get('event_id') not in rule.event_ids:
                continue
            try:
                if not rule.match(rec):
                    continue
            except Exception:
                continue
            t = rec.get('time')
            if rule.aggregation:
                agg = rule.aggregation
                group = str(lookup(rec, agg['by']) or '') if agg['by'] else ''
                val = lookup(rec, agg['field']) if agg['field'] else None
                self.groups[rule.id][group].times.append((t, None if val is None else str(val).lower(), key))
                continue
            d = self.plain.get(rule.id)
            if d is None:
                d = self.plain[rule.id] = dict(rule.summary(), count=0, first=t, last=t, record_keys=[], group=None)
            d['count'] += 1
            if t and (d['first'] is None or t < d['first']):
                d['first'] = t
            if t and (d['last'] is None or t > d['last']):
                d['last'] = t
            if len(d['record_keys']) < self.MAX_KEYS:
                d['record_keys'].append(key)
            out.append(rule.id)
        return out

    def finish(self) -> list[dict]:
        """Every detection: one per matched plain rule, one per group whose count passes an aggregating rule."""
        out = list(self.plain.values())
        for rule_id, groups in self.groups.items():
            rule = self.rules[rule_id]
            agg = rule.aggregation
            for group, hits in groups.items():
                best = _best_window(sorted((h for h in hits.times if h[0] is not None), key=lambda h: h[0]), rule.timeframe,
                                    distinct=agg['field'] is not None)
                if best is None:
                    continue
                n, window = best
                if not (n > agg['value'] if agg['op'] == '>' else n >= agg['value']):
                    continue
                out.append(dict(rule.summary(), count=n, first=window[0][0], last=window[-1][0],
                                record_keys=[h[2] for h in window][:self.MAX_KEYS],
                                group={agg['by']: group} if agg['by'] else None))
        level = {lv: i for i, lv in enumerate(LEVELS)}
        out.sort(key=lambda d: (-level[d['level']], d['first'] or 0))
        return out


def _best_window(hits: list, timeframe: int | None, distinct: bool):
    """The time window (at most `timeframe` long) holding the most hits, or distinct values: (count, hits in it)."""
    if not hits:
        return None

    def size(window):
        return len({h[1] for h in window if h[1] is not None}) if distinct else len(window)

    if timeframe is None:
        return size(hits), hits
    times = [h[0] for h in hits]
    best = None
    for i, (t, _, _) in enumerate(hits):
        window = hits[i:bisect_right(times, t + timedelta(seconds=timeframe), lo=i)]
        n = size(window)
        if best is None or n > best[0]:
            best = (n, window)
    return best

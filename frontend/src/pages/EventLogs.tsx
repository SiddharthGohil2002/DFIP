import { useEffect, useState } from 'react';
import { FileCode, Search, ShieldAlert } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import type { EventDetection, EventLogInfo, EventRecord } from '../lib/types';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Hash, Loading, Modal, PageHeader, Pager, Tabs, type Tone } from '../ui';
import { ExportButton } from '../ui/ExportButton';

type Tab = 'NOTABLE' | 'ALL' | 'DETECTIONS' | 'LOGS';
const PAGE = 200;
const LEVEL_TONE: Record<string, Tone> = { critical: 'danger', high: 'danger', medium: 'warn', low: 'info', informational: 'neutral' };
const CATEGORY_TONE: Record<string, Tone> = { LOG_CLEARED: 'danger', LOGON_FAILED: 'warn', ACCOUNT: 'warn', DEFENDER: 'danger', SERVICE: 'warn', POWERSHELL: 'warn' };

interface Facets {
  channels: { value: string; count: number }[];
  categories: { value: string; label: string; count: number }[];
  event_ids: { value: number; count: number }[];
  users: { value: string; count: number }[];
}

/** A channel's last part (Microsoft-Windows-PowerShell/Operational -> PowerShell/Operational) for narrow columns. */
function shortChannel(c: string | null) {
  if (!c) return '—';
  return c.replace(/^Microsoft-Windows-/, '');
}

export function EventLogsPage() {
  const { caseId, overview } = useCase();
  const [tab, setTab] = useState<Tab>('NOTABLE');
  const [detection, setDetection] = useState<EventDetection | null>(null);
  const counts = overview?.counts;
  const logsPath = `/forensics/eventlogs/logs?case_id=${encodeURIComponent(caseId)}`;
  const logs = useApi<{ data: EventLogInfo[] }>(logsPath);
  const withRecords = (logs.data?.data || []).filter((l) => l.records || l.recovered);

  function showDetection(d: EventDetection) {
    setDetection(d);
    setTab('ALL');
  }

  return (
    <div className="stack">
      <PageHeader
        title="Event logs"
        subtitle="Every record of the Windows event logs (.evtx), read with libevtx. Notable events are the ones an investigation looks for — logons, failed logons, account and group changes, cleared logs, services, scheduled tasks, Remote Desktop, PowerShell, USB devices, Microsoft Defender, startup and shutdown — described in plain English. Detections come from DFIP's curated Sigma rules."
      />
      {logs.data && !logs.data.data.length && (
        <Banner tone="info">No event logs have been read yet. They are read by the Standard and Full analysis profiles (module "Windows event logs").</Banner>
      )}
      <Card flush>
        <Tabs<Tab> value={tab} onChange={(t) => { setTab(t); if (t !== 'ALL') setDetection(null); }} tabs={[
          { id: 'NOTABLE', label: 'Notable', count: counts?.notable_events },
          { id: 'ALL', label: 'All events', count: counts?.event_records },
          { id: 'DETECTIONS', label: 'Detections', count: counts?.event_detections },
          { id: 'LOGS', label: 'Logs', count: logs.data ? withRecords.length : undefined },
        ]} />
        {tab === 'NOTABLE' && <Events key="notable" caseId={caseId} notable />}
        {tab === 'ALL' && <Events key={`all-${detection?.rule_id || ''}`} caseId={caseId} detection={detection} onClearDetection={() => setDetection(null)} />}
        {tab === 'DETECTIONS' && <Detections caseId={caseId} onShow={showDetection} />}
        {tab === 'LOGS' && <Logs path={logsPath} data={logs.data?.data} error={logs.error} loading={logs.loading} />}
      </Card>
    </div>
  );
}

function Events({ caseId, notable, detection, onClearDetection }: {
  caseId: string; notable?: boolean; detection?: EventDetection | null; onClearDetection?: () => void;
}) {
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('');
  const [channel, setChannel] = useState('');
  const [eventId, setEventId] = useState('');
  const [eventIds, setEventIds] = useState('');
  const [level, setLevel] = useState('');
  const [recovered, setRecovered] = useState(false);
  const [skip, setSkip] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const facets = useApi<Facets>(`/forensics/eventlogs/facets?case_id=${encodeURIComponent(caseId)}`);
  const qs = new URLSearchParams({ case_id: caseId, limit: String(PAGE), skip: String(skip) });
  if (notable) qs.set('notable', 'true');
  if (search) qs.set('search', search);
  if (category) qs.set('category', category);
  if (channel) qs.set('channel', channel);
  if (eventIds) qs.set('event_id', eventIds);
  if (level) qs.set('level', level);
  if (recovered) qs.set('recovered', 'true');
  if (detection) qs.set('detection', detection.rule_id);
  const path = `/forensics/eventlogs/events?${qs}`;
  const list = useApi<{ data: EventRecord[]; total: number }>(path);
  useEffect(() => setSkip(0), [search, category, channel, eventIds, level, recovered]);
  const validIds = /^\s*\d+(\s*,\s*\d+)*\s*$/.test(eventId) || eventId.trim() === '';

  return (
    <>
      {detection && (
        <div className="row" style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', gap: 8 }}>
          <Badge tone={LEVEL_TONE[detection.level]}>{detection.level.toUpperCase()}</Badge>
          <span className="small">Events matched by <span className="strong">{detection.title}</span></span>
          <Button size="sm" variant="ghost" onClick={onClearDetection}>Show all events</Button>
        </div>
      )}
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', gap: 8 }}>
        <input className="input sm" style={{ maxWidth: 260 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
          placeholder="Search descriptions and event data" aria-label="Search events" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
        <select className="input sm" style={{ maxWidth: 190 }} value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category">
          <option value="">All categories</option>
          {(facets.data?.categories || []).map((c) => <option key={c.value} value={c.value}>{c.label} ({c.count.toLocaleString()})</option>)}
        </select>
        <select className="input sm" style={{ maxWidth: 230 }} value={channel} onChange={(e) => setChannel(e.target.value)} aria-label="Log">
          <option value="">All logs</option>
          {(facets.data?.channels || []).map((c) => <option key={c.value} value={c.value}>{shortChannel(c.value)} ({c.count.toLocaleString()})</option>)}
        </select>
        <input className="input sm" style={{ maxWidth: 190 }} value={eventId} onChange={(e) => setEventId(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && validIds && setEventIds(eventId.replace(/\s/g, ''))} onBlur={() => validIds && setEventIds(eventId.replace(/\s/g, ''))}
          placeholder="Event ID, e.g. 4624,4625" aria-label="Event IDs" aria-invalid={!validIds} />
        {!notable && (
          <>
            <select className="input sm" style={{ maxWidth: 150 }} value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Level">
              <option value="">Any level</option>
              <option value="warning">Warning or worse</option>
              <option value="error">Error or worse</option>
              <option value="critical">Critical</option>
            </select>
            <label className="check"><input type="checkbox" checked={recovered} onChange={(e) => setRecovered(e.target.checked)} /> Recovered records only</label>
          </>
        )}
        {(search || category || channel || eventIds || level || recovered) && (
          <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); setCategory(''); setChannel(''); setEventId(''); setEventIds(''); setLevel(''); setRecovered(false); }}>Clear</Button>
        )}
        <span style={{ flex: 1 }} />
        {!!list.data?.data.length && <ExportButton path={path} what="event list" />}
      </div>
      <ErrorBanner error={list.error} />
      {list.loading && !list.data ? <Loading /> : !list.data?.data.length ? (
        <Empty title={notable ? 'No notable events' : 'No event records'} text={search || category || channel || eventIds || level || recovered ? 'Nothing matches these filters.' : undefined} />
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Time</th><th>Log</th><th className="right">Event</th><th>User</th><th>What happened</th><th /></tr></thead>
              <tbody>
                {list.data.data.map((e) => (
                  <tr key={e._id}>
                    <td className="mono tiny nowrap">{time(e.time)}</td>
                    <td className="small">{shortChannel(e.channel)}{e.recovered && <div><Badge tone="warn" title="Recovered from unused space in the log">RECOVERED</Badge></div>}</td>
                    <td className="right mono small">{e.event_id ?? '—'}</td>
                    <td className="small">{e.user || <span className="faint">—</span>}</td>
                    <td className="small">
                      {e.category && <Badge tone={CATEGORY_TONE[e.category] || 'neutral'}>{e.title}</Badge>}{' '}
                      {e.description || <span className="muted">{e.provider} event {e.event_id}{e.data_values?.length ? `: ${e.data_values.slice(0, 2).join(' · ').slice(0, 160)}` : ''}</span>}
                      {e.detections?.length > 0 && <div><Badge tone="danger" title="Matched a detection rule"><ShieldAlert size={11} /> DETECTION</Badge></div>}
                    </td>
                    <td className="nowrap">
                      <Button size="sm" variant="ghost" icon={<FileCode size={13} />} onClick={() => setOpen(e._id)} aria-label={`Details of event ${e.event_id} at ${e.time}`}>Details</Button>
                      <TagButton type="EVENT" id={e._id} title={e.description || `${e.channel} event ${e.event_id}`} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager skip={skip} limit={PAGE} total={list.data.total} onChange={setSkip} />
        </>
      )}
      <EventDetail caseId={caseId} id={open} onClose={() => setOpen(null)} />
    </>
  );
}

function EventDetail({ caseId, id, onClose }: { caseId: string; id: string | null; onClose: () => void }) {
  const time = useTime();
  const { data, error, loading } = useApi<EventRecord>(id ? `/forensics/eventlogs/events/${id}?case_id=${encodeURIComponent(caseId)}` : null);
  const e = data && data._id === id ? data : null;
  const fields = e ? Object.entries(e.data || {}) : [];
  return (
    <Modal open={!!id} title={e ? `${e.channel} event ${e.event_id}` : 'Event'} onClose={onClose} wide>
      <ErrorBanner error={error} />
      {!e ? (loading ? <Loading /> : null) : (
        <div className="stack" style={{ gap: 14 }}>
          {e.description && <p style={{ margin: 0 }}>{e.description}</p>}
          {e.details?.DecodedCommand && (
            <Banner tone="warn"><span className="strong">Decoded -EncodedCommand:</span> <span className="mono small">{e.details.DecodedCommand}</span></Banner>
          )}
          {e.parse_error && <Banner tone="warn">{e.parse_error}. The fields below are what libevtx could read.</Banner>}
          <dl className="kv" style={{ gridTemplateColumns: '150px 1fr' }}>
            <dt>Time (TimeCreated)</dt><dd className="mono">{time(e.time)}</dd>
            <dt>Record number</dt><dd className="mono">{e.record_id ?? '—'}{e.recovered && <> <Badge tone="warn">RECOVERED</Badge></>}</dd>
            <dt>Log</dt><dd className="mono small break">{e.log_path}</dd>
            <dt>Provider</dt><dd>{e.provider}{e.provider_guid && <span className="mono tiny muted"> {e.provider_guid}</span>}</dd>
            <dt>Event ID</dt><dd className="mono">{e.event_id}{e.qualifiers ? ` (qualifiers ${e.qualifiers})` : ''} · version {e.version ?? 0}</dd>
            <dt>Level</dt><dd>{e.level_name}{e.keywords && <span className="mono tiny muted"> keywords {e.keywords}</span>}</dd>
            <dt>Task / opcode</dt><dd className="mono">{e.task ?? 0} / {e.opcode ?? 0}</dd>
            <dt>Computer</dt><dd>{e.computer || '—'}</dd>
            <dt>User</dt><dd>{e.user || '—'}{e.user_sid && <span className="mono tiny muted"> {e.user_sid}</span>}</dd>
            <dt>Process / thread</dt><dd className="mono">{e.process_id ?? '—'} / {e.thread_id ?? '—'}</dd>
            {e.detections?.length > 0 && (<><dt>Detections</dt><dd>{e.detections.map((d) => <Badge key={d} tone="danger">{d}</Badge>)}</dd></>)}
          </dl>
          {(fields.length > 0 || e.data_values?.length > 0) && (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>{e.user_data ? `UserData (${e.user_data})` : 'EventData'}</th><th>Value</th></tr></thead>
                <tbody>
                  {fields.map(([k, v]) => <tr key={k}><td className="small strong nowrap">{k}</td><td className="mono small break" style={{ whiteSpace: 'pre-wrap' }}>{v}</td></tr>)}
                  {(e.data_values || []).map((v, i) => <tr key={`v${i}`}><td className="small muted nowrap">Value {i + 1}</td><td className="mono small break" style={{ whiteSpace: 'pre-wrap' }}>{v}</td></tr>)}
                </tbody>
              </table>
            </div>
          )}
          {e.truncated && <p className="small muted" style={{ margin: 0 }}>Long values are shortened to 16,384 characters.</p>}
          {e.xml && (
            <details>
              <summary className="small strong">XML{e.xml_truncated ? ' (first 32,768 characters)' : ''}</summary>
              <pre className="mono tiny" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 360, overflow: 'auto' }}>{e.xml}</pre>
            </details>
          )}
        </div>
      )}
    </Modal>
  );
}

function Detections({ caseId, onShow }: { caseId: string; onShow: (d: EventDetection) => void }) {
  const time = useTime();
  const path = `/forensics/eventlogs/detections?case_id=${encodeURIComponent(caseId)}`;
  const { data, error, loading } = useApi<{ data: EventDetection[] }>(path);
  if (loading && !data) return <Loading />;
  return (
    <>
      <div className="row" style={{ padding: '10px 14px 0', alignItems: 'flex-start' }}>
        <p className="small muted grow" style={{ margin: 0 }}>
          Leads from DFIP's curated Sigma rules (backend/rules/sigma), most severe first. A detection is a reason to look, not a conclusion: each rule lists its usual false positives.
        </p>
        {!!data?.data.length && <ExportButton path={path} what="list of detections" />}
      </div>
      <ErrorBanner error={error} />
      {!data?.data.length ? <Empty title="No detections" text="No rule matched the event records (or no event logs have been read)." /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Level</th><th>Rule</th><th className="right">Events</th><th>First</th><th>Last</th><th /></tr></thead>
            <tbody>
              {data.data.map((d) => (
                <tr key={d._id}>
                  <td><Badge tone={LEVEL_TONE[d.level]}>{d.level.toUpperCase()}</Badge></td>
                  <td className="small">
                    <div className="strong">{d.title}{d.group && <span className="muted"> · {Object.entries(d.group).map(([k, v]) => `${k} ${v}`).join(', ')}</span>}</div>
                    <div className="muted">{d.description}</div>
                    {d.sample?.[0] && <div className="tiny mono" style={{ marginTop: 4 }}>{d.sample[0]}</div>}
                    <div className="row" style={{ gap: 4, marginTop: 4 }}>
                      {d.tags.filter((t) => /^attack\.t\d/.test(t)).map((t) => <Badge key={t}>{t.replace('attack.', '').toUpperCase()}</Badge>)}
                      {d.falsepositives.length > 0 && <span className="tiny muted">False positives: {d.falsepositives.join('; ')}</span>}
                    </div>
                  </td>
                  <td className="right mono">{d.count.toLocaleString()}</td>
                  <td className="mono tiny nowrap">{time(d.first)}</td>
                  <td className="mono tiny nowrap">{time(d.last)}</td>
                  <td><Button size="sm" onClick={() => onShow(d)}>Show events</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function Logs({ path, data, error, loading }: { path: string; data?: EventLogInfo[]; error?: string | null; loading: boolean }) {
  const time = useTime();
  const [empty, setEmpty] = useState(false);
  if (loading && !data) return <Loading />;
  const rows = (data || []).filter((l) => empty || l.records || l.recovered);
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
        <label className="check"><input type="checkbox" checked={empty} onChange={(e) => setEmpty(e.target.checked)} /> Include empty logs</label>
        <span className="small muted">{(data || []).length.toLocaleString()} log files read; a Windows installation keeps a few hundred, most of them empty.</span>
        <span style={{ flex: 1 }} />
        {!!data?.length && <ExportButton path={path} what="list of logs" />}
      </div>
      <ErrorBanner error={error} />
      {!rows.length ? <Empty title="No event logs" /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Log</th><th className="right">Records</th><th className="right">Recovered</th><th>First event</th><th>Last event</th><th>State</th><th>SHA-256</th></tr></thead>
            <tbody>
              {rows.map((l) => (
                <tr key={`${l.evidence_id}${l.path}`}>
                  <td className="small"><div className="strong">{l.channel || l.name}</div><div className="tiny mono muted break">{l.path} · {formatBytes(l.size)}</div></td>
                  <td className="right mono">{l.records.toLocaleString()}</td>
                  <td className="right mono">{l.recovered ? l.recovered.toLocaleString() : '—'}</td>
                  <td className="mono tiny nowrap">{time(l.first)}</td>
                  <td className="mono tiny nowrap">{time(l.last)}</td>
                  <td className="small">
                    {!l.dirty && !l.full && !l.corrupted && !l.capped && !l.errors.length && <Badge tone="ok">OK</Badge>}
                    {l.dirty && <Badge tone="warn" title="The log was not closed cleanly (Windows was still writing it)">NOT CLOSED</Badge>}
                    {l.full && <Badge tone="warn" title="The log reached its maximum size: older events were overwritten">FULL</Badge>}
                    {l.corrupted && <Badge tone="danger">DAMAGED</Badge>}
                    {l.capped && <Badge tone="warn">CAPPED</Badge>}
                    {l.errors.length > 0 && <div className="tiny muted">{l.errors[0]}</div>}
                  </td>
                  <td><Hash value={l.sha256} short={12} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

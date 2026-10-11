import { useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { RotateCcw, Search, ZoomOut } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { TimeModeContext, formatNumber, isoToLocalInput, localInputToIso, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import type { TimelineEvent } from '../lib/types';
import { Badge, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, type Tone } from '../ui';
import { niceMax } from '../ui/charts';

const LIMIT = 100;
const TYPE_FILTERS: Record<string, { label: string; types: string }> = {
  all: { label: 'All event types', types: '' },
  notable: { label: 'User activity', types: 'BROWSER_VISIT,BROWSER_DOWNLOAD,USB_ACTIVITY,PROGRAM_RUN,RECENT_FILE_OPENED,FILE_DELETED_TO_RECYCLE_BIN' },
  files: { label: 'Filesystem (MACB)', types: 'FILE_MACB' },
  browser: { label: 'Browser activity', types: 'BROWSER_VISIT,BROWSER_DOWNLOAD' },
  usb: { label: 'USB activity', types: 'USB_ACTIVITY' },
  activity: { label: 'Windows activity', types: 'PROGRAM_RUN,RECENT_FILE_OPENED,FILE_DELETED_TO_RECYCLE_BIN' },
};
const TYPE_TONE: Record<string, Tone> = {
  FILE_MACB: 'neutral', BROWSER_VISIT: 'info', BROWSER_DOWNLOAD: 'accent', USB_ACTIVITY: 'warn',
  PROGRAM_RUN: 'ok', RECENT_FILE_OPENED: 'info', FILE_DELETED_TO_RECYCLE_BIN: 'danger',
};
const TYPE_LABEL: Record<string, string> = {
  FILE_MACB: 'File MACB', BROWSER_VISIT: 'Browser visit', BROWSER_DOWNLOAD: 'Download', USB_ACTIVITY: 'USB',
  PROGRAM_RUN: 'Program run', RECENT_FILE_OPENED: 'File opened', FILE_DELETED_TO_RECYCLE_BIN: 'Recycled',
};

export function TimelinePage() {
  const { caseId, overview } = useCase();
  const { mode } = useContext(TimeModeContext);
  const time = useTime();
  const [filter, setFilter] = useState('all');
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [start, setStart] = useState<string | null>(null);
  const [end, setEnd] = useState<string | null>(null);
  const [evidence, setEvidence] = useState('');
  const [order, setOrder] = useState<'asc' | 'desc'>('asc');
  const [skip, setSkip] = useState(0);

  const base = useMemo(() => {
    const p = new URLSearchParams({ case_id: caseId });
    if (TYPE_FILTERS[filter].types) p.set('type', TYPE_FILTERS[filter].types);
    if (search) p.set('q', search);
    if (start) p.set('start', start);
    if (end) p.set('end', end);
    if (evidence) p.set('evidence_id', evidence);
    return p.toString();
  }, [caseId, filter, search, start, end, evidence]);
  useEffect(() => setSkip(0), [base, order]);

  const events = useApi<{ data: TimelineEvent[]; total: number }>(`/forensics/timeline?${base}&order=${order}&limit=${LIMIT}&skip=${skip}`);
  const hist = useApi<Histogram>(`/forensics/timeline/histogram?${base}`);
  const filtered = filter !== 'all' || search || start || end || evidence;

  function reset() {
    setFilter('all');
    setQ('');
    setSearch('');
    setStart(null);
    setEnd(null);
    setEvidence('');
  }

  return (
    <div className="stack">
      <PageHeader
        title="Timeline"
        subtitle="One chronology of filesystem MACB times (m = modified, a = accessed, c = changed, b = born/created), browser visits and downloads, USB device events, and Windows activity (programs run, files opened, files recycled)."
      />

      <Card>
        <div className="stack" style={{ gap: 12 }}>
          <div className="row">
            <select className="select sm" style={{ width: 170 }} value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Event type">
              {Object.entries(TYPE_FILTERS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            <input className="input sm grow" style={{ maxWidth: 340 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())} placeholder="Search event descriptions (Enter)" aria-label="Search" />
            <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
            {(overview?.evidence.length || 0) > 1 && (
              <select className="select sm" style={{ width: 160 }} value={evidence} onChange={(e) => setEvidence(e.target.value)} aria-label="Evidence">
                <option value="">All evidence</option>
                {overview!.evidence.map((e) => <option key={e.evidence_id} value={e.evidence_id}>{e.evidence_id}</option>)}
              </select>
            )}
            <div className="spacer" style={{ flex: 1 }} />
            <Button size="sm" onClick={() => setOrder(order === 'asc' ? 'desc' : 'asc')}>{order === 'asc' ? 'Oldest first' : 'Newest first'}</Button>
            {filtered && <Button size="sm" variant="ghost" icon={<RotateCcw size={13} />} onClick={reset}>Reset</Button>}
          </div>
          <div className="row">
            <label className="small muted row" style={{ gap: 6 }}>
              From
              <input className="input sm" type="datetime-local" style={{ width: 200 }} value={start ? isoToLocalInput(start, mode) : ''} onChange={(e) => setStart(localInputToIso(e.target.value, mode))} />
            </label>
            <label className="small muted row" style={{ gap: 6 }}>
              To
              <input className="input sm" type="datetime-local" style={{ width: 200 }} value={end ? isoToLocalInput(end, mode) : ''} onChange={(e) => setEnd(localInputToIso(e.target.value, mode))} />
            </label>
            <span className="small muted">Times in {mode === 'utc' ? 'UTC' : 'your local time zone'} (switch in the top bar).</span>
          </div>
        </div>
      </Card>

      <Card
        title="Events over time"
        subtitle={hist.data?.unit ? `${formatNumber(events.data?.total)} events · one column per ${hist.data.unit} (UTC) · click a column to zoom in` : undefined}
        actions={(start || end) && <Button size="sm" icon={<ZoomOut size={13} />} onClick={() => { setStart(null); setEnd(null); }}>Full range</Button>}
      >
        {hist.loading && !hist.data ? <Loading /> : <HistogramChart data={hist.data} onZoom={(s, e) => { setStart(s); setEnd(e); }} />}
      </Card>

      <Card flush>
        <ErrorBanner error={events.error} />
        {events.loading && !events.data ? (
          <Loading />
        ) : !events.data?.data.length ? (
          <Empty title={filtered ? 'No events match these filters' : 'No timeline yet'} text={filtered ? undefined : 'Run the full analysis on this case\'s evidence to build its timeline.'} />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Time</th><th>Type</th><th>Event</th><th>Source</th><th /></tr></thead>
              <tbody>
                {events.data.data.map((e) => (
                  <tr key={e._id} className={e.deleted ? 'is-deleted' : ''}>
                    <td className="mono small nowrap">{time(e.timestamp)}</td>
                    <td><Badge tone={TYPE_TONE[e.type] || 'neutral'}>{TYPE_LABEL[e.type] || e.type}</Badge></td>
                    <td className="cell-path">{e.description}</td>
                    <td className="tiny muted cell-source">{e.source}<div>{e.evidence_id}</div></td>
                    <td className="nowrap right"><TagButton type="TIMELINE_EVENT" id={e._id} title={e.description} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {events.data && <Pager skip={skip} limit={LIMIT} total={events.data.total} onChange={setSkip} />}
      </Card>
    </div>
  );
}

interface Histogram {
  unit: 'hour' | 'day' | 'month' | null;
  first?: string;
  last?: string;
  buckets: { t: string; total: number; by_type: Record<string, number> }[];
}

function bucketEnd(t: Date, unit: Histogram['unit']): Date {
  const d = new Date(t);
  if (unit === 'hour') d.setUTCHours(d.getUTCHours() + 1);
  else if (unit === 'day') d.setUTCDate(d.getUTCDate() + 1);
  else d.setUTCMonth(d.getUTCMonth() + 1);
  return d;
}

function bucketLabel(t: Date, unit: Histogram['unit']): string {
  const iso = t.toISOString();
  if (unit === 'month') return iso.slice(0, 7);
  if (unit === 'day') return iso.slice(0, 10);
  return `${iso.slice(0, 10)} ${iso.slice(11, 13)}:00`;
}

/** Event counts per time bucket on a true time axis (gaps in activity stay visible). */
function HistogramChart({ data, onZoom }: { data: Histogram | null; onZoom: (start: string, end: string) => void }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(900);
  const [hover, setHover] = useState<{ i: number; x: number; y: number } | null>(null);

  useLayoutEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(320, e.contentRect.width)));
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  if (!data || !data.unit || !data.buckets.length) {
    return (
      <div ref={wrap}>
        <p className="small muted" style={{ margin: 0 }}>No events to chart.</p>
      </div>
    );
  }

  const height = 180;
  const pad = { top: 10, right: 12, bottom: 26, left: 44 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const buckets = data.buckets.map((b) => ({ ...b, start: new Date(b.t) }));
  const t0 = buckets[0].start.getTime();
  const t1 = bucketEnd(buckets[buckets.length - 1].start, data.unit).getTime();
  const span = Math.max(1, t1 - t0);
  const x = (t: number) => pad.left + ((t - t0) / span) * plotW;
  const max = niceMax(Math.max(...buckets.map((b) => b.total)));
  const y = (v: number) => pad.top + plotH - (v / max) * plotH;
  const ticks = [0, max / 2, max];
  const slots = buckets.map((b) => x(bucketEnd(b.start, data.unit).getTime()) - x(b.start.getTime()));
  // Axis labels at fixed points of the time axis (start, middle, end), not at bucket indexes.
  const axisLabels = [0, 0.5, 1].map((f) => ({ f, t: new Date(t0 + f * span - (f === 1 ? 1 : 0)) }));
  const hb = hover ? buckets[hover.i] : null;

  return (
    <div ref={wrap} style={{ position: 'relative' }}>
      <svg className="chart" width={width} height={height} role="img" aria-label={`Timeline events per ${data.unit}`}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.left} x2={width - pad.right} y1={y(t)} y2={y(t)} stroke="#e6eaf0" strokeWidth={1} />
            <text x={pad.left - 8} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--muted)">{Math.round(t).toLocaleString()}</text>
          </g>
        ))}
        {buckets.map((b, i) => {
          const slot = slots[i];
          const w = Math.max(2, Math.min(24, slot - 2));
          const cx = x(b.start.getTime()) + slot / 2;
          const top = y(b.total);
          const h = Math.max(1, pad.top + plotH - top);
          const r = Math.min(4, w / 2, h);
          const left = cx - w / 2;
          const bottom = pad.top + plotH;
          // Rounded data-end on top, square at the baseline.
          const d = `M${left},${bottom} V${top + r} Q${left},${top} ${left + r},${top} H${left + w - r} Q${left + w},${top} ${left + w},${top + r} V${bottom} Z`;
          const hitW = Math.max(w + 6, 10);
          const zoom = () => onZoom(b.start.toISOString(), new Date(bucketEnd(b.start, data.unit).getTime() - 1000).toISOString());
          return (
            <g key={b.t}>
              <path d={d} fill="var(--accent)" opacity={hover && hover.i !== i ? 0.55 : 1} />
              <rect
                className="bar"
                x={cx - hitW / 2}
                y={pad.top}
                width={hitW}
                height={plotH}
                fill="transparent"
                tabIndex={0}
                role="button"
                aria-label={`${bucketLabel(b.start, data.unit)}: ${b.total} events. Activate to zoom in.`}
                onPointerMove={(e) => setHover({ i, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })}
                onPointerLeave={() => setHover(null)}
                onFocus={() => setHover({ i, x: cx, y: top })}
                onBlur={() => setHover(null)}
                onClick={zoom}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && zoom()}
              />
            </g>
          );
        })}
        <line x1={pad.left} x2={width - pad.right} y1={pad.top + plotH} y2={pad.top + plotH} stroke="#c7d0db" strokeWidth={1} />
        {axisLabels.map(({ f, t }) => (
          <text key={f} x={pad.left + f * plotW} y={height - 6} textAnchor={f === 0 ? 'start' : f === 1 ? 'end' : 'middle'} fontSize={11} fill="var(--muted)">
            {bucketLabel(t, data.unit)}
          </text>
        ))}
      </svg>
      {hover && hb && (
        <div
          role="tooltip"
          style={{
            position: 'absolute', left: Math.min(hover.x + 12, width - 220), top: Math.max(0, hover.y - 10), pointerEvents: 'none',
            background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, boxShadow: 'var(--shadow-lg)', padding: '8px 10px', fontSize: 12, minWidth: 180,
          }}
        >
          <div><b style={{ fontSize: 14 }}>{hb.total.toLocaleString()}</b> events</div>
          <div className="muted">{bucketLabel(hb.start, data.unit)} UTC</div>
          {Object.entries(hb.by_type).map(([k, v]) => (
            <div key={k} className="row" style={{ justifyContent: 'space-between', gap: 12 }}>
              <span className="muted">{TYPE_LABEL[k] || k}</span>
              <b>{v.toLocaleString()}</b>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

import { useEffect, useState, type ReactNode } from 'react';
import { Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import type { Artifact } from '../lib/types';
import { Badge, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, Tabs } from '../ui';

const LIMIT = 100;
const BROWSERS = ['Chrome', 'Edge', 'Brave', 'Opera', 'Opera GX', 'Vivaldi', 'Chromium', 'Firefox'];
type Kind = 'BROWSER_HISTORY' | 'BROWSER_DOWNLOAD' | 'BROWSER_SEARCH' | 'BROWSER_RECOVERED' | 'BROWSER_COOKIE' | 'BROWSER_BOOKMARK'
  | 'BROWSER_AUTOFILL' | 'BROWSER_LOGIN';
type Time = (t?: string | null) => string;
type Col = [string, (r: Artifact, time: Time) => ReactNode, string?];

const NOTES: Partial<Record<Kind, string>> = {
  BROWSER_SEARCH: 'Search terms from the browsers\' own search-term tables and from search addresses (Google, Bing, DuckDuckGo and others) in their history, including deleted history rows that were recovered.',
  BROWSER_RECOVERED: 'History rows deleted from the browser that are still in the database file: in free space, on free pages, or in an older copy of a page in the write-ahead log (-wal). Chrome and Firefox normally zero deleted rows in the database itself, so most are found in write-ahead logs.',
  BROWSER_COOKIE: 'Cookies show which sites the browser had sessions with. Chromium encrypts cookie values; Firefox does not.',
  BROWSER_AUTOFILL: 'What was typed into form fields and search boxes, how often and when. Saved card numbers stay encrypted.',
  BROWSER_LOGIN: 'Sites with saved logins and their user names. Passwords are encrypted by the browser and are never shown.',
};

const COLUMNS: Record<Kind, Col[]> = {
  BROWSER_HISTORY: [
    ['Last visit', (r, t) => t(r.last_visit_time), 'mono small nowrap'],
    ['Visits', (r) => r.visit_count, 'right'],
    ['Page', (r) => <><div className="strong">{r.title || <span className="muted">(no title)</span>}</div><div className="small mono muted">{r.url}</div></>, 'cell-path'],
    ['Source database', (r) => <>{r.source_path}<div>{r.evidence_id}</div></>, 'cell-path tiny muted'],
  ],
  BROWSER_DOWNLOAD: [
    ['Started', (r, t) => t(r.start_time), 'mono small nowrap'],
    ['Saved to', (r) => r.target_path, 'cell-path mono small'],
    ['From', (r) => r.tab_url, 'cell-path mono small muted'],
    ['Size', (r) => (r.total_bytes ? formatBytes(r.total_bytes) : '—'), 'right small nowrap'],
  ],
  BROWSER_SEARCH: [
    ['Time', (r, t) => t(r.time), 'mono small nowrap'],
    ['Search term', (r) => <><span className="strong">{r.term}</span> {r.recovered && <Badge tone="danger">RECOVERED</Badge>}</>, 'small'],
    ['Engine', (r) => r.engine || '—', 'small'],
    ['Address', (r) => r.url, 'cell-path mono tiny muted'],
    ['User', (r) => r.user, 'small'],
  ],
  BROWSER_RECOVERED: [
    ['Last visit', (r, t) => t(r.last_visit_time), 'mono small nowrap'],
    ['Page', (r) => <><div className="strong">{r.title || <span className="muted">(no title)</span>}</div><div className="small mono muted">{r.url}</div></>, 'cell-path'],
    ['Found in', (r) => <>{r.wal_frame ? `WAL frame ${r.wal_frame}` : `${r.recovered_from}, page ${r.page}`}<div className="tiny muted">byte {Number(r.file_offset).toLocaleString()} of the {r.file === 'wal' ? 'write-ahead log' : 'database'}{r.row_id ? ` · row ${r.row_id}` : ''}</div></>, 'small'],
    ['Source database', (r) => r.source_path, 'cell-path tiny muted'],
  ],
  BROWSER_COOKIE: [
    ['Created', (r, t) => t(r.created), 'mono small nowrap'],
    ['Site', (r) => <span className="mono">{r.host}</span>, 'small'],
    ['Name', (r) => <span className="mono">{r.name}</span>, 'small'],
    ['Value', (r) => (r.value_encrypted ? <Badge>ENCRYPTED</Badge> : <span className="mono tiny">{String(r.value ?? '').slice(0, 60)}</span>)],
    ['Expires', (r, t) => t(r.expires), 'mono small nowrap'],
    ['Last used', (r, t) => t(r.last_accessed), 'mono small nowrap'],
  ],
  BROWSER_BOOKMARK: [
    ['Added', (r, t) => t(r.added), 'mono small nowrap'],
    ['Bookmark', (r) => <><div className="strong">{r.title}</div><div className="small mono muted">{r.url}</div></>, 'cell-path'],
    ['Folder', (r) => r.folder, 'small'],
    ['User', (r) => r.user, 'small'],
  ],
  BROWSER_AUTOFILL: [
    ['Last used', (r, t) => t(r.last_used), 'mono small nowrap'],
    ['Field', (r) => <><span className="mono">{r.field}</span> {r.kind !== 'form field' && <Badge>{r.kind}</Badge>}</>, 'small'],
    ['Value', (r) => r.value, 'small strong'],
    ['Uses', (r) => r.times_used ?? '—', 'right'],
    ['First used', (r, t) => t(r.first_used), 'mono small nowrap'],
  ],
  BROWSER_LOGIN: [
    ['Saved', (r, t) => t(r.created), 'mono small nowrap'],
    ['Site', (r) => <span className="mono">{r.site}</span>, 'small cell-path'],
    ['User name', (r) => (r.never_save ? <Badge>NEVER SAVE</Badge> : r.username || (r.username_encrypted ? <Badge>ENCRYPTED</Badge> : '—')), 'small'],
    ['Password', (r) => (r.password_saved ? <Badge tone="warn">SAVED (ENCRYPTED)</Badge> : '—')],
    ['Last used', (r, t) => t(r.last_used), 'mono small nowrap'],
    ['Uses', (r) => r.times_used ?? '—', 'right'],
  ],
};

export function BrowserPage() {
  const { caseId, overview } = useCase();
  const time = useTime();
  const [kind, setKind] = useState<Kind>('BROWSER_HISTORY');
  const [browser, setBrowser] = useState('');
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [skip, setSkip] = useState(0);
  useEffect(() => setSkip(0), [kind, browser, search]);

  const params = new URLSearchParams({ case_id: caseId, kind, limit: String(LIMIT), skip: String(skip) });
  if (browser) params.set('browser', browser);
  if (search) params.set('search', search);
  const res = useApi<{ data: Artifact[]; total: number }>(`/forensics/browser?${params}`);
  const { error, loading } = res;
  // Until the new tab's rows arrive, the previous tab's are still loaded: never draw them under this tab's columns.
  const data = res.dataPath && new URLSearchParams(res.dataPath.split('?')[1]).get('kind') === kind ? res.data : null;
  const counts = overview?.counts;
  const cols = COLUMNS[kind];

  return (
    <div className="stack">
      <PageHeader
        title="Browser history"
        subtitle="Parsed from the browser profiles found inside the analyzed images: Chrome, Edge, Brave, Opera, Vivaldi and Firefox. Each row names the database it came from."
      />
      <Card flush>
        <Tabs<Kind>
          value={kind}
          onChange={setKind}
          tabs={[
            { id: 'BROWSER_HISTORY', label: 'History', count: counts?.browser_history },
            { id: 'BROWSER_DOWNLOAD', label: 'Downloads', count: counts?.browser_downloads },
            { id: 'BROWSER_SEARCH', label: 'Searches', count: counts?.browser_searches },
            { id: 'BROWSER_RECOVERED', label: 'Recovered history', count: counts?.browser_recovered },
            { id: 'BROWSER_COOKIE', label: 'Cookies', count: counts?.browser_cookies },
            { id: 'BROWSER_BOOKMARK', label: 'Bookmarks', count: counts?.browser_bookmarks },
            { id: 'BROWSER_AUTOFILL', label: 'Autofill', count: counts?.browser_autofill },
            { id: 'BROWSER_LOGIN', label: 'Saved logins', count: counts?.browser_logins },
          ]}
        />
        {NOTES[kind] && <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[kind]}</p>}
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
          <select className="select sm" style={{ width: 150 }} value={browser} onChange={(e) => setBrowser(e.target.value)} aria-label="Browser">
            <option value="">All browsers</option>
            {BROWSERS.map((b) => <option key={b}>{b}</option>)}
          </select>
          <input className="input sm" style={{ maxWidth: 320 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())} placeholder="Search this tab" aria-label="Search" />
          <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
          {search && <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); }}>Clear</Button>}
          <span className="small muted">{data ? `${data.total.toLocaleString()} records` : ''}</span>
        </div>
        <ErrorBanner error={error} />
        {loading && !data ? (
          <Loading />
        ) : !data?.data.length ? (
          <Empty title="No browser records" text={browser || search ? 'Nothing matches these filters.' : 'No browser profiles with these records were found in the analyzed images.'} />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Browser</th>{cols.map(([h, , cls]) => <th key={h} className={cls?.includes('right') ? 'right' : undefined}>{h}</th>)}<th /></tr></thead>
              <tbody>
                {data.data.map((r) => (
                  <tr key={r._id}>
                    <td><Badge tone={kind === 'BROWSER_DOWNLOAD' ? 'accent' : 'info'}>{r.browser || '—'}</Badge></td>
                    {cols.map(([h, cell, cls]) => <td key={h} className={cls}>{cell(r, time)}</td>)}
                    <td className="nowrap right"><TagButton type="BROWSER" id={r._id} title={r.title || r.term || r.url || r.target_path || r.site || r.host} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />}
      </Card>
    </div>
  );
}

import { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import type { Artifact } from '../lib/types';
import { Badge, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, Tabs } from '../ui';

const LIMIT = 100;
const BROWSERS = ['Chrome', 'Edge', 'Brave', 'Chromium', 'Firefox'];
type Kind = 'BROWSER_HISTORY' | 'BROWSER_DOWNLOAD';

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

  return (
    <div className="stack">
      <PageHeader
        title="Browser history"
        subtitle="Parsed from the browser databases found inside the analyzed images: Chrome, Edge and Brave History files, and Firefox places.sqlite. Each row names the database it came from."
      />
      <Card flush>
        <Tabs<Kind>
          value={kind}
          onChange={setKind}
          tabs={[
            { id: 'BROWSER_HISTORY', label: 'History', count: counts?.browser_history },
            { id: 'BROWSER_DOWNLOAD', label: 'Downloads', count: counts?.browser_downloads },
          ]}
        />
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
          <select className="select sm" style={{ width: 150 }} value={browser} onChange={(e) => setBrowser(e.target.value)} aria-label="Browser">
            <option value="">All browsers</option>
            {BROWSERS.map((b) => <option key={b}>{b}</option>)}
          </select>
          <input className="input sm" style={{ maxWidth: 320 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())} placeholder="Search URLs, titles, file names" aria-label="Search" />
          <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
          {search && <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); }}>Clear</Button>}
          <span className="small muted">{data ? `${data.total.toLocaleString()} records` : ''}</span>
        </div>
        <ErrorBanner error={error} />
        {loading && !data ? (
          <Loading />
        ) : !data?.data.length ? (
          <Empty title="No browser records" text={browser || search ? 'Nothing matches these filters.' : 'No Chrome, Edge, Brave or Firefox databases were found in the analyzed images.'} />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                {kind === 'BROWSER_HISTORY' ? (
                  <tr><th>Browser</th><th>Last visit</th><th className="right">Visits</th><th>Page</th><th>Source database</th><th /></tr>
                ) : (
                  <tr><th>Browser</th><th>Started</th><th>Saved to</th><th>From</th><th className="right">Size</th><th /></tr>
                )}
              </thead>
              <tbody>
                {data.data.map((r) =>
                  kind === 'BROWSER_HISTORY' ? (
                    <tr key={r._id}>
                      <td><Badge tone="info">{r.browser || '—'}</Badge></td>
                      <td className="mono small nowrap">{time(r.last_visit_time)}</td>
                      <td className="right">{r.visit_count}</td>
                      <td className="cell-path"><div className="strong">{r.title || <span className="muted">(no title)</span>}</div><div className="small mono muted">{r.url}</div></td>
                      <td className="cell-path tiny muted">{r.source_path}<div>{r.evidence_id}</div></td>
                      <td className="nowrap right"><TagButton type="BROWSER" id={r._id} title={r.title || r.url} /></td>
                    </tr>
                  ) : (
                    <tr key={r._id}>
                      <td><Badge tone="accent">{r.browser || '—'}</Badge></td>
                      <td className="mono small nowrap">{time(r.start_time)}</td>
                      <td className="cell-path mono small">{r.target_path}</td>
                      <td className="cell-path mono small muted">{r.tab_url}</td>
                      <td className="right small nowrap">{r.total_bytes ? formatBytes(r.total_bytes) : '—'}</td>
                      <td className="nowrap right"><TagButton type="BROWSER" id={r._id} title={r.target_path} /></td>
                    </tr>
                  ),
                )}
              </tbody>
            </table>
          </div>
        )}
        {data && <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />}
      </Card>
    </div>
  );
}

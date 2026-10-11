import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Search as SearchIcon } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { api } from '../lib/api';
import { formatBytes, useTime } from '../lib/format';
import { Badge, Banner, Button, Card, Empty, PageHeader } from '../ui';

interface Results {
  query: string;
  totals: Record<string, number>;
  results: Record<string, any[]>;
}

export function SearchPage() {
  const { caseId } = useCase();
  const time = useTime();
  const [params] = useSearchParams();
  const [q, setQ] = useState(params.get('q') || '');
  const [res, setRes] = useState<Results | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function run(e?: FormEvent, term = q) {
    e?.preventDefault();
    if (term.trim().length < 2) return;
    setBusy(true);
    setError('');
    try {
      setRes(await api<Results>(`/forensics/search?case_id=${encodeURIComponent(caseId)}&q=${encodeURIComponent(term.trim())}`));
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  // A search started from the top bar arrives as ?q=…
  useEffect(() => {
    const term = params.get('q');
    if (term) {
      setQ(term);
      run(undefined, term);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params, caseId]);

  const total = res ? Object.values(res.totals).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="stack">
      <PageHeader title="Keyword search" subtitle="Case-insensitive search across file paths (including deleted files), timeline events, browser history and downloads, USB devices, Windows activity, findings and user accounts in the active case." />
      <Card>
        <form className="row" onSubmit={run}>
          <input className="input grow" style={{ maxWidth: 520 }} value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. payroll, SecureDelete, AA951D0000007252, .ps1" autoFocus aria-label="Keyword" />
          <Button type="submit" variant="primary" icon={<SearchIcon size={15} />} busy={busy} disabled={q.trim().length < 2}>Search</Button>
        </form>
      </Card>
      {error && <Banner tone="danger">{error}</Banner>}
      {res && (
        <>
          <p className="muted" style={{ margin: 0 }}>{total.toLocaleString()} matches for “{res.query}”.</p>
          {!total && <Card><Empty title="No matches" text="Try a shorter term or part of a file name, URL or serial number." /></Card>}
          <Group title="Files" total={res.totals.files} shown={res.results.files.length} link={{ to: '/app/files', label: 'Open deleted files' }}>
            {res.results.files.map((f) => (
              <tr key={f._id}>
                <td className="cell-path mono small">{f.path}</td>
                <td>{f.deleted && <Badge tone="danger">DELETED</Badge>}</td>
                <td className="small nowrap">{f.is_dir ? 'folder' : formatBytes(f.size)}</td>
                <td className="mono small">{f.evidence_id}</td>
              </tr>
            ))}
          </Group>
          <Group title="Timeline events" total={res.totals.timeline} shown={res.results.timeline.length} link={{ to: '/app/timeline', label: 'Open timeline' }}>
            {res.results.timeline.map((e) => (
              <tr key={e._id}>
                <td className="mono small nowrap">{time(e.timestamp)}</td>
                <td className="small">{e.type}</td>
                <td className="cell-path small" colSpan={2}>{e.description}</td>
              </tr>
            ))}
          </Group>
          <Group title="Browser records" total={res.totals.browser} shown={res.results.browser.length} link={{ to: '/app/browser', label: 'Open browser history' }}>
            {res.results.browser.map((b) => (
              <tr key={b._id}>
                <td className="small">{b.browser}</td>
                <td className="small">{b.type === 'BROWSER_DOWNLOAD' ? 'Download' : 'Visit'}</td>
                <td className="cell-path small mono" colSpan={2}>{b.type === 'BROWSER_DOWNLOAD' ? `${b.target_path} ← ${b.tab_url}` : `${b.url}${b.title ? ` — ${b.title}` : ''}`}</td>
              </tr>
            ))}
          </Group>
          <Group title="USB devices" total={res.totals.usb} shown={res.results.usb.length} link={{ to: '/app/usb', label: 'Open USB devices' }}>
            {res.results.usb.map((u) => (
              <tr key={u._id}>
                <td className="small strong">{u.friendly_name || `${u.vendor} ${u.product}`}</td>
                <td className="mono small">{u.serial}</td>
                <td className="small" colSpan={2}>{u.source}</td>
              </tr>
            ))}
          </Group>
          <Group title="Windows activity" total={res.totals.activity} shown={(res.results.activity || []).length} link={{ to: '/app/activity', label: 'Open Windows activity' }}>
            {(res.results.activity || []).map((a) => (
              <tr key={a._id}>
                <td className="small">{a.type === 'PROGRAM_RUN' ? 'Program run' : a.type === 'RECENT_FILE' ? 'File opened' : 'Recycle Bin'}</td>
                <td className="mono small nowrap">{time(a.last_run || a.lnk_modified || a.deleted_time)}</td>
                <td className="cell-path small mono" colSpan={2}>{a.executable_path || a.executable || a.target_path || a.original_path}</td>
              </tr>
            ))}
          </Group>
          <Group title="User accounts" total={res.totals.accounts ?? 0} shown={(res.results.accounts || []).length} link={{ to: '/app/computer', label: 'Open computer and users' }}>
            {(res.results.accounts || []).map((a) => (
              <tr key={a._id}>
                <td className="small strong">{a.username}{a.full_name && <span className="muted"> ({a.full_name})</span>}</td>
                <td className="mono small">{a.sid}</td>
                <td className="small" colSpan={2}>{a.profile_path}</td>
              </tr>
            ))}
          </Group>
          <Group title="Findings" total={res.totals.findings} shown={res.results.findings.length} link={{ to: '/app/findings', label: 'Open findings' }}>
            {res.results.findings.map((f) => (
              <tr key={f._id}>
                <td className="small strong">{f.title}</td>
                <td><Badge>{f.severity}</Badge></td>
                <td className="small" colSpan={2}>{f.description}</td>
              </tr>
            ))}
          </Group>
        </>
      )}
    </div>
  );
}

function Group({ title, total, shown, link, children }: { title: string; total: number; shown: number; link: { to: string; label: string }; children: ReactNode }) {
  if (!total) return null;
  return (
    <Card title={`${title} (${total.toLocaleString()})`} subtitle={total > shown ? `Showing the first ${shown}` : undefined} actions={<Link className="btn sm" to={link.to}>{link.label}</Link>} flush>
      <div className="table-wrap">
        <table className="table"><tbody>{children}</tbody></table>
      </div>
    </Card>
  );
}

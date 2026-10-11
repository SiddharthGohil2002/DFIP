import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { FileSearch, Search as SearchIcon } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { api, post } from '../lib/api';
import { formatBytes, formatNumber, useTime } from '../lib/format';
import { TagButton } from '../lib/tags';
import type { ContentHit, ContentResults } from '../lib/types';
import { ViewButton } from '../ui/FileViewer';
import { Badge, Banner, Button, Card, Empty, PageHeader, Pager, Tabs, useToast } from '../ui';

interface Results {
  query: string;
  totals: Record<string, number>;
  results: Record<string, any[]>;
}

type Mode = 'records' | 'text' | 'regex';
const MODES: { id: Mode; label: string }[] = [
  { id: 'records', label: 'Names and records' },
  { id: 'text', label: 'File contents' },
  { id: 'regex', label: 'Regular expression' },
];
const MIN: Record<Mode, number> = { records: 2, text: 3, regex: 1 };
const PLACEHOLDER: Record<Mode, string> = {
  records: 'e.g. payroll, SecureDelete, AA951D0000007252, .ps1',
  text: 'e.g. DE89370400440532013, sandisk, transfer the payroll',
  regex: 'e.g. emp05\\d,DE\\d{20}  or  (?i)wipe .{0,20}drive',
};
const METHOD: Record<ContentHit['method'], string> = {
  text: 'text file', strings: 'strings', pdf: 'PDF text', ooxml: 'Office document', odf: 'OpenDocument', rtf: 'RTF',
};
const LIMIT = 50;

export function SearchPage() {
  const { caseId } = useCase();
  const time = useTime();
  const [params] = useSearchParams();
  const [mode, setMode] = useState<Mode>((params.get('mode') as Mode) || 'records');
  const [q, setQ] = useState(params.get('q') || '');
  const [res, setRes] = useState<Results | null>(null);
  const [content, setContent] = useState<ContentResults | null>(null);
  const [skip, setSkip] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function run(e?: FormEvent, term = q, m = mode, from = 0) {
    e?.preventDefault();
    const t = m === 'regex' ? term : term.trim();
    if (t.length < MIN[m]) return;
    setBusy(true);
    setError('');
    try {
      const enc = encodeURIComponent(caseId);
      if (m === 'records') {
        setContent(null);
        setRes(await api<Results>(`/forensics/search?case_id=${enc}&q=${encodeURIComponent(t)}`));
      } else {
        setRes(null);
        setContent(await api<ContentResults>(`/forensics/content-search?case_id=${enc}&mode=${m}&q=${encodeURIComponent(t)}&skip=${from}&limit=${LIMIT}`));
        setSkip(from);
      }
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
      const m = (params.get('mode') as Mode) || 'records';
      setQ(term);
      setMode(m);
      run(undefined, term, m);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params, caseId]);

  function switchMode(m: Mode) {
    setMode(m);
    setRes(null);
    setContent(null);
    setError('');
  }

  const total = res ? Object.values(res.totals).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="stack">
      <PageHeader
        title="Keyword search"
        subtitle="Names and records: file paths (including deleted files), timeline, browser, USB, Windows activity, findings, user accounts and found data. File contents: the text inside documents, PDFs, text files and the strings of other files (Full analysis). Every content search is recorded in the audit log."
      />
      <Card flush>
        <Tabs<Mode> value={mode} onChange={switchMode} tabs={MODES} />
        <form className="row" style={{ padding: 14 }} onSubmit={(e) => run(e)}>
          <input className={`input grow ${mode === 'regex' ? 'mono' : ''}`} style={{ maxWidth: 560 }} value={q} onChange={(e) => setQ(e.target.value)}
            placeholder={PLACEHOLDER[mode]} autoFocus aria-label={mode === 'regex' ? 'Regular expression' : 'Keyword'} />
          <Button type="submit" variant="primary" icon={<SearchIcon size={15} />} busy={busy} disabled={(mode === 'regex' ? q : q.trim()).length < MIN[mode]}>Search</Button>
          {mode === 'text' && <span className="small muted">Case-insensitive; matches parts of words; at least 3 characters.</span>}
          {mode === 'regex' && <span className="small muted">RE2 syntax, case-sensitive (start with <code>(?i)</code> to ignore case).</span>}
        </form>
      </Card>
      {error && <Banner tone="danger">{error}</Banner>}
      {content && <ContentResultsView r={content} onPage={(from) => run(undefined, content.query, content.mode, from)} skip={skip} />}
      {res && (
        <>
          <p className="muted" style={{ margin: 0 }}>{total.toLocaleString()} matches for “{res.query}”.</p>
          {!total && <Card><Empty title="No matches" text="Try a shorter term or part of a file name, URL or serial number, or search the file contents." /></Card>}
          <Group title="Files" total={res.totals.files} shown={res.results.files.length} link={{ to: '/app/files', label: 'Open files' }}>
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
          <Group title="Found data" total={res.totals.found ?? 0} shown={(res.results.found || []).length} link={{ to: '/app/found-data', label: 'Open found data' }}>
            {(res.results.found || []).map((f) => (
              <tr key={f._id}>
                <td className="small">{f.label || f.kind}</td>
                <td className="mono small">{f.display}</td>
                <td className="small" colSpan={2}>{f.count} occurrence{f.count === 1 ? '' : 's'} in {f.file_count} file{f.file_count === 1 ? '' : 's'} · {f.evidence_id}</td>
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

function ContentResultsView({ r, skip, onPage }: { r: ContentResults; skip: number; onPage: (skip: number) => void }) {
  const { can } = useAuth();
  const toast = useToast();
  const [queued, setQueued] = useState<string[]>([]);

  async function index(eid: string) {
    try {
      const j = await post<{ job_id: string }>(`/jobs/analysis/${encodeURIComponent(eid)}`, { modules: ['content', 'found_data'] });
      setQueued((x) => [...x, eid]);
      toast(`Indexing the file contents of ${eid} (${j.job_id})`, 'ok');
    } catch (e: any) {
      toast(e.message, 'danger');
    }
  }

  return (
    <>
      {r.not_indexed.length > 0 && (
        <Banner tone="info">
          <div className="stack" style={{ gap: 6 }}>
            <div>The file contents of {r.not_indexed.length === 1 ? 'this evidence item are' : 'these evidence items are'} not indexed, so they were not searched.
              Run the analysis with the Full profile, or index them here.</div>
            {r.not_indexed.map((e) => (
              <div key={e.evidence_id} className="row" style={{ gap: 8 }}>
                <span className="mono small">{e.evidence_id}</span><span className="small muted">{e.filename}</span>
                {can('ANALYSIS_RUN') && (queued.includes(e.evidence_id)
                  ? <Badge tone="accent">INDEXING</Badge>
                  : <Button size="sm" icon={<FileSearch size={13} />} onClick={() => index(e.evidence_id)}>Index file contents</Button>)}
              </div>
            ))}
          </div>
        </Banner>
      )}
      <p className="muted" style={{ margin: 0 }}>
        {formatNumber(r.total_matches)} match{r.total_matches === 1 ? '' : 'es'} in {formatNumber(r.total_files)} file{r.total_files === 1 ? '' : 's'} for{' '}
        {r.mode === 'regex' ? <code>{r.query}</code> : `“${r.query}”`} ({(r.elapsed_ms / 1000).toFixed(1)} s).
      </p>
      {!r.complete && <Banner tone="warn">The search stopped at its time limit or result limit, so more files may match. Use a longer or more specific term.</Banner>}
      {!r.files.length && r.not_indexed.length < 1 && <Card><Empty title="No matches" text="No indexed file contains this text." /></Card>}
      {r.files.map((h) => (
        <Card key={`${h.evidence_id}:${h.volume_id}:${h.inode}:${h.path}`} flush>
          <div className="row" style={{ padding: '12px 14px', justifyContent: 'space-between', borderBottom: '1px solid var(--border)' }}>
            <div className="stack" style={{ gap: 4, minWidth: 0 }}>
              <span className="mono small strong" style={{ wordBreak: 'break-all' }}>{h.path}</span>
              <span className="row" style={{ gap: 6 }}>
                {h.deleted && <Badge tone="danger">DELETED</Badge>}
                <Badge>{METHOD[h.method]}{h.encoding && h.method === 'text' ? ` · ${h.encoding}` : ''}</Badge>
                <span className="small muted">{h.evidence_id} · {formatBytes(h.size)} · {formatNumber(h.match_count)} match{h.match_count === 1 ? '' : 'es'}</span>
              </span>
            </div>
            <span className="row nowrap" style={{ gap: 6 }}>
              {h.entry_id && <TagButton type="FILE" id={h.entry_id} title={h.path} />}
              {h.partition_offset !== null && <ViewButton source={{ kind: 'image', evidenceId: h.evidence_id, inode: h.inode, offset: h.partition_offset, name: h.path }} />}
            </span>
          </div>
          <div className="snippets" style={{ padding: '4px 14px 12px' }}>
            {h.matches.map((m) => (
              <div key={m.text_offset} className="snippet-row">
                <span className="snippet">{m.before}<mark>{m.match}</mark>{m.after}</span>
                {m.byte_offset !== null && h.partition_offset !== null ? (
                  <ViewButton source={{ kind: 'image', evidenceId: h.evidence_id, inode: h.inode, offset: h.partition_offset, name: h.path }}
                    at={{ offset: m.byte_offset, length: m.byte_length }} />
                ) : (
                  <span className="tiny muted nowrap" title="The text was taken out of the document (for example a compressed Word file), so it has no position in the file's bytes.">in extracted text</span>
                )}
              </div>
            ))}
            {h.match_count > h.matches.length && <div className="tiny muted">Showing the first {h.matches.length} of {formatNumber(h.match_count)} matches in this file.</div>}
            {h.truncated && <div className="tiny muted">Only the start of this file was indexed (its text is longer than the index keeps per file).</div>}
          </div>
        </Card>
      ))}
      <Pager skip={skip} limit={LIMIT} total={r.total_files} onChange={onPage} />
    </>
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

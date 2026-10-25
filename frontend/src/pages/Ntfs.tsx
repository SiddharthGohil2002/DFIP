import { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import { ViewButton } from '../ui/FileViewer';
import { ExportButton } from '../ui/ExportButton';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, Tabs, type Tone } from '../ui';

type Tab = 'TIMESTOMP' | 'STREAMS' | 'USN';
const LIMIT = 200;
const REASON_TONE: Record<string, Tone> = { FILE_DELETE: 'danger', DATA_OVERWRITE: 'danger', BASIC_INFO_CHANGE: 'warn', RENAME_NEW_NAME: 'warn',
  RENAME_OLD_NAME: 'warn', FILE_CREATE: 'ok', STREAM_CHANGE: 'accent' };
const NOTES: Record<Tab, string> = {
  TIMESTOMP: 'Any program can set a file\'s $STANDARD_INFORMATION times; Windows sets $FILE_NAME times when the name is created. "Strong": the created, modified and accessed times are one whole-second value earlier than the name\'s creation, the pattern timestomping tools leave. "Possible": an earlier, whole-second creation time in a user\'s folder. Copying, archives and installers change times too, so check before concluding.',
  STREAMS: 'Extra data stored next to a file. Zone.Identifier (the Mark of the Web) records that a file came from the internet, and from where; other streams can hide data.',
  USN: 'The NTFS change journal: every change Windows recorded to files on the volume, oldest first, including files that were later renamed and deleted. The last record of each change ("CLOSE") holds all of its reasons.',
};

export function NtfsPage() {
  const { caseId, overview } = useCase();
  const [tab, setTab] = useState<Tab>('TIMESTOMP');
  const c = overview?.counts;
  const volumesPath = `/forensics/ntfs/volumes?case_id=${encodeURIComponent(caseId)}`;
  const volumes = useApi<{ data: any[] }>(volumesPath);
  return (
    <div className="stack">
      <PageHeader
        title="File system journal"
        subtitle="NTFS internals: files whose times look altered (timestomping), alternate data streams including where downloads came from, and the USN change journal of files created, renamed and deleted."
      />
      {volumes.data && !volumes.data.data.length && (
        <Banner tone="info">No NTFS volume has been analysed in this case. NTFS volumes are read by the Standard and Full analysis profiles (module "NTFS: timestomping, alternate data streams and USN journal").</Banner>
      )}
      <Card flush>
        <Tabs<Tab> value={tab} onChange={setTab} tabs={[
          { id: 'TIMESTOMP', label: 'Timestomping', count: c?.timestomp_suspects },
          { id: 'STREAMS', label: 'Alternate data streams', count: c?.alternate_streams },
          { id: 'USN', label: 'USN journal', count: c?.usn_records },
        ]} />
        <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[tab]}</p>
        {tab === 'TIMESTOMP' && <Timestomp caseId={caseId} />}
        {tab === 'STREAMS' && <Streams caseId={caseId} />}
        {tab === 'USN' && <Usn caseId={caseId} />}
      </Card>
      {!!volumes.data?.data.length && (
        <Card title="NTFS volumes read" actions={<ExportButton path={volumesPath} what="list of volumes" />}>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Evidence</th><th>Volume</th><th>Serial number</th><th className="right">MFT entries</th><th className="right">Journal records</th></tr></thead>
              <tbody>
                {volumes.data.data.map((v) => (
                  <tr key={`${v.evidence_id}${v.volume_id}`}>
                    <td className="mono small">{v.evidence_id}</td><td className="small">{v.name || '—'} <span className="muted mono">({v.volume_id})</span></td>
                    <td className="mono small">{v.serial_number || '—'}</td>
                    <td className="right mono">{(v.mft_entries ?? 0).toLocaleString()}</td><td className="right mono">{(v.usn_records ?? 0).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

function SearchRow({ placeholder, onSearch, exportPath, children }: {
  placeholder: string; onSearch: (s: string) => void; exportPath: string | null; children?: React.ReactNode;
}) {
  const [q, setQ] = useState('');
  return (
    <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
      <input className="input sm" style={{ maxWidth: 320 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && onSearch(q.trim())}
        placeholder={placeholder} aria-label="Search" />
      <Button size="sm" icon={<Search size={13} />} onClick={() => onSearch(q.trim())}>Search</Button>
      {children}
      <span style={{ flex: 1 }} />
      <ExportButton path={exportPath} />
    </div>
  );
}

function Timestomp({ caseId }: { caseId: string }) {
  const time = useTime();
  const [search, setSearch] = useState('');
  const [level, setLevel] = useState('');
  const [skip, setSkip] = useState(0);
  useEffect(() => setSkip(0), [search, level]);
  const qs = new URLSearchParams({ case_id: caseId, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (level) qs.set('level', level);
  const path = `/forensics/ntfs/timestomp?${qs}`;
  const { data, error, loading } = useApi<{ data: any[]; total: number }>(path);
  return (
    <>
      <SearchRow placeholder="Search paths" onSearch={setSearch} exportPath={data?.data.length ? path : null}>
        <select className="input sm" style={{ maxWidth: 180 }} value={level} onChange={(e) => setLevel(e.target.value)} aria-label="Level">
          <option value="">Strong and possible</option><option value="strong">Strong</option><option value="possible">Possible</option>
        </select>
      </SearchRow>
      <ErrorBanner error={error} />
      {loading && !data ? <Loading /> : !data?.data.length ? <Empty title="No file times look altered" /> : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>File</th><th>Created ($SI)</th><th>Name created ($FN)</th><th>Changed ($SI)</th><th>Why</th><th /></tr></thead>
              <tbody>
                {data.data.map((t) => (
                  <tr key={t._id}>
                    <td className="small"><span className="mono cell-path">{t.path}</span>{' '}
                      <Badge tone={t.level === 'strong' ? 'danger' : 'warn'}>{t.level.toUpperCase()}</Badge>
                      {!t.allocated && <Badge tone="warn">DELETED</Badge>}
                      <div className="tiny muted">MFT entry {t.entry}</div></td>
                    <td className="mono tiny nowrap">{time(t.si_created)}<div className="faint">modified {time(t.si_modified)}</div></td>
                    <td className="mono tiny nowrap">{time(t.fn_created)}</td>
                    <td className="mono tiny nowrap">{time(t.si_changed)}</td>
                    <td className="small">{(t.reasons || []).join('; ')}</td>
                    <td><TagButton type="WINDOWS" id={t._id} title={t.path} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />
        </>
      )}
    </>
  );
}

function Streams({ caseId }: { caseId: string }) {
  const [search, setSearch] = useState('');
  const [downloaded, setDownloaded] = useState(false);
  const [skip, setSkip] = useState(0);
  useEffect(() => setSkip(0), [search, downloaded]);
  const qs = new URLSearchParams({ case_id: caseId, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (downloaded) qs.set('downloaded', 'true');
  const path = `/forensics/ntfs/streams?${qs}`;
  const { data, error, loading } = useApi<{ data: any[]; total: number }>(path);
  return (
    <>
      <SearchRow placeholder="Search paths, addresses and content" onSearch={setSearch} exportPath={data?.data.length ? path : null}>
        <label className="check"><input type="checkbox" checked={downloaded} onChange={(e) => setDownloaded(e.target.checked)} /> Downloaded files only</label>
      </SearchRow>
      <ErrorBanner error={error} />
      {loading && !data ? <Loading /> : !data?.data.length ? <Empty title="No alternate data streams" /> : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Stream</th><th className="right">Size</th><th>What it says</th><th /></tr></thead>
              <tbody>
                {data.data.map((s) => (
                  <tr key={s._id}>
                    <td className="small"><span className="mono cell-path">{s.path}</span>
                      {s.kind && <div><Badge tone={s.zone ? 'accent' : 'neutral'}>{s.kind}</Badge></div>}
                      {!s.kind && <div><Badge tone="warn">HIDDEN DATA?</Badge></div>}</td>
                    <td className="right mono small">{formatBytes(s.size)}</td>
                    <td className="small">
                      {s.zone ? (
                        <>
                          <div>{s.zone.ZoneName || `Zone ${s.zone.ZoneId}`}</div>
                          {s.zone.HostUrl && <div className="mono tiny cell-path">from {s.zone.HostUrl}</div>}
                          {s.zone.ReferrerUrl && <div className="mono tiny cell-path muted">page {s.zone.ReferrerUrl}</div>}
                        </>
                      ) : s.text ? <span className="mono tiny" style={{ whiteSpace: 'pre-wrap' }}>{s.text.slice(0, 300)}</span> : <span className="faint">binary data</span>}
                    </td>
                    <td className="nowrap">
                      {s.inode && <ViewButton source={{ kind: 'image', evidenceId: s.evidence_id, inode: s.inode, offset: s.partition_offset, name: s.path }} />}
                      <TagButton type="WINDOWS" id={s._id} title={s.path} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />
        </>
      )}
    </>
  );
}

function Usn({ caseId }: { caseId: string }) {
  const time = useTime();
  const [search, setSearch] = useState('');
  const [reason, setReason] = useState('');
  const [closing, setClosing] = useState(false);
  const [skip, setSkip] = useState(0);
  useEffect(() => setSkip(0), [search, reason, closing]);
  const qs = new URLSearchParams({ case_id: caseId, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (reason) qs.set('reason', reason);
  if (closing) qs.set('closing', 'true');
  const path = `/forensics/ntfs/usn?${qs}`;
  const { data, error, loading } = useApi<{ data: any[]; total: number }>(path);
  return (
    <>
      <SearchRow placeholder="Search file names and paths" onSearch={setSearch} exportPath={data?.data.length ? path : null}>
        <select className="input sm" style={{ maxWidth: 200 }} value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Change">
          <option value="">Every change</option>
          {['FILE_CREATE', 'FILE_DELETE', 'RENAME_NEW_NAME', 'RENAME_OLD_NAME', 'DATA_OVERWRITE', 'BASIC_INFO_CHANGE', 'STREAM_CHANGE', 'SECURITY_CHANGE'].map((r) =>
            <option key={r} value={r}>{r}</option>)}
        </select>
        <label className="check"><input type="checkbox" checked={closing} onChange={(e) => setClosing(e.target.checked)} /> Closing records only</label>
      </SearchRow>
      <ErrorBanner error={error} />
      {loading && !data ? <Loading /> : !data?.data.length ? <Empty title="No journal records" text="No NTFS volume with a USN change journal ($Extend\$UsnJrnl) was analysed, or nothing matches." /> : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Time</th><th>File</th><th>Change</th><th className="right">Entry</th><th className="right">USN</th><th /></tr></thead>
              <tbody>
                {data.data.map((x) => (
                  <tr key={x._id}>
                    <td className="mono tiny nowrap">{time(x.time)}</td>
                    <td className="small"><span className="mono cell-path">{x.path || x.name}</span>
                      {!x.path && <div className="tiny muted">in folder MFT entry {x.parent_entry}</div>}</td>
                    <td className="small"><span className="row" style={{ gap: 3 }}>{(x.reasons || []).map((r: string) =>
                      <Badge key={r} tone={REASON_TONE[r] || 'neutral'}>{r}</Badge>)}</span></td>
                    <td className="right mono small">{x.entry}-{x.sequence}</td>
                    <td className="right mono small">{x.usn.toLocaleString()}</td>
                    <td><TagButton type="USN" id={x._id} title={x.path || x.name} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />
        </>
      )}
    </>
  );
}

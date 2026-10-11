import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Download, File, FileSearch, Folder, RotateCcw, Search } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { api, downloadFile, post } from '../lib/api';
import { formatBytes, formatNumber, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import { ViewButton } from '../ui/FileViewer';
import type { Artifact, FsEntry } from '../lib/types';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Hash, Loading, Modal, PageHeader, Pager, Tabs, useToast } from '../ui';

const LIMIT = 100;
type Tab = 'deleted' | 'all' | 'recovered';

export function FilesPage() {
  const { overview, caseId, reloadOverview } = useCase();
  const [params, setParams] = useSearchParams();
  const analyzed = (overview?.evidence || []).filter((e) => e.analysis_status === 'COMPLETED');
  const evidenceId = params.get('evidence') || analyzed[0]?.evidence_id || '';
  const [tab, setTab] = useState<Tab>('deleted');
  const counts = overview?.counts;

  return (
    <div className="stack">
      <PageHeader
        title="Deleted files"
        subtitle="The file index Sleuth Kit (fls) built for each analyzed image, including deleted entries still described by the filesystem. Recovery copies a file out with icat; the original image is never modified."
        actions={
          analyzed.length > 0 && (
            <select className="select" style={{ width: 300 }} value={evidenceId} onChange={(e) => setParams({ evidence: e.target.value })} aria-label="Evidence">
              {analyzed.map((e) => <option key={e.evidence_id} value={e.evidence_id}>{e.evidence_id} — {e.filename}</option>)}
            </select>
          )
        }
      />
      {!overview ? (
        <Loading />
      ) : !analyzed.length ? (
        <Card><Empty title="No analyzed evidence" text={<>Run the full analysis on an image (<Link to="/app/evidence">Evidence</Link>) to build its file index.</>} /></Card>
      ) : (
        <Card flush>
          <Tabs<Tab>
            value={tab}
            onChange={setTab}
            tabs={[
              { id: 'deleted', label: 'Deleted entries' },
              { id: 'all', label: 'All files' },
              { id: 'recovered', label: 'Recovered files', count: counts?.recovered_files },
            ]}
          />
          {tab === 'recovered' ? (
            <RecoveredFiles caseId={caseId} />
          ) : (
            <FileIndex key={`${evidenceId}-${tab}`} evidenceId={evidenceId} deletedOnly={tab === 'deleted'} onRecovered={reloadOverview} />
          )}
        </Card>
      )}
    </div>
  );
}

function FileIndex({ evidenceId, deletedOnly, onRecovered }: { evidenceId: string; deletedOnly: boolean; onRecovered: () => void }) {
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [skip, setSkip] = useState(0);
  const [recovered, setRecovered] = useState<Record<string, any>>({});
  const [busy, setBusy] = useState('');
  useEffect(() => setSkip(0), [search]);
  const path = `/forensics/evidence/${encodeURIComponent(evidenceId)}/files?limit=${LIMIT}&skip=${skip}${deletedOnly ? '&deleted=true' : ''}${search ? `&q=${encodeURIComponent(search)}` : ''}`;
  const { data, error, loading } = useApi<{ data: FsEntry[]; total: number }>(path);

  async function recover(f: FsEntry) {
    const key = `${f.partition_offset}:${f.inode}`;
    setBusy(key);
    try {
      const r = await post<any>(`/forensics/evidence/${encodeURIComponent(evidenceId)}/recover?inode=${encodeURIComponent(f.inode)}&offset=${f.partition_offset}`);
      if (r.status !== 'COMPLETED') throw new Error(r.stderr || `icat ${r.status}`);
      setRecovered((m) => ({ ...m, [key]: r }));
      toast(`Recovered ${r.filename} (${formatBytes(r.size)}) — SHA-256 ${r.sha256.slice(0, 12)}…`, 'ok');
      onRecovered();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
        <input className="input sm" style={{ maxWidth: 340 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())} placeholder="Filter by path, e.g. payroll or .docx" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Filter</Button>
        {search && <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); }}>Clear</Button>}
        <span className="small muted">{data ? `${formatNumber(data.total)} ${deletedOnly ? 'deleted entries' : 'entries'}` : ''}</span>
      </div>
      <ErrorBanner error={error} />
      {loading && !data ? (
        <Loading />
      ) : !data?.data.length ? (
        <Empty title={deletedOnly ? 'No deleted entries' : 'No matching files'} text={deletedOnly ? 'The filesystem metadata in this image describes no deleted files. File carving can still find data in unallocated space.' : undefined} />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Path</th><th>Inode</th><th>Size</th><th>Modified</th><th>Accessed</th><th>Created</th><th /></tr></thead>
            <tbody>
              {data.data.map((f) => {
                const key = `${f.partition_offset}:${f.inode}`;
                const rec = recovered[key];
                return (
                  <tr key={f._id} className={f.deleted ? 'is-deleted' : ''}>
                    <td className="cell-path">
                      <span className="row" style={{ gap: 6, flexWrap: 'nowrap', alignItems: 'flex-start' }}>
                        {f.is_dir ? <Folder size={14} style={{ flex: 'none', marginTop: 2 }} /> : <File size={14} style={{ flex: 'none', marginTop: 2 }} />}
                        <span className={f.deleted ? 'strong' : ''}>{f.path}</span>
                      </span>
                      {f.deleted && <Badge tone="danger">{(f.deleted_status || 'deleted').toUpperCase()}</Badge>}
                    </td>
                    <td className="mono small">{f.inode}</td>
                    <td className="small nowrap">{f.is_dir ? '—' : formatBytes(f.size)}</td>
                    <td className="mono tiny nowrap">{time(f.mtime, false)}</td>
                    <td className="mono tiny nowrap">{time(f.atime, false)}</td>
                    <td className="mono tiny nowrap">{time(f.crtime, false)}</td>
                    <td className="nowrap right">
                      <TagButton type="FILE" id={f._id} title={f.path} />{' '}
                      {!f.is_dir && <ViewButton source={{ kind: 'image', evidenceId, inode: f.inode, offset: f.partition_offset, name: f.path }} />}{' '}
                      {rec ? (
                        <Button size="sm" icon={<Download size={13} />} onClick={() => downloadFile(`/forensics/artifacts/${rec.artifact_id}/download`, rec.filename).catch((e) => toast(e.message, 'danger'))}>
                          Download
                        </Button>
                      ) : (
                        !f.is_dir && can('ANALYSIS_RUN') && (
                          <Button size="sm" icon={<RotateCcw size={13} />} busy={busy === key} onClick={() => recover(f)}>Recover</Button>
                        )
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {data && <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />}
    </>
  );
}

function RecoveredFiles({ caseId }: { caseId: string }) {
  const toast = useToast();
  const time = useTime();
  const { can } = useAuth();
  const { data, error, loading } = useApi<{ data: Artifact[] }>(`/forensics/artifacts?case_id=${encodeURIComponent(caseId)}&artifact_type=RECOVERED_FILE`);
  const [meta, setMeta] = useState<{ name: string; json: any } | null>(null);
  const [busy, setBusy] = useState('');

  async function inspect(a: Artifact) {
    setBusy(a.artifact_id!);
    try {
      const r = await api<any>(`/forensics/artifacts/${a.artifact_id}/metadata`, { method: 'POST' });
      if (!r.available) throw new Error('ExifTool is not installed on the server');
      let json: any = r.stdout;
      try {
        json = JSON.parse(r.stdout)[0];
      } catch {
        /* show raw output */
      }
      setMeta({ name: a.filename || '', json });
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  if (loading && !data) return <Loading />;
  return (
    <>
      <ErrorBanner error={error} />
      {!data?.data.length ? (
        <Empty icon={<RotateCcw size={20} />} title="Nothing recovered yet" text="Recover a file from the Deleted entries or All files tab. Each recovered copy is hashed and logged to the chain of custody." />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>File</th><th>Original path</th><th>Size</th><th>SHA-256</th><th>Recovered</th><th /></tr></thead>
            <tbody>
              {data.data.map((a) => (
                <tr key={a._id}>
                  <td className="strong">{a.filename}{a.was_deleted && <div><Badge tone="danger">WAS DELETED</Badge></div>}</td>
                  <td className="cell-path small">{a.original_path || `inode ${a.inode}`}<div className="muted tiny">{a.evidence_id}</div></td>
                  <td className="small nowrap">{formatBytes(a.size)}</td>
                  <td><Hash value={a.sha256} short={16} /></td>
                  <td className="small nowrap">{time(a.timestamp)}</td>
                  <td className="nowrap right">
                    <TagButton type="ARTIFACT" id={a.artifact_id} title={a.original_path || a.filename} />{' '}
                    {a.artifact_id && <ViewButton source={{ kind: 'artifact', artifactId: a.artifact_id, name: a.filename || a.original_path || 'Recovered file' }} />}{' '}
                    {can('ANALYSIS_RUN') && <Button size="sm" icon={<FileSearch size={13} />} busy={busy === a.artifact_id} onClick={() => inspect(a)}>Metadata</Button>}{' '}
                    <Button size="sm" icon={<Download size={13} />} onClick={() => downloadFile(`/forensics/artifacts/${a.artifact_id}/download`, a.filename || 'recovered.bin').catch((e) => toast(e.message, 'danger'))}>
                      Download
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal open={!!meta} title={`Metadata — ${meta?.name}`} onClose={() => setMeta(null)} wide>
        <Banner tone="info">Extracted with ExifTool from the recovered copy.</Banner>
        {meta && typeof meta.json === 'object' ? (
          <dl className="kv">
            {Object.entries(meta.json).map(([k, v]) => (
              <div key={k} style={{ display: 'contents' }}>
                <dt className="small">{k}</dt>
                <dd className="small mono">{String(v)}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <pre className="pre">{String(meta?.json ?? '')}</pre>
        )}
      </Modal>
    </>
  );
}

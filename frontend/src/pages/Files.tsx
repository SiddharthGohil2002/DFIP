import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Download, File, FileSearch, Folder, Info, RotateCcw, Search } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { api, downloadFile, post } from '../lib/api';
import { formatBytes, formatNumber, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import { Comments } from '../ui/Comments';
import { ViewButton } from '../ui/FileViewer';
import type { Artifact, FsEntry, HashKind } from '../lib/types';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Hash, Loading, Modal, PageHeader, Pager, Tabs, useToast, type Tone } from '../ui';

const LIMIT = 100;
type Tab = 'deleted' | 'all' | 'members' | 'recovered';
type Flag = '' | 'renamed' | 'encrypted' | HashKind;

/** The file categories file processing assigns (from the content, never the name). */
export const CATEGORY_LABELS: Record<string, string> = {
  executable: 'Program', script: 'Script', document: 'Document', archive: 'Archive', image: 'Picture', video: 'Video',
  audio: 'Audio', email: 'Email', database: 'Database', registry: 'Registry hive', shortcut: 'Shortcut', text: 'Text',
  empty: 'Empty', other: 'Other',
};

export const HASH_KIND: Record<HashKind, { label: string; tone: Tone }> = {
  KNOWN_BAD: { label: 'Known bad', tone: 'danger' },
  NOTABLE: { label: 'Notable', tone: 'accent' },
  KNOWN_GOOD: { label: 'Known good', tone: 'ok' },
};

const FLAGS: { id: Flag; label: string }[] = [
  { id: '', label: 'Any file' },
  { id: 'renamed', label: 'Renamed (content does not match the name)' },
  { id: 'encrypted', label: 'Encrypted' },
  { id: 'KNOWN_BAD', label: 'Known bad (hash set)' },
  { id: 'NOTABLE', label: 'Notable (hash set)' },
  { id: 'KNOWN_GOOD', label: 'Known good (hash set)' },
];

export function FilesPage() {
  const { overview, caseId, reloadOverview } = useCase();
  const [params, setParams] = useSearchParams();
  const analyzed = (overview?.evidence || []).filter((e) => e.analysis_status === 'COMPLETED');
  const evidenceId = params.get('evidence') || analyzed[0]?.evidence_id || '';
  const initialFlag = (params.get('flag') || '') as Flag;
  const [tab, setTab] = useState<Tab>(initialFlag ? 'all' : 'deleted');
  const counts = overview?.counts;

  return (
    <div className="stack">
      <PageHeader
        title="Files"
        subtitle="The file index the Sleuth Kit built for each analyzed image, including deleted entries still described by the file system, with each file's hashes and its real type from its content. Recovery copies a file out with icat; the original image is never modified."
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
              { id: 'deleted', label: 'Deleted entries', count: counts?.deleted_files },
              { id: 'all', label: 'All files', count: counts?.files },
              { id: 'members', label: 'Archives and attachments', count: counts?.archive_members },
              { id: 'recovered', label: 'Recovered files', count: counts?.recovered_files },
            ]}
          />
          {tab === 'recovered' ? (
            <RecoveredFiles caseId={caseId} />
          ) : (
            <FileIndex key={`${evidenceId}-${tab}`} caseId={caseId} evidenceId={evidenceId} deletedOnly={tab === 'deleted'}
              members={tab === 'members'} initialFlag={tab === 'all' ? initialFlag : ''} onRecovered={reloadOverview} />
          )}
        </Card>
      )}
    </div>
  );
}

/** Badges for what file processing found: renamed, encrypted, and the hash-set status. */
export function FileFlags({ f }: { f: FsEntry }) {
  return (
    <>
      {f.ext_mismatch && (
        <Badge tone="warn" title={`The content is ${f.mime}; the name suggests ${f.expected_type}`}>RENAMED</Badge>
      )}
      {f.encryption && <Badge tone="warn" title={f.encryption.detail}>ENCRYPTED</Badge>}
      {f.hash_status && (
        <Badge tone={HASH_KIND[f.hash_status].tone} title={(f.hash_sets || []).map((s) => s.name).join(', ')}>
          {HASH_KIND[f.hash_status].label.toUpperCase()}
        </Badge>
      )}
    </>
  );
}

const CONTAINER_KIND: Record<string, string> = {
  zip: 'ZIP archive', '7z': 'archive', ooxml: 'Office document', odf: 'OpenDocument', ole: 'Office (OLE) file', pdf: 'PDF attachment',
  email: 'email',
};

function FileIndex({ caseId, evidenceId, deletedOnly, members, initialFlag, onRecovered }: {
  caseId: string; evidenceId: string; deletedOnly: boolean; members: boolean; initialFlag: Flag; onRecovered: () => void;
}) {
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('');
  const [flag, setFlag] = useState<Flag>(initialFlag);
  const [hideKnown, setHideKnown] = useState(true);
  const [skip, setSkip] = useState(0);
  const [recovered, setRecovered] = useState<Record<string, any>>({});
  const [busy, setBusy] = useState('');
  const [details, setDetails] = useState<FsEntry | null>(null);
  useEffect(() => setSkip(0), [search, category, flag, hideKnown]);
  const qs = new URLSearchParams({ limit: String(LIMIT), skip: String(skip) });
  if (deletedOnly) qs.set('deleted', 'true');
  if (members) qs.set('members', 'true');
  if (search) qs.set('q', search);
  if (category) qs.set('category', category);
  if (flag === 'renamed') qs.set('renamed', 'true');
  else if (flag === 'encrypted') qs.set('encrypted', 'true');
  else if (flag) qs.set('hash_status', flag);
  if (hideKnown && flag !== 'KNOWN_GOOD') qs.set('hide_known', 'true');
  const { data, error, loading } = useApi<{ data: FsEntry[]; total: number }>(`/forensics/evidence/${encodeURIComponent(evidenceId)}/files?${qs}`);
  const filtered = Boolean(search || category || flag);

  async function recover(f: FsEntry) {
    const key = f.container ? f._id : `${f.partition_offset}:${f.inode}`;
    setBusy(key);
    try {
      const r = await post<any>(f.container ? `/forensics/members/${f._id}/recover`
        : `/forensics/evidence/${encodeURIComponent(evidenceId)}/recover?inode=${encodeURIComponent(f.inode)}&offset=${f.partition_offset}`);
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
        <input className="input sm" style={{ maxWidth: 300 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())} placeholder="Filter by path, e.g. payroll or .docx" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Filter</Button>
        <select className="select sm" style={{ width: 150 }} value={category} onChange={(e) => setCategory(e.target.value)} aria-label="File type">
          <option value="">All types</option>
          {Object.entries(CATEGORY_LABELS).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
        </select>
        <select className="select sm" style={{ width: 250 }} value={flag} onChange={(e) => setFlag(e.target.value as Flag)} aria-label="Flag">
          {FLAGS.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
        </select>
        <label className="check" title="Files whose hash is in a known-good set (for example the NSRL) are hidden">
          <input type="checkbox" checked={hideKnown} disabled={flag === 'KNOWN_GOOD'} onChange={(e) => setHideKnown(e.target.checked)} />
          Hide known-good files
        </label>
        {filtered && <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); setCategory(''); setFlag(''); }}>Clear</Button>}
        <span className="small muted">{data ? (members ? `${formatNumber(data.total)} file${data.total === 1 ? '' : 's'} inside archives, documents and emails`
          : `${formatNumber(data.total)} ${deletedOnly ? 'deleted' : ''} ${data.total === 1 ? 'entry' : 'entries'}`.replace('  ', ' ')) : ''}</span>
      </div>
      <ErrorBanner error={error} />
      {loading && !data ? (
        <Loading />
      ) : !data?.data.length ? (
        <Empty
          title={filtered ? 'No matching files' : deletedOnly ? 'No deleted entries' : members ? 'No archive contents' : 'No files'}
          text={deletedOnly && !filtered ? 'The filesystem metadata in this image describes no deleted files. File carving can still find data in unallocated space.'
            : members && !filtered ? 'Archives and documents are opened by the Full analysis profile (Archives and embedded files); email attachments by the Email module.' : undefined}
        />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Path</th><th>Type</th><th>Size</th><th>Modified</th><th>Accessed</th><th>Created</th><th /></tr></thead>
            <tbody>
              {data.data.map((f) => {
                const key = f.container ? f._id : `${f.partition_offset}:${f.inode}`;
                const rec = recovered[key];
                const viewable = !f.is_dir && (!f.container || !!f.container.store);
                return (
                  <tr key={f._id} className={f.deleted ? 'is-deleted' : ''}>
                    <td className="cell-path">
                      <span className="row" style={{ gap: 6, flexWrap: 'nowrap', alignItems: 'flex-start' }}>
                        {f.is_dir ? <Folder size={14} style={{ flex: 'none', marginTop: 2 }} /> : <File size={14} style={{ flex: 'none', marginTop: 2 }} />}
                        <span className={f.deleted ? 'strong' : ''}>{f.path}</span>
                      </span>
                      <span className="row" style={{ gap: 4 }}>
                        {f.deleted && <Badge tone="danger">{f.container ? 'IN A DELETED FILE' : (f.deleted_status || 'deleted').toUpperCase()}</Badge>}
                        {f.container && <Badge tone="accent">{`IN ${CONTAINER_KIND[f.container.kind] || 'container'}`.toUpperCase()}{f.container.depth > 1 ? ' (NESTED)' : ''}</Badge>}
                        <FileFlags f={f} />
                      </span>
                      {f.container?.note && <div className="tiny muted">{f.container.note}</div>}
                    </td>
                    <td className="small">
                      {f.is_dir ? '—' : f.file_category ? (
                        <>{CATEGORY_LABELS[f.file_category] || f.file_category}<div className="tiny muted mono">{f.mime}</div></>
                      ) : <span className="muted">—</span>}
                    </td>
                    <td className="small nowrap">{f.is_dir ? '—' : formatBytes(f.size)}</td>
                    <td className="mono tiny nowrap">{f.container ? <span title="As recorded in the container (no time zone)">{f.container.modified || '—'}</span> : time(f.mtime, false)}</td>
                    <td className="mono tiny nowrap">{time(f.atime, false)}</td>
                    <td className="mono tiny nowrap">{time(f.crtime, false)}</td>
                    <td className="nowrap right">
                      {!f.is_dir && <Button size="sm" variant="ghost" className="icon-btn" icon={<Info size={15} />} onClick={() => setDetails(f)} aria-label={`Details of ${f.path}`} title="Hashes, type and same content" />}{' '}
                      <TagButton type="FILE" id={f._id} title={f.path} />{' '}
                      {viewable && <ViewButton source={f.container ? { kind: 'member', entryId: f._id, name: f.path } : { kind: 'image', evidenceId, inode: f.inode, offset: f.partition_offset, name: f.path, volumeId: (f as any).volume_id }} />}{' '}
                      {rec ? (
                        <Button size="sm" icon={<Download size={13} />} onClick={() => downloadFile(`/forensics/artifacts/${rec.artifact_id}/download`, rec.filename).catch((e) => toast(e.message, 'danger'))}>
                          Download
                        </Button>
                      ) : (
                        viewable && can('ANALYSIS_RUN') && (
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
      <FileDetails caseId={caseId} file={details} onClose={() => setDetails(null)} />
    </>
  );
}

/** Everything file processing knows about one file, and where else in the case the same content is. */
export function FileDetails({ caseId, file: f, onClose }: { caseId: string; file: FsEntry | null; onClose: () => void }) {
  const same = useApi<{ files: FsEntry[]; artifacts: Artifact[] }>(
    f?.sha256 ? `/forensics/hash?case_id=${encodeURIComponent(caseId)}&digest=${f.sha256}` : null,
  );
  const others = (same.data?.files || []).filter((x) => x._id !== f?._id);
  const copies = same.data?.artifacts || [];
  return (
    <Modal open={!!f} title={`File details — ${f?.name || f?.path || ''}`} onClose={onClose} wide>
      {f && (
        <div className="stack">
          {!f.sha256 && !f.hash_error && (
            <Banner tone="info">This file has not been hashed yet: run the analysis with the standard profile (file hashes and types).</Banner>
          )}
          {f.hash_error && <Banner tone="warn">The file could not be read for hashing: {f.hash_error}</Banner>}
          <dl className="kv">
            <dt>Path</dt><dd className="mono small">{f.path}</dd>
            <dt>Evidence</dt><dd className="small">{f.evidence_id} · volume {f.volume_id || `offset ${f.partition_offset}`} · inode <span className="mono">{f.inode}</span>{f.deleted && ' · deleted'}</dd>
            {f.container && (<>
              <dt>Taken out of</dt>
              <dd className="small"><span className="mono">{f.container.parent}</span> ({CONTAINER_KIND[f.container.kind] || f.container.kind}
                {f.container.depth > 1 ? `, ${f.container.depth} containers deep` : ''})
                <div className="tiny muted">Member <span className="mono">{f.container.member}</span>{f.container.modified ? ` · modified ${f.container.modified} as recorded (no time zone)` : ''}
                  {f.container.packed_size !== null && f.container.packed_size !== undefined ? ` · ${formatBytes(f.container.packed_size)} compressed` : ''}</div>
                {f.container.note && <div className="tiny">{f.container.note}</div>}</dd>
            </>)}
            {f.archive && (<>
              <dt>Contains</dt>
              <dd className="small">{f.archive.error ? `Could not be opened: ${f.archive.error}` : f.archive.note ? f.archive.note
                : `${formatNumber(f.archive.members || 0)} file(s): ${formatNumber(f.archive.extracted || 0)} extracted${f.archive.encrypted ? `, ${f.archive.encrypted} encrypted (listed only)` : ''}${f.archive.not_extracted ? `, ${f.archive.not_extracted} not extracted` : ''}${f.archive.names_encrypted ? ' · the member names are encrypted too' : ''}`}
                {!!f.archive.members && <> — see the Archive contents tab</>}</dd>
            </>)}
            <dt>Size</dt><dd className="small">{formatBytes(f.size)} ({formatNumber(f.size)} bytes)</dd>
            {f.mime && (<>
              <dt>Type (from content)</dt>
              <dd className="small">{CATEGORY_LABELS[f.file_category || ''] || f.file_category} · <span className="mono">{f.mime}</span><div className="tiny muted">{f.magic}</div></dd>
              <dt>Name check</dt>
              <dd className="small">{f.ext_mismatch ? <><Badge tone="warn">RENAMED</Badge> The name suggests {f.expected_type}, but the content is <span className="mono">{f.mime}</span>.</> : 'The name matches the content (or its extension says nothing about it).'}</dd>
              <dt>Entropy</dt>
              <dd className="small">{f.entropy?.toFixed(3)} bits per byte<span className="muted"> (0 = constant, 8 = indistinguishable from random; compressed and encrypted data is close to 8)</span></dd>
              <dt>Encryption</dt>
              <dd className="small">{f.encryption ? <><Badge tone="warn">ENCRYPTED</Badge> {f.encryption.detail}</> : 'None recognised'}</dd>
            </>)}
            {f.sha256 && (<>
              <dt>MD5</dt><dd><Hash value={f.md5} /></dd>
              <dt>SHA-1</dt><dd><Hash value={f.sha1} /></dd>
              <dt>SHA-256</dt><dd><Hash value={f.sha256} /></dd>
              <dt>Hashed</dt><dd className="small">{f.deleted ? 'Deleted file: the hashes are of its content as it is on the disk now (its clusters may have been reused).' : 'The allocated file content.'}</dd>
              <dt>Hash sets</dt>
              <dd className="small">
                {f.hash_sets?.length ? f.hash_sets.map((s) => (
                  <div key={s.set_id}><Badge tone={HASH_KIND[s.kind].tone}>{HASH_KIND[s.kind].label}</Badge> {s.name} <span className="muted">({s.set_id}, {s.algorithm.toUpperCase()})</span></div>
                )) : 'In no imported hash set'}
              </dd>
            </>)}
          </dl>
          {f.sha256 && (
            <div>
              <h4 style={{ margin: '4px 0 8px' }}>Same content elsewhere in this case</h4>
              {same.loading && !same.data ? <Loading /> : !others.length && !copies.length ? (
                <p className="small muted">No other file in the case has this SHA-256.</p>
              ) : (
                <table className="table">
                  <thead><tr><th>Where</th><th>Evidence</th><th>Kind</th></tr></thead>
                  <tbody>
                    {others.map((x) => (
                      <tr key={x._id}>
                        <td className="cell-path mono small">{x.path}</td>
                        <td className="small">{x.evidence_id}</td>
                        <td className="small">{x.deleted ? <Badge tone="danger">DELETED</Badge> : 'File'}</td>
                      </tr>
                    ))}
                    {copies.map((a) => (
                      <tr key={a._id}>
                        <td className="cell-path mono small">{a.filename}{a.original_path && <div className="tiny muted">from {a.original_path}</div>}</td>
                        <td className="small">{a.evidence_id}</td>
                        <td className="small">{a.type === 'RECOVERED_FILE' ? 'Recovered copy' : a.type === 'CARVED_FILE' ? 'Carved file' : 'Extracted file'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
          {f._id && <Comments caseId={caseId} targetType="FILE" targetId={f._id} title="Comments on this file" />}
        </div>
      )}
    </Modal>
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

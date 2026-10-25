import { useState } from 'react';
import { ArchiveRestore, ChevronRight, Folder, FolderOpen, Search } from 'lucide-react';
import { post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { TagButton } from '../lib/tags';
import { useApi } from '../lib/useApi';
import { ViewButton } from '../ui/FileViewer';
import { ExportButton } from '../ui/ExportButton';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Loading, Modal, PageHeader, Pager, Tabs, type Tone, useToast } from '../ui';

type Change = 'DELETED_SINCE' | 'CHANGED_SINCE' | 'ADDED_SINCE';
const LIMIT = 100;
const CHANGE_LABEL: Record<Change, string> = { DELETED_SINCE: 'Deleted since', CHANGED_SINCE: 'Changed since', ADDED_SINCE: 'Added since' };
const CHANGE_TONE: Record<Change, Tone> = { DELETED_SINCE: 'danger', CHANGED_SINCE: 'warn', ADDED_SINCE: 'ok' };
const NOTES: Record<Change, string> = {
  DELETED_SINCE: 'In the snapshot, gone from the volume now. The snapshot still holds the file as it was: view it or recover it.',
  CHANGED_SINCE: 'In both, with a different size or modification time. The snapshot holds the earlier version.',
  ADDED_SINCE: 'On the volume now, not in the snapshot: made (or moved there) after the snapshot was taken.',
};

/** Recovers a file as it was in a shadow copy, with its hash and a custody record. */
function useRecover() {
  const toast = useToast();
  const [busy, setBusy] = useState('');
  async function recover(evidenceId: string, volumeId: string, inode: string, path: string) {
    setBusy(`${volumeId}:${inode}`);
    try {
      const r = await post<any>('/forensics/shadow-copies/recover', { evidence_id: evidenceId, volume_id: volumeId, inode, path });
      toast(`${r.filename} recovered from shadow copy ${r.shadow_copy} (SHA-256 ${r.sha256.slice(0, 12)}…); it is listed under Files, Recovered files`, 'ok');
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy('');
    }
  }
  return { recover, busy };
}

export function ShadowCopiesPage() {
  const { caseId, overview } = useCase();
  const time = useTime();
  const storesPath = `/forensics/shadow-copies/stores?case_id=${encodeURIComponent(caseId)}`;
  const stores = useApi<{ data: any[] }>(storesPath);
  const [browsing, setBrowsing] = useState<any>(null);
  const list = stores.data?.data || [];
  return (
    <div className="stack">
      <PageHeader title="Shadow copies"
        subtitle="Volume Shadow Copies: the snapshots Windows keeps of NTFS volumes (restore points, backups). Each was read as it was when it was made and compared with the volume now; files deleted or changed since can still be read and recovered from it." />
      <ErrorBanner error={stores.error} />
      {!stores.data ? <Loading /> : !list.length ? (
        <Banner tone="info">No shadow copies were found in this case. NTFS volumes are checked for them by the Standard and Full analysis profiles (module "Volume Shadow Copies").</Banner>
      ) : (
        <>
          <Card title="Snapshots" flush actions={<ExportButton path={storesPath} what="list of snapshots" />}>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Evidence</th><th>Volume</th><th>Copy</th><th>Made</th><th>Identifier</th>
                  <th className="right">Deleted since</th><th className="right">Changed since</th><th className="right">Added since</th><th /></tr></thead>
                <tbody>
                  {list.map((s) => (
                    <tr key={`${s.evidence_id}${s.volume_id}`}>
                      <td className="mono small">{s.evidence_id}</td>
                      <td className="mono small">{s.parent_volume_id}</td>
                      <td className="small">{s.store}</td>
                      <td className="small nowrap">{time(s.created)}</td>
                      <td className="mono tiny">{s.identifier}</td>
                      <td className="right">{s.counts?.deleted_since ?? '—'}</td>
                      <td className="right">{s.counts?.changed_since ?? '—'}</td>
                      <td className="right">{s.counts?.added_since ?? '—'}</td>
                      <td className="right"><Button size="sm" icon={<FolderOpen size={13} />} onClick={() => setBrowsing(s)}>Browse</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <Differences caseId={caseId} stores={list} counts={overview?.counts} />
        </>
      )}
      {browsing && <BrowseModal store={browsing} onClose={() => setBrowsing(null)} />}
    </div>
  );
}

function Differences({ caseId, stores, counts }: { caseId: string; stores: any[]; counts?: any }) {
  const time = useTime();
  const { can } = useAuth();
  const { recover, busy } = useRecover();
  const [change, setChange] = useState<Change>('DELETED_SINCE');
  const [volume, setVolume] = useState('');
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [skip, setSkip] = useState(0);
  const qs = new URLSearchParams({ case_id: caseId, change, limit: String(LIMIT), skip: String(skip) });
  if (volume) qs.set('volume_id', volume.split('|')[1]), qs.set('evidence_id', volume.split('|')[0]);
  if (search) qs.set('search', search);
  const path = `/forensics/shadow-copies?${qs}`;
  const res = useApi<{ data: any[]; total: number; counts: Record<string, number> }>(path);
  const n = res.data?.counts || {};
  return (
    <Card flush>
      <Tabs<Change> value={change} onChange={(c) => { setChange(c); setSkip(0); }} tabs={(['DELETED_SINCE', 'CHANGED_SINCE', 'ADDED_SINCE'] as Change[]).map((c) => (
        { id: c, label: CHANGE_LABEL[c], count: n[c] ?? (c === 'DELETED_SINCE' ? counts?.shadow_deleted : undefined) }))} />
      <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[change]}</p>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <select className="input sm" style={{ maxWidth: 260 }} value={volume} onChange={(e) => { setVolume(e.target.value); setSkip(0); }} aria-label="Shadow copy">
          <option value="">Every shadow copy</option>
          {stores.map((s) => <option key={`${s.evidence_id}|${s.volume_id}`} value={`${s.evidence_id}|${s.volume_id}`}>{s.evidence_id} · copy {s.store} of {s.parent_volume_id}</option>)}
        </select>
        <input className="input sm" style={{ maxWidth: 280 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && (setSearch(q.trim()), setSkip(0))}
          placeholder="Part of the path" aria-label="Search paths" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => { setSearch(q.trim()); setSkip(0); }}>Search</Button>
        <span className="small muted">{res.data ? `${res.data.total.toLocaleString()} entries` : ''}</span>
        <span style={{ flex: 1 }} />
        {!!res.data?.data.length && <ExportButton path={path} what="file list" />}
      </div>
      <ErrorBanner error={res.error} />
      {!res.data ? <Loading /> : !res.data.data.length ? <Empty title={`No file ${CHANGE_LABEL[change].toLowerCase()} a shadow copy`} /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>File</th><th>Copy</th><th className="right">Size then</th><th>Modified then</th><th className="right">Size now</th><th>Modified now</th><th /></tr></thead>
            <tbody>
              {res.data.data.map((x) => (
                <tr key={x._id}>
                  <td className="cell-path small mono">{x.is_dir && <Folder size={13} style={{ verticalAlign: -2, marginRight: 4 }} />}{x.path}
                    <div><Badge tone={CHANGE_TONE[x.change as Change]}>{CHANGE_LABEL[x.change as Change]}</Badge> <span className="tiny muted">{x.evidence_id}</span></div></td>
                  <td className="small nowrap">{x.store} <span className="tiny muted">({time(x.store_created)})</span></td>
                  <td className="right small">{x.change !== 'ADDED_SINCE' && !x.is_dir ? formatBytes(x.size ?? 0) : '—'}</td>
                  <td className="small nowrap">{x.mtime ? time(x.mtime) : '—'}</td>
                  <td className="right small">{x.current && !x.is_dir ? formatBytes(x.current.size ?? 0) : '—'}</td>
                  <td className="small nowrap">{x.current?.mtime ? time(x.current.mtime) : '—'}</td>
                  <td className="right nowrap">
                    {x.change !== 'ADDED_SINCE' && !x.is_dir && (
                      <>
                        <ViewButton source={{ kind: 'shadow', evidenceId: x.evidence_id, volumeId: x.volume_id, inode: x.inode, name: `${x.path} (shadow copy ${x.store})` }} />
                        {can('ANALYSIS_RUN') && <Button size="sm" variant="ghost" icon={<ArchiveRestore size={13} />} disabled={busy === `${x.volume_id}:${x.inode}`}
                          aria-label={`Recover ${x.path} from shadow copy ${x.store}`} onClick={() => recover(x.evidence_id, x.volume_id, x.inode, x.path)}>Recover</Button>}
                      </>
                    )}
                    <TagButton type="SHADOW_FILE" id={x._id} title={x.path} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {res.data && <Pager skip={skip} limit={LIMIT} total={res.data.total} onChange={setSkip} />}
    </Card>
  );
}

function BrowseModal({ store, onClose }: { store: any; onClose: () => void }) {
  const time = useTime();
  const { can } = useAuth();
  const { recover, busy } = useRecover();
  const [path, setPath] = useState('/');
  const listPath = `/forensics/shadow-copies/browse?evidence_id=${encodeURIComponent(store.evidence_id)}&volume_id=${encodeURIComponent(store.volume_id)}&path=${encodeURIComponent(path)}`;
  const res = useApi<{ data: any[] }>(listPath);
  const parts = path.split('/').filter(Boolean);
  return (
    <Modal open wide title={`Shadow copy ${store.store} of ${store.evidence_id} ${store.parent_volume_id}, as on ${time(store.created)}`} onClose={onClose}>
      <div className="stack" style={{ gap: 10 }}>
        <div className="row small" style={{ gap: 2, flexWrap: 'wrap' }}>
          <button className="link-button mono" onClick={() => setPath('/')}>/</button>
          {parts.map((p, i) => (
            <span key={i} className="row" style={{ gap: 2 }}><ChevronRight size={12} />
              <button className="link-button mono" onClick={() => setPath('/' + parts.slice(0, i + 1).join('/'))}>{p}</button></span>
          ))}
          <span style={{ flex: 1 }} />
          {!!res.data?.data.length && <ExportButton path={listPath} what="folder listing" />}
        </div>
        <ErrorBanner error={res.error} />
        {!res.data ? <Loading /> : !res.data.data.length ? <Empty title="Empty folder" /> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Name</th><th className="right">Size</th><th>Modified</th><th /></tr></thead>
              <tbody>
                {res.data.data.map((x) => (
                  <tr key={x.inode + x.name}>
                    <td className="small mono">{x.is_dir ? (
                      <button className="link-button mono" onClick={() => setPath(x.path)}><Folder size={13} style={{ verticalAlign: -2, marginRight: 4 }} />{x.name}</button>
                    ) : x.name}{x.deleted && <> <Badge tone="danger">DELETED</Badge></>}</td>
                    <td className="right small">{x.is_dir ? '' : formatBytes(x.size)}</td>
                    <td className="small nowrap">{x.mtime ? time(x.mtime) : '—'}</td>
                    <td className="right nowrap">{!x.is_dir && (
                      <>
                        <ViewButton source={{ kind: 'shadow', evidenceId: store.evidence_id, volumeId: store.volume_id, inode: x.inode, name: `${x.path} (shadow copy ${store.store})` }} />
                        {can('ANALYSIS_RUN') && <Button size="sm" variant="ghost" icon={<ArchiveRestore size={13} />} disabled={busy === `${store.volume_id}:${x.inode}`}
                          aria-label={`Recover ${x.path}`} onClick={() => recover(store.evidence_id, store.volume_id, x.inode, x.path)}>Recover</Button>}
                      </>
                    )}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Modal>
  );
}

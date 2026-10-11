import { useEffect, useState } from 'react';
import { Download, RotateCcw, Search } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { downloadFile, post } from '../lib/api';
import { formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Artifact } from '../lib/types';
import { TagButton } from '../lib/tags';
import { ViewButton } from '../ui/FileViewer';
import { Badge, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, Tabs, useToast } from '../ui';

const LIMIT = 100;
type Kind = 'PROGRAM_RUN' | 'RECENT_FILE' | 'RECYCLE_BIN_ITEM';

const EMPTY: Record<Kind, string> = {
  PROGRAM_RUN: 'No Prefetch files (C:\\Windows\\Prefetch) were found in the analyzed images.',
  RECENT_FILE: 'No shortcuts were found in the users\' Recent folders.',
  RECYCLE_BIN_ITEM: 'No Recycle Bin index ($I) files were found.',
};

export function ActivityPage() {
  const { caseId, overview } = useCase();
  const [kind, setKind] = useState<Kind>('PROGRAM_RUN');
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [skip, setSkip] = useState(0);
  useEffect(() => setSkip(0), [kind, search]);

  const params = new URLSearchParams({ case_id: caseId, kind, limit: String(LIMIT), skip: String(skip) });
  if (search) params.set('search', search);
  const res = useApi<{ data: Artifact[]; total: number }>(`/forensics/activity?${params}`);
  const { error, loading } = res;
  // Until the new tab's rows arrive, the previous tab's are still loaded: never draw them under this tab's columns.
  const data = res.dataPath && new URLSearchParams(res.dataPath.split('?')[1]).get('kind') === kind ? res.data : null;
  const counts = overview?.counts;

  return (
    <div className="stack">
      <PageHeader
        title="Windows activity"
        subtitle="What the user did on the computer, from Windows' own records: programs run (Prefetch), files opened (shortcuts in the Recent folder) and files moved to the Recycle Bin."
      />
      <Card flush>
        <Tabs<Kind>
          value={kind}
          onChange={setKind}
          tabs={[
            { id: 'PROGRAM_RUN', label: 'Programs run', count: counts?.programs_run },
            { id: 'RECENT_FILE', label: 'Recently opened files', count: counts?.recent_files },
            { id: 'RECYCLE_BIN_ITEM', label: 'Recycle Bin', count: counts?.recycle_bin_items },
          ]}
        />
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
          <input className="input sm" style={{ maxWidth: 320 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())} placeholder="Search programs, paths, volume labels" aria-label="Search" />
          <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
          {search && <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); }}>Clear</Button>}
          <span className="small muted">{data ? `${data.total.toLocaleString()} ${data.total === 1 ? 'record' : 'records'}` : ''}</span>
        </div>
        <ErrorBanner error={error} />
        {loading && !data ? (
          <Loading />
        ) : !data?.data.length ? (
          <Empty title="No records" text={search ? 'Nothing matches this search.' : EMPTY[kind]} />
        ) : kind === 'PROGRAM_RUN' ? (
          <Programs rows={data.data} />
        ) : kind === 'RECENT_FILE' ? (
          <RecentFiles rows={data.data} />
        ) : (
          <RecycleBin rows={data.data} />
        )}
        {data && <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />}
      </Card>
      <p className="small muted" style={{ margin: 0 }}>
        Times come from Windows' own records. Prefetch is written about ten seconds after a program starts; a shortcut's
        target times describe the file itself, while the shortcut's own times show when it was first and last opened.
      </p>
    </div>
  );
}

function Programs({ rows }: { rows: Artifact[] }) {
  const time = useTime();
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Program</th><th className="right">Runs</th><th>Last run</th><th>Earlier runs</th><th>Volume</th><th>Prefetch file</th><th /></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r._id}>
              <td className="cell-path"><div className="strong">{r.executable}</div><div className="tiny mono muted">{r.executable_path}</div></td>
              <td className="right">{r.run_count ?? '—'}</td>
              <td className="mono small nowrap">{time(r.last_run)}</td>
              <td className="mono tiny">{(r.last_run_times || []).slice(1).map((t: string) => <div key={t}>{time(t)}</div>)}{(r.last_run_times || []).length < 2 && <span className="muted">—</span>}</td>
              <td className="tiny">{(r.volumes || []).map((v: any) => <div key={v.device_path}><span className="mono">{v.serial}</span> <span className="muted">{v.device_path}</span></div>)}</td>
              <td className="cell-path tiny muted">{r.source_path}<div>{r.evidence_id} · v{r.format_version}{r.compressed ? ' · compressed' : ''}</div></td>
              <td className="nowrap right">
                <TagButton type="ACTIVITY" id={r._id} title={r.executable_path || r.executable} />{' '}
                {r.parent_artifact_id && <ViewButton source={{ kind: 'artifact', artifactId: r.parent_artifact_id, name: r.source_path }} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RecentFiles({ rows }: { rows: Artifact[] }) {
  const time = useTime();
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Last opened</th><th>File</th><th>Drive</th><th>Target file times</th><th>Shortcut</th><th /></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r._id}>
              <td className="mono small nowrap">{time(r.lnk_modified)}{r.lnk_created && r.lnk_created !== r.lnk_modified && <div className="tiny muted">first {time(r.lnk_created)}</div>}</td>
              <td className="cell-path">
                <div className="mono small strong">{r.target_path}</div>
                {r.drive_type === 'Removable' && <Badge tone="warn">Removable drive</Badge>}
                {r.drive_type === 'Network' && <Badge tone="info">Network</Badge>}
                {r.arguments && <div className="tiny mono muted">args: {r.arguments}</div>}
              </td>
              <td className="small">{r.drive_type || '—'}{r.volume_label && <div className="strong">{r.volume_label}</div>}{r.drive_serial && <div className="tiny mono muted">serial {r.drive_serial}</div>}</td>
              <td className="tiny mono">
                <div>created {time(r.target_created)}</div>
                <div>modified {time(r.target_modified)}</div>
                <div>accessed {time(r.target_accessed)}</div>
                {r.target_size != null && <div className="muted">{formatBytes(r.target_size)}</div>}
              </td>
              <td className="cell-path tiny muted">{r.source_path}<div>{r.evidence_id}{r.machine_id ? ` · machine ${r.machine_id}` : ''}</div></td>
              <td className="nowrap right">
                <TagButton type="ACTIVITY" id={r._id} title={r.target_path} />{' '}
                {r.parent_artifact_id && <ViewButton source={{ kind: 'artifact', artifactId: r.parent_artifact_id, name: r.source_path }} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RecycleBin({ rows }: { rows: Artifact[] }) {
  const { can } = useAuth();
  const { reloadOverview } = useCase();
  const toast = useToast();
  const time = useTime();
  const [busy, setBusy] = useState('');
  const [recovered, setRecovered] = useState<Record<string, any>>({});

  async function recover(r: Artifact) {
    setBusy(r._id);
    try {
      const res = await post<any>(`/forensics/evidence/${encodeURIComponent(r.evidence_id)}/recover?inode=${encodeURIComponent(r.data_inode)}&offset=${r.partition_offset ?? 0}`);
      if (res.status !== 'COMPLETED') throw new Error(res.stderr || `icat ${res.status}`);
      setRecovered((m) => ({ ...m, [r._id]: res }));
      toast(`Recovered ${res.filename} (${formatBytes(res.size)}) — SHA-256 ${res.sha256.slice(0, 12)}…`, 'ok');
      reloadOverview();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Deleted</th><th>Original location</th><th>Size</th><th>Content ($R)</th><th>Index file</th><th /></tr></thead>
        <tbody>
          {rows.map((r) => {
            const rec = recovered[r._id];
            return (
              <tr key={r._id}>
                <td className="mono small nowrap">{time(r.deleted_time)}</td>
                <td className="cell-path"><div className="mono small strong">{r.original_path}</div><div className="tiny muted">user SID {r.sid}</div></td>
                <td className="small nowrap">{r.original_size != null ? formatBytes(r.original_size) : '—'}</td>
                <td className="small">{r.data_present ? <Badge tone="ok">{r.data_is_dir ? 'Folder present' : 'Present'}</Badge> : <Badge>Not present</Badge>}</td>
                <td className="cell-path tiny muted">{r.source_path}<div>{r.evidence_id} · format v{r.format_version}</div></td>
                <td className="nowrap right">
                  <TagButton type="ACTIVITY" id={r._id} title={r.original_path} />{' '}
                  {r.data_present && !r.data_is_dir && <ViewButton source={{ kind: 'image', evidenceId: r.evidence_id, inode: r.data_inode, offset: r.partition_offset ?? 0, name: r.data_path }} />}{' '}
                  {rec ? (
                    <Button size="sm" icon={<Download size={13} />} onClick={() => downloadFile(`/forensics/artifacts/${rec.artifact_id}/download`, rec.filename).catch((e) => toast(e.message, 'danger'))}>Download</Button>
                  ) : (
                    r.data_present && !r.data_is_dir && can('ANALYSIS_RUN') && (
                      <Button size="sm" icon={<RotateCcw size={13} />} busy={busy === r._id} onClick={() => recover(r)}>Recover</Button>
                    )
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

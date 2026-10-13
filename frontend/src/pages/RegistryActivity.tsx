import { Fragment, useEffect, useState } from 'react';
import { ListTree, Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Artifact } from '../lib/types';
import { TagButton } from '../lib/tags';
import { Badge, Button, Empty, ErrorBanner, Hash, Loading } from '../ui';
import { ExportButton } from '../ui/ExportButton';

/** Tabs of the Windows activity page that come from the registry (module registry). */
export type RegistryTab = 'EXECUTION' | 'SHELLBAG' | 'SEARCHES' | 'PERSISTENCE' | 'INSTALLED' | 'REMOTE';

const SEARCH_TYPES: [string, string][] = [['EXPLORER_SEARCH', 'Explorer searches'], ['TYPED_PATH', 'Paths typed in Explorer'],
  ['RUN_MRU', 'Run dialog (Win+R)'], ['RECENT_DOC', 'Recent documents (RecentDocs)'], ['TYPED_URL', 'Addresses typed (Internet Explorer)']];

const NOTES: Record<RegistryTab, string> = {
  EXECUTION: 'One row per program with every trace Windows keeps of it. Prefetch, UserAssist and BAM show it ran; Amcache records it (with its SHA-1) about when it first appeared; ShimCache shows only that it was on the disk.',
  SHELLBAG: 'Folders opened in Explorer (UsrClass.dat ShellBags), including folders on removable and network drives that are gone. "Last browsed" is known for the most recently opened folder at each level.',
  SEARCHES: 'What the user searched for and typed, most recent first. The time is when the list was last changed, so it belongs to the first entry.',
  PERSISTENCE: 'Programs set to start on their own: Run and RunOnce keys (computer and user), automatic services, Image File Execution Options debuggers and Winlogon. Entries that stand out are flagged with the reason.',
  INSTALLED: 'Programs listed under Uninstall in the SOFTWARE hive (computer) and in each user\'s hive.',
  REMOTE: 'Remote desktop connections the user made (Terminal Server Client) and mapped network drives.',
};

function rowsPath(caseId: string, type: string, search: string, extra = '') {
  const qs = new URLSearchParams({ case_id: caseId, type, limit: '1000' });
  if (search) qs.set('search', search);
  return `/forensics/registry?${qs}${extra}`;
}

function useRows(caseId: string, type: string, search: string, extra = '') {
  return useApi<{ data: Artifact[]; total: number }>(rowsPath(caseId, type, search, extra));
}

const executionPath = (caseId: string, search: string) => `/forensics/execution?case_id=${encodeURIComponent(caseId)}${search ? `&search=${encodeURIComponent(search)}` : ''}`;

export function RegistryActivity({ tab }: { tab: RegistryTab }) {
  const { caseId } = useCase();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [flagged, setFlagged] = useState(false);
  useEffect(() => { setQ(''); setSearch(''); }, [tab]);
  // What the tab's table loads. Searches exports each of its lists; Remote merges two lists, so it has no export.
  const exportPath = tab === 'EXECUTION' ? executionPath(caseId, search) : tab === 'SHELLBAG' ? rowsPath(caseId, 'SHELLBAG', search)
    : tab === 'PERSISTENCE' ? rowsPath(caseId, 'PERSISTENCE', search, flagged ? '&flagged=true' : '')
    : tab === 'INSTALLED' ? rowsPath(caseId, 'INSTALLED_PROGRAM', search) : null;
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
        <input className="input sm" style={{ maxWidth: 320 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
          placeholder="Search programs, paths, commands" aria-label="Search" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
        {search && <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); }}>Clear</Button>}
        {tab === 'PERSISTENCE' && (
          <label className="check"><input type="checkbox" checked={flagged} onChange={(e) => setFlagged(e.target.checked)} /> Only entries that stand out</label>
        )}
        <span style={{ flex: 1 }} />
        <ExportButton path={exportPath} />
      </div>
      <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[tab]}</p>
      {tab === 'EXECUTION' && <Execution caseId={caseId} search={search} />}
      {tab === 'SHELLBAG' && <Shellbags caseId={caseId} search={search} />}
      {tab === 'SEARCHES' && <Searches caseId={caseId} search={search} />}
      {tab === 'PERSISTENCE' && <Persistence caseId={caseId} search={search} flagged={flagged} />}
      {tab === 'INSTALLED' && <Installed caseId={caseId} search={search} />}
      {tab === 'REMOTE' && <Remote caseId={caseId} search={search} />}
    </>
  );
}

const SOURCE_LABEL: Record<string, string> = { prefetch: 'Prefetch', userassist: 'UserAssist', bam: 'BAM', amcache: 'Amcache', shimcache: 'ShimCache' };

function Execution({ caseId, search }: { caseId: string; search: string }) {
  const time = useTime();
  const [open, setOpen] = useState<string | null>(null);
  const { data, error, loading } = useApi<{ data: any[]; total: number }>(executionPath(caseId, search));
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No execution traces" text="No Prefetch, UserAssist, BAM, Amcache or ShimCache records were found." /></>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Program</th><th>Traces</th><th>Last run</th><th>First recorded</th><th>SHA-1 (Amcache)</th><th /></tr></thead>
        <tbody>
          {data.data.map((r) => (
            <Fragment key={r.program}>
              <tr>
                <td className="strong">{r.program}<div className="tiny muted mono cell-path">{r.paths[0]}</div></td>
                <td className="small">
                  <span className="row" style={{ gap: 4 }}>{r.sources.map((s: string) => <Badge key={s} tone={s === 'shimcache' ? 'neutral' : 'accent'}>{SOURCE_LABEL[s]}</Badge>)}</span>
                  {!r.ran && <div className="tiny muted">on the disk; no trace of running</div>}
                </td>
                <td className="mono tiny nowrap">{time(r.last_run)}</td>
                <td className="mono tiny nowrap">{time(r.first_seen)}</td>
                <td>{r.sha1 ? <Hash value={r.sha1} short={12} /> : <span className="muted">—</span>}</td>
                <td className="right"><Button size="sm" icon={<ListTree size={13} />} onClick={() => setOpen(open === r.program ? null : r.program)}
                  aria-expanded={open === r.program} aria-label={`Traces of ${r.program}`}>Traces</Button></td>
              </tr>
              {open === r.program && (
                <tr><td colSpan={6} style={{ background: 'var(--surface-2)' }}>
                  <dl className="kv">
                    {r.prefetch.map((p: any, i: number) => (<Fragment key={`p${i}`}><dt>Prefetch</dt><dd className="small">{p.run_count} runs · last {p.last_runs.slice(0, 3).map((t: string) => time(t)).join(', ')}<div className="tiny muted mono">{p.source}</div></dd></Fragment>))}
                    {r.userassist.map((u: any, i: number) => (<Fragment key={`u${i}`}><dt>UserAssist ({u.user || 'user'})</dt><dd className="small">{u.run_count} runs, focus {u.focus_count} times ({Math.round((u.focus_time_ms || 0) / 1000)} s) · last {time(u.last_run)}</dd></Fragment>))}
                    {r.bam.map((b: any, i: number) => (<Fragment key={`b${i}`}><dt>BAM ({b.user || b.sid})</dt><dd className="small">last run {time(b.last_run)}</dd></Fragment>))}
                    {r.amcache.map((a: any, i: number) => (<Fragment key={`a${i}`}><dt>Amcache</dt><dd className="small">recorded {time(a.first_recorded)}{a.version ? ` · version ${a.version}` : ''}{a.publisher ? ` · ${a.publisher}` : ''}{a.size ? ` · ${formatBytes(a.size)}` : ''}{a.link_date ? ` · linked ${a.link_date}` : ''}</dd></Fragment>))}
                    {r.shimcache.map((s: any, i: number) => (<Fragment key={`s${i}`}><dt>ShimCache</dt><dd className="small">entry {s.position + 1} · file modified {time(s.last_modified)}</dd></Fragment>))}
                    <dt>Paths</dt><dd className="small mono">{r.paths.map((p: string) => <div key={p}>{p}</div>)}</dd>
                  </dl>
                </td></tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Shellbags({ caseId, search }: { caseId: string; search: string }) {
  const time = useTime();
  const { data, error, loading } = useRows(caseId, 'SHELLBAG', search);
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No folders" text="No ShellBags were found in the users' UsrClass.dat or NTUSER.DAT." /></>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Folder</th><th>User</th><th>Last browsed</th><th>Created</th><th>Modified</th><th>Accessed</th><th /></tr></thead>
        <tbody>
          {data.data.map((r) => (
            <tr key={r._id}>
              <td className="cell-path mono small">{r.path}<div className="tiny muted">{r.shell_type}{r.node_slot ? ` · bag ${r.node_slot}` : ''}</div></td>
              <td className="small">{r.user}</td>
              <td className="mono tiny nowrap">{r.mru_position === 0 ? time(r.key_last_write) : <span className="muted">—</span>}</td>
              <td className="mono tiny nowrap">{time(r.created)}</td>
              <td className="mono tiny nowrap">{time(r.modified)}</td>
              <td className="mono tiny nowrap">{time(r.accessed)}</td>
              <td className="right"><TagButton type="REGISTRY" id={r._id} title={r.path} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Searches({ caseId, search }: { caseId: string; search: string }) {
  const time = useTime();
  const lists = SEARCH_TYPES.map(([t]) => useRows(caseId, t, search)); // eslint-disable-line react-hooks/rules-of-hooks
  if (lists.some((l) => l.loading && !l.data)) return <Loading />;
  const any = lists.some((l) => l.data?.data.length);
  if (!any) return <Empty title="No searches or typed paths" text="No WordWheelQuery, TypedPaths, RunMRU, RecentDocs or TypedURLs were found." />;
  return (
    <div className="stack" style={{ padding: '10px 14px 14px', gap: 14 }}>
      {SEARCH_TYPES.map(([t, label], i) => {
        const rows = (lists[i].data?.data || []).filter((r) => t !== 'RECENT_DOC' || !r.extension);
        if (!rows.length) return null;
        return (
          <div key={t}>
            <div className="row" style={{ margin: '4px 0 6px' }}>
              <h4 style={{ margin: 0 }}>{label}</h4>
              <span style={{ flex: 1 }} />
              <ExportButton path={rowsPath(caseId, t, search)} what="list" />
            </div>
            <table className="table">
              <thead><tr><th>#</th><th>{t === 'RUN_MRU' ? 'Command' : t === 'RECENT_DOC' ? 'File' : 'Value'}</th><th>User</th><th>List last changed</th><th /></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r._id}>
                    <td className="small">{(r.order ?? 0) + 1}</td>
                    <td className="mono small cell-path">{r.value}</td>
                    <td className="small">{r.user}</td>
                    <td className="mono tiny nowrap">{r.order === 0 ? time(r.key_last_write) : <span className="muted">earlier</span>}</td>
                    <td className="right"><TagButton type="REGISTRY" id={r._id} title={r.value} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      })}
    </div>
  );
}

function Persistence({ caseId, search, flagged }: { caseId: string; search: string; flagged: boolean }) {
  const time = useTime();
  const { data, error, loading } = useRows(caseId, 'PERSISTENCE', search, flagged ? '&flagged=true' : '');
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No autostart entries" text={flagged ? 'Nothing stands out.' : 'No Run keys, services, debuggers or Winlogon entries were found.'} /></>;
  const rows = [...data.data].sort((a, b) => Number(!a.flags?.length) - Number(!b.flags?.length));
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Entry</th><th>Runs</th><th>Where</th><th>Written</th><th /></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r._id}>
              <td className="small"><span className="strong">{r.name}</span><div className="tiny muted">{r.kind}{r.user ? ` · ${r.user}` : ' · computer'}{r.start_type ? ` · ${r.start_type}` : ''}</div>
                {r.flags?.length > 0 && (
                  <div style={{ marginTop: 4 }}>
                    <Badge tone="warn">STANDS OUT</Badge>
                    {r.flags.map((f: string) => <div key={f} className="tiny" style={{ color: 'var(--warn)', marginTop: 2 }}>{f}</div>)}
                  </div>
                )}</td>
              <td className="mono small cell-path">{r.command}{r.service_dll && <div className="tiny muted">DLL {r.service_dll}</div>}</td>
              <td className="tiny muted mono cell-path">{r.location}</td>
              <td className="mono tiny nowrap">{time(r.key_last_write)}</td>
              <td className="right"><TagButton type="REGISTRY" id={r._id} title={`${r.name} = ${r.command}`} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Installed({ caseId, search }: { caseId: string; search: string }) {
  const time = useTime();
  const { data, error, loading } = useRows(caseId, 'INSTALLED_PROGRAM', search);
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No installed programs" text="No Uninstall entries were found." /></>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Program</th><th>Publisher</th><th>Installed</th><th>Entry written</th><th>Location</th><th /></tr></thead>
        <tbody>
          {data.data.map((r) => (
            <tr key={r._id}>
              <td className="small strong">{r.name}{r.version && <span className="muted"> {r.version}</span>}<div className="tiny muted">{r.scope === 'user' ? `user ${r.user}` : 'computer'}</div></td>
              <td className="small">{r.publisher}</td>
              <td className="small nowrap">{formatInstallDate(r.install_date)}</td>
              <td className="mono tiny nowrap">{time(r.key_last_write)}</td>
              <td className="mono tiny cell-path">{r.install_location}</td>
              <td className="right"><TagButton type="REGISTRY" id={r._id} title={r.name} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatInstallDate(v?: string) {
  return v && /^\d{8}$/.test(v) ? `${v.slice(0, 4)}-${v.slice(4, 6)}-${v.slice(6)}` : v || '—';
}

function Remote({ caseId, search }: { caseId: string; search: string }) {
  const time = useTime();
  const rdp = useRows(caseId, 'RDP_CONNECTION', search);
  const drives = useRows(caseId, 'NETWORK_DRIVE', search);
  if ((rdp.loading && !rdp.data) || (drives.loading && !drives.data)) return <Loading />;
  const rows = [...(rdp.data?.data || []), ...(drives.data?.data || [])];
  if (!rows.length) return <Empty title="No remote desktop connections or network drives" />;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Kind</th><th>Target</th><th>User</th><th>Detail</th><th>Written</th><th /></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r._id}>
              <td className="small">{r.type === 'RDP_CONNECTION' ? 'Remote desktop' : 'Network drive'}</td>
              <td className="mono small">{r.server || r.remote_path}</td>
              <td className="small">{r.user}</td>
              <td className="small">{r.username_hint ? `as ${r.username_hint}` : r.drive ? `${r.drive}:` : ''}</td>
              <td className="mono tiny nowrap">{time(r.key_last_write)}</td>
              <td className="right"><TagButton type="REGISTRY" id={r._id} title={r.server || r.remote_path} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export const REGISTRY_COUNT = (c: any): Partial<Record<RegistryTab, number>> => ({
  EXECUTION: c?.programs_executed, SHELLBAG: c?.folders_browsed, SEARCHES: c?.user_searches, PERSISTENCE: c?.persistence_entries,
  INSTALLED: c?.installed_programs,
});


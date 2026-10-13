import { Fragment, useEffect, useState } from 'react';
import { ImageOff, ListTree, Search } from 'lucide-react';
import { fetchBlob } from '../lib/api';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import { ViewButton } from '../ui/FileViewer';
import { ExportButton } from '../ui/ExportButton';
import { Badge, Button, Empty, ErrorBanner, Loading, Pager, type Tone } from '../ui';

/** Tabs of the Windows activity page from Jump Lists, the Timeline, thumbnails, SRUM and Windows Search (module user_activity). */
export type UserTab = 'JUMPLISTS' | 'TIMELINE' | 'THUMBNAILS' | 'NETWORK' | 'SEARCH_INDEX';
export const USER_TABS: UserTab[] = ['JUMPLISTS', 'TIMELINE', 'THUMBNAILS', 'NETWORK', 'SEARCH_INDEX'];
const LIMIT = 200;

const NOTES: Record<UserTab, string> = {
  JUMPLISTS: 'Files and folders each program opened, from its Jump List (AutomaticDestinations: with when it was last used, pinned items and use counts; CustomDestinations: the program\'s own lists and tasks). Programs are named from their AppID where it is well known.',
  TIMELINE: 'The Windows Timeline (ActivitiesCache.db): applications and documents opened, how long an application was in use, clipboard copies, and entries the user deleted from the Timeline that were still waiting to be synchronised.',
  THUMBNAILS: 'Thumbnails from Explorer\'s cache. A thumbnail stays after its picture is deleted or wiped. Where the Windows Search index knows the picture, its path is shown.',
  NETWORK: 'Network data used by each application and user, from SRUM (Windows records it about once an hour; the totals cover the hours recorded).',
  SEARCH_INDEX: 'What Windows Search indexed: path, size, times, owner and a summary of the text, including files that are no longer on the disk.',
};
const STATE_TONE: Record<string, Tone> = { 'on disk': 'ok', deleted: 'warn', 'not on the disk': 'danger' };

export const USER_COUNT = (c: any): Partial<Record<UserTab, number>> => ({
  JUMPLISTS: c?.jumplist_entries, TIMELINE: c?.timeline_activities, THUMBNAILS: c?.thumbnails, SEARCH_INDEX: c?.search_index_entries,
});

function rowsPath(caseId: string, type: string, search: string, skip: number, extra: Record<string, string> = {}) {
  const qs = new URLSearchParams({ case_id: caseId, type, limit: String(LIMIT), skip: String(skip), ...extra });
  if (search) qs.set('search', search);
  return `/forensics/user-activity?${qs}`;
}

function useRows(caseId: string, type: string, search: string, skip: number, extra: Record<string, string> = {}) {
  return useApi<{ data: any[]; total: number }>(rowsPath(caseId, type, search, skip, extra));
}

const ROW_TYPE: Record<Exclude<UserTab, 'NETWORK'>, string> = {
  JUMPLISTS: 'JUMPLIST_ENTRY', TIMELINE: 'TIMELINE_ACTIVITY', THUMBNAILS: 'THUMBNAIL', SEARCH_INDEX: 'SEARCH_INDEX_ENTRY',
};
const networkPath = (caseId: string) => `/forensics/user-activity/network?case_id=${encodeURIComponent(caseId)}`;

export function UserActivity({ tab }: { tab: UserTab }) {
  const { caseId } = useCase();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [state, setState] = useState('');
  const [skip, setSkip] = useState(0);
  useEffect(() => { setQ(''); setSearch(''); setState(''); setSkip(0); }, [tab]);
  useEffect(() => setSkip(0), [search, state]);
  const exportPath = tab === 'NETWORK' ? networkPath(caseId)
    : rowsPath(caseId, ROW_TYPE[tab], search, skip, tab === 'SEARCH_INDEX' && state ? { file_state: state } : {});
  return (
    <>
      {tab !== 'NETWORK' && (
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
          <input className="input sm" style={{ maxWidth: 320 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
            placeholder={tab === 'THUMBNAILS' ? 'Search cache entries and indexed paths' : 'Search files, programs and text'} aria-label="Search" />
          <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
          {search && <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); }}>Clear</Button>}
          {tab === 'SEARCH_INDEX' && (
            <select className="input sm" style={{ maxWidth: 220 }} value={state} onChange={(e) => setState(e.target.value)} aria-label="File now">
              <option value="">All indexed files</option>
              <option value="not on the disk">Not on the disk</option>
              <option value="deleted">Deleted</option>
              <option value="on disk">Still on the disk</option>
            </select>
          )}
          <span style={{ flex: 1 }} />
          <ExportButton path={exportPath} />
        </div>
      )}
      {tab === 'NETWORK' ? (
        <div className="row" style={{ padding: '10px 14px 0', alignItems: 'flex-start' }}>
          <p className="small muted grow" style={{ margin: 0 }}>{NOTES[tab]}</p>
          <ExportButton path={exportPath} />
        </div>
      ) : <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[tab]}</p>}
      {tab === 'JUMPLISTS' && <JumpLists caseId={caseId} search={search} skip={skip} onPage={setSkip} />}
      {tab === 'TIMELINE' && <Timeline caseId={caseId} search={search} skip={skip} onPage={setSkip} />}
      {tab === 'THUMBNAILS' && <Thumbnails caseId={caseId} search={search} skip={skip} onPage={setSkip} />}
      {tab === 'NETWORK' && <Network caseId={caseId} />}
      {tab === 'SEARCH_INDEX' && <SearchIndex caseId={caseId} search={search} state={state} skip={skip} onPage={setSkip} />}
    </>
  );
}

interface ListProps { caseId: string; search: string; skip: number; onPage: (s: number) => void }

function JumpLists({ caseId, search, skip, onPage }: ListProps) {
  const time = useTime();
  const [open, setOpen] = useState<string | null>(null);
  const { data, error, loading } = useRows(caseId, ROW_TYPE.JUMPLISTS, search, skip);
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No Jump Lists" text={search ? 'Nothing matches this search.' : 'No AutomaticDestinations or CustomDestinations files were found in the users\' Recent folders.'} /></>;
  return (
    <>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Last used</th><th>User</th><th>Program</th><th>Item</th><th className="right">Uses</th><th /></tr></thead>
          <tbody>
            {data.data.map((j) => {
              const lnk = j.lnk || {};
              return (
                <Fragment key={j._id}>
                  <tr>
                    <td className="mono tiny nowrap">{j.last_used ? time(j.last_used) : <span className="faint">{j.jumplist_kind === 'custom' ? 'not recorded' : '—'}</span>}</td>
                    <td className="small">{j.user || '—'}</td>
                    <td className="small">{j.application || <span className="mono">AppID {j.app_id}</span>}
                      <div className="tiny muted">{j.jumplist_kind === 'custom' ? `Custom list: ${j.category}` : 'Recent and pinned'}</div></td>
                    <td className="small">
                      <span className="mono cell-path">{j.target || '—'}</span>{' '}
                      {j.pinned && <Badge tone="accent">PINNED</Badge>}{' '}
                      {lnk.drive_type === 'Removable' && <Badge tone="warn">{`Removable drive${lnk.volume_label ? ` "${lnk.volume_label}"` : ''}`}</Badge>}
                      {lnk.arguments && <div className="tiny muted mono cell-path">{lnk.arguments}</div>}
                    </td>
                    <td className="right mono small">{j.access_count ?? '—'}</td>
                    <td className="nowrap">
                      <Button size="sm" variant="ghost" icon={<ListTree size={13} />} onClick={() => setOpen(open === j._id ? null : j._id)}
                        aria-label={`Details of ${j.target}`}>Details</Button>
                      <TagButton type="WINDOWS" id={j._id} title={j.target} />
                    </td>
                  </tr>
                  {open === j._id && (
                    <tr><td colSpan={6}>
                      <dl className="kv small" style={{ gridTemplateColumns: '180px 1fr' }}>
                        <dt>Jump List</dt><dd className="mono tiny break">{j.source_path}</dd>
                        {j.entry_number != null && (<><dt>Entry</dt><dd className="mono">{j.entry_number}</dd></>)}
                        {j.hostname && (<><dt>Computer (DestList)</dt><dd>{j.hostname}</dd></>)}
                        {j.mac_address && (<><dt>MAC address (object ID)</dt><dd className="mono">{j.mac_address}</dd></>)}
                        {j.droid_file_id && (<><dt>Object ID (file)</dt><dd className="mono tiny">{j.droid_file_id}</dd></>)}
                        {lnk.target_created && (<><dt>Target created</dt><dd className="mono tiny">{time(lnk.target_created)}</dd></>)}
                        {lnk.target_modified && (<><dt>Target modified</dt><dd className="mono tiny">{time(lnk.target_modified)}</dd></>)}
                        {lnk.target_accessed && (<><dt>Target accessed</dt><dd className="mono tiny">{time(lnk.target_accessed)}</dd></>)}
                        {lnk.target_size != null && (<><dt>Target size</dt><dd>{formatBytes(lnk.target_size)}</dd></>)}
                        {lnk.drive_serial && (<><dt>Volume serial</dt><dd className="mono">{lnk.drive_serial}</dd></>)}
                        {lnk.description && (<><dt>Description</dt><dd>{lnk.description}</dd></>)}
                        {lnk.working_directory && (<><dt>Working folder</dt><dd className="mono tiny">{lnk.working_directory}</dd></>)}
                      </dl>
                    </td></tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      <Pager skip={skip} limit={LIMIT} total={data.total} onChange={onPage} />
    </>
  );
}

function Timeline({ caseId, search, skip, onPage }: ListProps) {
  const time = useTime();
  const { data, error, loading } = useRows(caseId, ROW_TYPE.TIMELINE, search, skip);
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No Windows Timeline activity" text={search ? 'Nothing matches this search.' : 'No ActivitiesCache.db was found (Windows 10 version 1803 and later keep one per account).'} /></>;
  return (
    <>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Start</th><th>User</th><th>Application</th><th>Activity</th><th>What</th><th /></tr></thead>
          <tbody>
            {data.data.map((a) => (
              <tr key={a._id}>
                <td className="mono tiny nowrap">{time(a.start_time)}{a.end_time && <div className="faint">to {time(a.end_time)}</div>}</td>
                <td className="small">{a.user || '—'}</td>
                <td className="small">{a.app_display_name || <span className="mono cell-path">{a.app || '—'}</span>}
                  {a.app_display_name && a.app && <div className="tiny muted mono cell-path">{a.app}</div>}</td>
                <td className="small">
                  <Badge tone={a.operation_type === 3 ? 'danger' : a.activity_type === 10 ? 'warn' : 'neutral'}>{a.activity_label}</Badge>
                  {a.operation_type === 3 && <div><Badge tone="danger">DELETED BY THE USER</Badge></div>}
                  {a.duration_seconds != null && <div className="tiny muted">in use {a.duration_seconds} s</div>}
                </td>
                <td className="small">
                  {a.clipboard_text ? <span className="mono">{a.clipboard_text}</span> : (a.display_text || '')}
                  {a.description && a.description !== a.display_text && <div className="tiny mono cell-path">{a.description}</div>}
                </td>
                <td><TagButton type="WINDOWS" id={a._id} title={a.display_text || a.description || a.app} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager skip={skip} limit={LIMIT} total={data.total} onChange={onPage} />
    </>
  );
}

/** A thumbnail fetched with the user's session (every view is recorded in the audit log, as for any file content). */
function ThumbImage({ artifactId, label }: { artifactId: string; label: string }) {
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let objectUrl: string | null = null;
    let live = true;
    fetchBlob(`/forensics/artifacts/${encodeURIComponent(artifactId)}/raw`)
      .then((b) => { if (live) { objectUrl = URL.createObjectURL(b); setUrl(objectUrl); } })
      .catch(() => live && setFailed(true));
    return () => { live = false; if (objectUrl) URL.revokeObjectURL(objectUrl); };
  }, [artifactId]);
  if (failed) return <div className="thumb-box"><ImageOff size={20} /></div>;
  return <div className="thumb-box">{url ? <img src={url} alt={label} /> : <Loading label="" />}</div>;
}

function Thumbnails({ caseId, search, skip, onPage }: ListProps) {
  const { data, error, loading } = useRows(caseId, ROW_TYPE.THUMBNAILS, search, skip);
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No thumbnails" text={search ? 'Nothing matches this search.' : 'No thumbcache_*.db files were found under AppData\\Local\\Microsoft\\Windows\\Explorer.'} /></>;
  return (
    <>
      <div className="thumb-grid">
        {data.data.map((t) => {
          const label = t.indexed_path || `Thumbnail ${t.entry_hash}`;
          return (
            <section className="card thumb-card" key={t._id}>
              <ThumbImage artifactId={t.artifact_id} label={label} />
              <div className="small">
                <div className="mono tiny">{t.entry_hash}</div>
                <div className="tiny muted">{t.width ? `${t.width}×${t.height} · ` : ''}{t.image_type?.toUpperCase()} · thumbcache_{t.cache_size} · {t.user}</div>
                {t.indexed_path ? (
                  <div className="tiny mono cell-path">{t.indexed_path} {t.indexed_file_state && <Badge tone={STATE_TONE[t.indexed_file_state]}>{t.indexed_file_state}</Badge>}</div>
                ) : <div className="tiny faint">File not known to the search index</div>}
              </div>
              <div className="row" style={{ gap: 4 }}>
                <ViewButton source={{ kind: 'artifact', artifactId: t.artifact_id, name: label }} />
                <TagButton type="WINDOWS" id={t._id} title={label} />
              </div>
            </section>
          );
        })}
      </div>
      <Pager skip={skip} limit={LIMIT} total={data.total} onChange={onPage} />
    </>
  );
}

function Network({ caseId }: { caseId: string }) {
  const time = useTime();
  const { data, error, loading } = useApi<{ data: any[] }>(networkPath(caseId));
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No network usage" text="No SRUM database (Windows\System32\sru\SRUDB.dat) was found." /></>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead><tr><th>Application</th><th>User</th><th className="right">Sent</th><th className="right">Received</th><th className="right">Hours</th><th>First</th><th>Last</th><th>Network</th></tr></thead>
        <tbody>
          {data.data.map((n, i) => (
            <tr key={`${n.evidence_id}${n.app}${n.sid}${i}`}>
              <td className="small mono cell-path">{n.app || '—'}</td>
              <td className="small">{n.user || <span className="mono tiny">{n.sid || '—'}</span>}</td>
              <td className="right mono small">{formatBytes(n.bytes_sent)}</td>
              <td className="right mono small">{formatBytes(n.bytes_received)}</td>
              <td className="right mono small">{n.records.toLocaleString()}</td>
              <td className="mono tiny nowrap">{time(n.first)}</td>
              <td className="mono tiny nowrap">{time(n.last)}</td>
              <td className="small">{(n.interfaces || []).join(', ') || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SearchIndex({ caseId, search, state, skip, onPage }: ListProps & { state: string }) {
  const time = useTime();
  const { data, error, loading } = useRows(caseId, ROW_TYPE.SEARCH_INDEX, search, skip, state ? { file_state: state } : {});
  if (loading && !data) return <Loading />;
  if (!data?.data.length) return <><ErrorBanner error={error} /><Empty title="No search index entries" text={search || state ? 'Nothing matches these filters.' : 'No Windows Search database (Windows.edb or Windows.db) was found.'} /></>;
  return (
    <>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>File</th><th className="right">Size</th><th>Modified</th><th>Indexed</th><th>Now</th><th /></tr></thead>
          <tbody>
            {data.data.map((s) => (
              <tr key={s._id}>
                <td className="small">
                  <span className="mono cell-path">{s.path}</span>
                  <div className="tiny muted">{[s.kind, s.owner].filter(Boolean).join(' · ')}</div>
                  {s.summary && <div className="tiny" style={{ maxWidth: 520 }}>“{s.summary.slice(0, 200)}{s.summary.length > 200 ? '…' : ''}”</div>}
                </td>
                <td className="right mono small">{s.size != null ? formatBytes(s.size) : '—'}</td>
                <td className="mono tiny nowrap">{time(s.modified)}</td>
                <td className="mono tiny nowrap">{time(s.gather_time)}</td>
                <td>{s.file_state ? <Badge tone={STATE_TONE[s.file_state]}>{s.file_state}</Badge> : <span className="faint small">other drive</span>}</td>
                <td><TagButton type="WINDOWS" id={s._id} title={s.path} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager skip={skip} limit={LIMIT} total={data.total} onChange={onPage} />
    </>
  );
}

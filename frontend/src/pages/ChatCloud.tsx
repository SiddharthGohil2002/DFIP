import { useEffect, useState, type ReactNode } from 'react';
import { Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatBytes, shortHash, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import { Badge, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, Tabs } from '../ui';
import { ExportButton } from '../ui/ExportButton';

type Kind = 'CHAT_MESSAGE' | 'CHAT_CALL' | 'CHAT_FILE_TRANSFER' | 'CHAT_CONTACT' | 'CHAT_APP' | 'CLOUD_ACCOUNT' | 'CLOUD_FILE';
const LIMIT = 200;
const NOTES: Record<Kind, string> = {
  CHAT_MESSAGE: 'Messages from Skype (classic) databases, oldest first. Formatting is removed; emoticons keep their text.',
  CHAT_CALL: 'Calls recorded by Skype (classic), with who took part and how long they lasted.',
  CHAT_FILE_TRANSFER: 'Files sent and received through Skype (classic), with where they were saved and whether the transfer completed.',
  CHAT_CONTACT: 'Skype accounts on this computer and their contacts.',
  CHAT_APP: 'Chat applications found on the disk. Teams, WhatsApp, Telegram, Signal and others keep their messages encrypted or in browser caches: they are listed with where their data is and when it last changed, and are not read.',
  CLOUD_ACCOUNT: 'Cloud storage clients signed in on this computer and the folders they sync.',
  CLOUD_FILE: 'Every file the OneDrive or Google Drive client knew about, including files that were only in the cloud. A SHA-1 that matches a file on this evidence (on the disk, in an archive or attached to an email) is shown.',
};

export function ChatCloudPage() {
  const { caseId, overview } = useCase();
  const [kind, setKind] = useState<Kind>('CHAT_MESSAGE');
  const c = overview?.counts;
  return (
    <div className="stack">
      <PageHeader
        title="Chat and cloud storage"
        subtitle="Skype messages, calls and file transfers; chat apps whose messages are encrypted; and the files OneDrive, Google Drive and Dropbox synced."
      />
      <Card flush>
        <Tabs<Kind> value={kind} onChange={setKind} tabs={[
          { id: 'CHAT_MESSAGE', label: 'Messages', count: c?.chat_messages },
          { id: 'CHAT_CALL', label: 'Calls', count: c?.chat_calls },
          { id: 'CHAT_FILE_TRANSFER', label: 'File transfers', count: c?.chat_file_transfers },
          { id: 'CHAT_CONTACT', label: 'Accounts and contacts', count: c?.chat_contacts },
          { id: 'CHAT_APP', label: 'Chat apps found', count: c?.chat_apps },
          { id: 'CLOUD_ACCOUNT', label: 'Cloud accounts', count: c?.cloud_accounts },
          { id: 'CLOUD_FILE', label: 'Cloud files', count: c?.cloud_files },
        ]} />
        <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[kind]}</p>
        <Records key={kind} caseId={caseId} kind={kind} />
        {kind === 'CHAT_CONTACT' && <Records caseId={caseId} kind={'CHAT_ACCOUNT' as Kind} title="Accounts signed in" />}
      </Card>
    </div>
  );
}

function Records({ caseId, kind, title }: { caseId: string; kind: Kind | 'CHAT_ACCOUNT'; title?: string }) {
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [conversation, setConversation] = useState('');
  const [filesOnly, setFilesOnly] = useState(true);
  const [skip, setSkip] = useState(0);
  useEffect(() => setSkip(0), [search, conversation, filesOnly]);
  const qs = new URLSearchParams({ case_id: caseId, type: kind, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (conversation) qs.set('conversation', conversation);
  if (kind === 'CLOUD_FILE' && filesOnly) qs.set('files_only', 'true');
  const path = `/forensics/chat-cloud?${qs}`;
  const { data, error, loading } = useApi<{ data: any[]; total: number }>(path);
  const convs = useApi<{ data: any[] }>(kind === 'CHAT_MESSAGE' ? `/forensics/chat-cloud/conversations?case_id=${encodeURIComponent(caseId)}` : null);
  const cols = COLUMNS[kind];
  const exportButton = !!data?.data.length && <ExportButton path={path} />;
  return (
    <>
      {title ? (
        <div className="row" style={{ padding: '14px 14px 0' }}>
          <h4 style={{ margin: 0 }}>{title}</h4>
          <span style={{ flex: 1 }} />
          {exportButton}
        </div>
      ) : (
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
          <input className="input sm" style={{ maxWidth: 300 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
            placeholder="Search" aria-label="Search records" />
          <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
          {kind === 'CHAT_MESSAGE' && !!convs.data?.data.length && (
            <select className="select sm" style={{ width: 260 }} value={conversation} onChange={(e) => setConversation(e.target.value)} aria-label="Conversation">
              <option value="">All conversations</option>
              {convs.data.data.map((x) => <option key={`${x.account}${x.conversation}`} value={x.conversation}>{x.conversation} ({x.messages}, {x.app})</option>)}
            </select>
          )}
          {kind === 'CLOUD_FILE' && <label className="check"><input type="checkbox" checked={filesOnly} onChange={(e) => setFilesOnly(e.target.checked)} /> Files only (hide folders)</label>}
          <span className="small muted">{data ? `${data.total.toLocaleString()} records` : ''}</span>
          <span style={{ flex: 1 }} />
          {exportButton}
        </div>
      )}
      <ErrorBanner error={error} />
      {loading && !data ? <Loading /> : !data?.data.length ? <Empty title="Nothing found" text={search ? 'Nothing matches this search.' : undefined} /> : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead><tr>{cols.map(([h, , cls]) => <th key={h} className={cls}>{h}</th>)}<th /></tr></thead>
              <tbody>
                {data.data.map((r) => (
                  <tr key={r._id}>
                    {cols.map(([h, cell, cls]) => <td key={h} className={cls}>{cell(r, time)}</td>)}
                    <td className="nowrap right"><TagButton type="CHAT_CLOUD" id={r._id} title={r.text || r.file_name || r.path || r.app || r.handle} /></td>
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

type Col = [string, (r: any, time: (t?: string | null) => string) => ReactNode, string?];
const mono = 'mono small nowrap';
const COLUMNS: Record<Kind | 'CHAT_ACCOUNT', Col[]> = {
  CHAT_MESSAGE: [
    ['Time', (r, t) => t(r.time), mono],
    ['App', (r) => <Badge tone="info">{r.app}</Badge>],
    ['Conversation', (r) => <span className="small">{r.conversation}<div className="tiny muted">{r.account}</div></span>],
    ['From', (r) => <span className="small">{r.author_name || r.author}<div className="tiny muted mono">{r.author}</div></span>],
    ['Message', (r) => <span className="small">{r.kind !== 'message' && <Badge tone="accent">{r.kind}</Badge>} {r.text}</span>],
  ],
  CHAT_CALL: [
    ['Started', (r, t) => t(r.time), mono],
    ['App', (r) => <Badge tone="info">{r.app}</Badge>],
    ['With', (r) => <span className="small">{(r.members || []).join(', ') || r.host}</span>],
    ['Direction', (r) => <span className="small">{r.incoming ? 'incoming' : 'outgoing'}{r.conference ? ' (conference)' : ''}</span>],
    ['Length', (r) => <span className="small">{r.duration_seconds != null ? `${Math.floor(r.duration_seconds / 60)} min ${r.duration_seconds % 60} s` : '—'}</span>, 'nowrap'],
  ],
  CHAT_FILE_TRANSFER: [
    ['Started', (r, t) => t(r.started), mono],
    ['File', (r) => <span className="small"><span className="mono">{r.file_name}</span><div className="tiny muted mono">{r.file_path}</div></span>],
    ['Direction', (r) => <Badge tone={r.direction === 'sent' ? 'warn' : 'info'}>{r.direction}</Badge>],
    ['With', (r) => <span className="small">{r.partner_name}<div className="tiny muted mono">{r.partner}</div></span>],
    ['Status', (r) => <span className="small">{r.status}</span>],
    ['Size', (r) => <span className="small">{r.size != null ? formatBytes(r.size) : '—'}</span>, 'right nowrap'],
  ],
  CHAT_CONTACT: [
    ['Contact', (r) => <span className="small strong">{r.display_name || r.name}<div className="tiny muted mono">{r.handle}</div></span>],
    ['App', (r) => <Badge tone="info">{r.app}</Badge>],
    ['Account', (r) => <span className="small mono">{r.account}</span>],
    ['Email / phone', (r) => <span className="small">{[r.emails, r.phone].filter(Boolean).join(' · ') || '—'}</span>],
    ['Place', (r) => <span className="small">{[r.city, r.country].filter(Boolean).join(', ') || '—'}</span>],
    ['Last online', (r, t) => t(r.last_online), mono],
  ],
  CHAT_ACCOUNT: [
    ['Account', (r) => <span className="small strong">{r.name}<div className="tiny muted mono">{r.handle}</div></span>],
    ['App', (r) => <Badge tone="info">{r.app}</Badge>],
    ['User', (r) => <span className="small">{r.user}</span>],
    ['Email', (r) => <span className="small">{r.emails || '—'}</span>],
    ['Last online', (r, t) => t(r.last_online), mono],
  ],
  CHAT_APP: [
    ['App', (r) => <span className="small strong">{r.app}</span>],
    ['User', (r) => <span className="small">{r.user}</span>],
    ['Read', (r) => r.parsed ? <Badge tone="ok">PARSED</Badge> : <span className="small"><Badge tone="warn">NOT READ</Badge> <span className="muted">{r.reason}</span></span>],
    ['Data', (r) => <span className="small">{r.parsed ? `${r.messages} messages` : `${(r.files ?? 0).toLocaleString()} files, ${formatBytes(r.size)}`}<div className="tiny muted mono cell-path">{r.path}</div></span>],
    ['Last change', (r, t) => t(r.last_change), mono],
  ],
  CLOUD_ACCOUNT: [
    ['Provider', (r) => <Badge tone="info">{r.provider}</Badge>],
    ['Account', (r) => <span className="small mono">{r.account}</span>],
    ['User', (r) => <span className="small">{r.user}</span>],
    ['Synced folder', (r) => <span className="small mono">{r.sync_folder || '—'}<div className="tiny muted">{r.web_url || r.note || ''}</div></span>],
    ['Files', (r) => <span className="small">{r.files != null ? r.files.toLocaleString() : '—'}</span>, 'right'],
  ],
  CLOUD_FILE: [
    ['Changed', (r, t) => t(r.modified), mono],
    ['Provider', (r) => <Badge tone="info">{r.provider}</Badge>],
    ['File', (r) => <span className="small"><span className="mono">{r.path}</span>{r.is_folder && <> <Badge>FOLDER</Badge></>}{r.trashed && <> <Badge tone="warn">TRASHED</Badge></>}
      {!!r.same_content?.length && <div className="tiny" style={{ color: 'var(--danger)' }}>Same content: {r.same_content.map((x: any) => x.path + (x.deleted ? ' (deleted)' : '')).join(', ')}</div>}</span>],
    ['Size', (r) => <span className="small">{r.size != null ? formatBytes(r.size) : '—'}</span>, 'right nowrap'],
    ['Hash', (r) => <span className="mono tiny">{r.hash ? `${r.hash_algorithm} ${shortHash(r.hash)}` : '—'}</span>],
  ],
};

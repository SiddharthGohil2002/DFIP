import { useState } from 'react';
import { Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { useTime } from '../lib/format';
import { TagButton } from '../lib/tags';
import { useApi } from '../lib/useApi';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, Tabs, type Tone } from '../ui';

type Tab = 'SHELL_COMMAND' | 'UNIX_EVENT' | 'SCHEDULED_JOB' | 'RECENT_DOCUMENT' | 'QUARANTINE_EVENT' | 'WIFI_NETWORK';
const LIMIT = 200;
const SEV: Record<string, Tone> = { high: 'danger', medium: 'warn', low: 'neutral' };
const NOTES: Record<Tab, string> = {
  SHELL_COMMAND: 'Commands from bash and zsh history files, with their times when the shell kept them. Copies to other computers, wiping and history clearing, account and privilege changes, and things set up to run again are flagged.',
  UNIX_EVENT: 'Logins, logouts, failed logins, boots and shutdowns (wtmp, btmp), and auth.log and syslog events: SSH logins, sudo and su, accounts created, USB devices, cron jobs run. Syslog times are local times of the computer, read in its time zone.',
  SCHEDULED_JOB: 'What runs on its own: cron jobs, systemd services, macOS LaunchAgents and LaunchDaemons, and SSH keys that let someone log in. Programs in temporary or hidden folders and commands that download and run code are flagged.',
  RECENT_DOCUMENT: 'Files opened on a Linux desktop (GNOME recently-used.xbel), with the program and when.',
  QUARANTINE_EVENT: 'Every file macOS marked as downloaded (LaunchServices quarantine): by which program, from where, and the sender of an email attachment.',
  WIFI_NETWORK: 'Wi-Fi networks a Mac knows, with when it last joined each.',
};

export function UnixPage() {
  const { caseId, overview } = useCase();
  const [tab, setTab] = useState<Tab>('SHELL_COMMAND');
  const c = overview?.counts as any;
  return (
    <div className="stack">
      <PageHeader title="Linux and macOS"
        subtitle="Linux and macOS computers in the case, from disk images or collections: shell history, logins and logs, scheduled jobs and services, recent files, downloads and Wi-Fi networks." />
      {c && !c.unix_systems && <Banner tone="info">No Linux or macOS system has been analysed in this case.</Banner>}
      <Card flush>
        <Tabs<Tab> value={tab} onChange={setTab} tabs={[
          { id: 'SHELL_COMMAND', label: 'Shell history', count: c?.shell_commands },
          { id: 'UNIX_EVENT', label: 'Logins and logs', count: c?.unix_events },
          { id: 'SCHEDULED_JOB', label: 'Jobs and services', count: c?.scheduled_jobs },
          { id: 'RECENT_DOCUMENT', label: 'Recent files', count: c?.recent_documents },
          { id: 'QUARANTINE_EVENT', label: 'Downloads (quarantine)', count: c?.quarantine_events },
          { id: 'WIFI_NETWORK', label: 'Wi-Fi networks', count: c?.wifi_networks },
        ]} />
        <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[tab]}</p>
        <Records key={tab} caseId={caseId} type={tab} />
      </Card>
    </div>
  );
}

function Flags({ flags }: { flags?: any[] }) {
  if (!flags?.length) return null;
  return <>{flags.map((f) => <div key={f.code}><Badge tone={SEV[f.severity] || 'neutral'}>{f.label}</Badge></div>)}</>;
}

function Records({ caseId, type }: { caseId: string; type: Tab }) {
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [flagged, setFlagged] = useState(false);
  const [kind, setKind] = useState('');
  const [skip, setSkip] = useState(0);
  const qs = new URLSearchParams({ case_id: caseId, type, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (flagged) qs.set('flagged', 'true');
  if (kind) qs.set('kind', kind);
  const res = useApi<{ data: any[]; total: number; kinds: Record<string, number> }>(`/forensics/unix?${qs}`);
  const rows = res.data?.data || [];
  const canFlag = type === 'SHELL_COMMAND' || type === 'UNIX_EVENT' || type === 'SCHEDULED_JOB';
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <input className="input sm" style={{ maxWidth: 300 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && (setSearch(q.trim()), setSkip(0))}
          placeholder="Search" aria-label="Search records" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => { setSearch(q.trim()); setSkip(0); }}>Search</Button>
        {type === 'UNIX_EVENT' && res.data && (
          <select className="input sm" style={{ maxWidth: 220 }} value={kind} onChange={(e) => { setKind(e.target.value); setSkip(0); }} aria-label="Kind">
            <option value="">Every kind</option>
            {Object.entries(res.data.kinds).sort().map(([k, n]) => <option key={k} value={k}>{k.replace(/_/g, ' ')} ({n})</option>)}
          </select>
        )}
        {canFlag && <label className="check"><input type="checkbox" checked={flagged} onChange={(e) => { setFlagged(e.target.checked); setSkip(0); }} /> Only what stands out</label>}
        <span className="small muted">{res.data ? `${res.data.total.toLocaleString()} records` : ''}</span>
      </div>
      <ErrorBanner error={res.error} />
      {!res.data ? <Loading /> : !rows.length ? <Empty title="Nothing here" text="No record of this kind was found." /> : (
        <div className="table-wrap">
          <table className="table">
            <thead>{header(type)}</thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x._id}>
                  {cells(type, x, time)}
                  <td className="nowrap right"><TagButton type="UNIX" id={x._id} title={x.command || x.path || x.url || x.ssid || x.label} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {res.data && <Pager skip={skip} limit={LIMIT} total={res.data.total} onChange={setSkip} />}
    </>
  );
}

function header(type: Tab) {
  const cols: Record<Tab, string[]> = {
    SHELL_COMMAND: ['Time', 'User', 'Command', 'Stands out'],
    UNIX_EVENT: ['Time', 'Event', 'User', 'From', 'Log'],
    SCHEDULED_JOB: ['Kind', 'Name', 'Runs', 'When', 'As', 'Stands out'],
    RECENT_DOCUMENT: ['Opened', 'File', 'Program', 'User'],
    QUARANTINE_EVENT: ['Time', 'Downloaded by', 'From', 'User'],
    WIFI_NETWORK: ['Network', 'Security', 'Last joined', 'Added'],
  };
  return <tr>{cols[type].map((c) => <th key={c}>{c}</th>)}<th /></tr>;
}

function cells(type: Tab, x: any, time: (v: any) => string) {
  const t = (v: any) => (v ? time(v) : '—');
  switch (type) {
    case 'SHELL_COMMAND':
      return <><td className="small nowrap">{t(x.time)}</td><td className="small">{x.user}<div className="tiny muted">{x.shell} · line {x.order}</div></td>
        <td className="mono small break">{x.command}</td><td className="small"><Flags flags={x.flags} /></td></>;
    case 'UNIX_EVENT':
      return <><td className="small nowrap">{t(x.time)}</td>
        <td className="small">{x.notable ? <span className="strong">{x.label}</span> : x.label}<div className="tiny muted break">{x.summary || (x.terminal ? `on ${x.terminal}` : '')}
          {x.duration_seconds != null ? ` · ${Math.round(x.duration_seconds / 60)} min` : ''}</div></td>
        <td className="small">{x.user || '—'}</td><td className="mono small">{x.ip || x.host || '—'}</td><td className="small">{x.log}</td></>;
    case 'SCHEDULED_JOB':
      return <><td className="small">{x.mechanism}{x.enabled === false && <div className="tiny muted">disabled</div>}</td><td className="small break">{x.name}</td>
        <td className="mono small break">{x.command}<div className="tiny muted">{x.source_path}</div></td><td className="small">{x.schedule}</td>
        <td className="small">{x.user || '—'}</td><td className="small"><Flags flags={x.flags} /></td></>;
    case 'RECENT_DOCUMENT':
      return <><td className="small nowrap">{t(x.visited || x.modified)}</td><td className="mono small break">{x.path}</td><td className="small">{x.application || '—'}</td>
        <td className="small">{x.user}</td></>;
    case 'QUARANTINE_EVENT':
      return <><td className="small nowrap">{t(x.time)}</td><td className="small">{x.agent}</td>
        <td className="small break">{x.url || (x.sender ? `email from ${x.sender}` : '—')}{x.origin_url && <div className="tiny muted">page {x.origin_url}</div>}</td><td className="small">{x.user}</td></>;
    case 'WIFI_NETWORK':
      return <><td className="small strong">{x.ssid}</td><td className="small">{x.security || '—'}</td><td className="small nowrap">{t(x.last_joined)}</td><td className="small nowrap">{t(x.added)}</td></>;
  }
}

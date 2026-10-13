import { useState } from 'react';
import { Paperclip, Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { TagButton } from '../lib/tags';
import { useApi } from '../lib/useApi';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, Stat, Tabs, type Tone } from '../ui';
import { ViewButton } from '../ui/FileViewer';
import { ExportButton } from '../ui/ExportButton';

type Tab = 'MESSAGES' | 'WHATSAPP' | 'PHONE_CALL' | 'PHONE_CONTACT' | 'PHONE_APP' | 'PHONE_WIFI';
const LIMIT = 200;
const NOTES: Record<Tab, string> = {
  MESSAGES: 'SMS, MMS and iMessage, oldest first. The other side is named from the phone\'s contacts when the number or address matches. Attachments found in the extraction can be opened.',
  WHATSAPP: 'WhatsApp messages from the phone\'s own database (msgstore.db on Android, ChatStorage.sqlite on an iPhone), oldest first.',
  PHONE_CALL: 'Phone, FaceTime and app calls, with their direction and length.',
  PHONE_CONTACT: 'The phone\'s contacts and the people WhatsApp knows, with their numbers and email addresses.',
  PHONE_APP: 'Apps the user installed. Encrypted messaging, disappearing messages, VPN, anonymity, cloud storage, file transfer and cleaning apps are flagged.',
  PHONE_WIFI: 'Saved Wi-Fi networks. Passwords are never read into DFIP.',
};
const DIRECTION_TONE: Record<string, Tone> = { outgoing: 'info', incoming: 'neutral', missed: 'warn', rejected: 'warn', blocked: 'danger' };

export function PhonePage() {
  const { caseId, overview } = useCase();
  const [tab, setTab] = useState<Tab>('MESSAGES');
  const c = overview?.counts as any;
  const devices = useApi<{ data: any[] }>(`/forensics/phones?case_id=${encodeURIComponent(caseId)}&type=PHONE_DEVICE`);
  return (
    <div className="stack">
      <PageHeader title="Phones"
        subtitle="Android and iOS full file system extractions in the case: messages, WhatsApp, calls, contacts, installed apps and Wi-Fi networks." />
      {c && !c.phones && <Banner tone="info">No phone extraction has been analysed in this case. Upload an Android or iOS full file system extraction (ZIP or TAR) as evidence.</Banner>}
      {(devices.data?.data || []).map((d) => (
        <Card key={d._id} title={`${[d.manufacturer, d.model].filter(Boolean).join(' ') || d.platform}${d.name ? ` · ${d.name}` : ''}`}
          actions={<TagButton type="PHONE" id={d._id} title={d.model || d.name || d.platform} />}>
          <div className="grid cols-3">
            <Stat label="System" value={`${d.platform} ${d.os_version || ''}`.trim()} hint={d.build ? `build ${d.build}` : d.evidence_id} />
            <Stat label="Time zone" value={d.time_zone || '—'} hint={d.evidence_id} />
            <Stat label="Messages" value={((d.messages ?? 0) + (d.whatsapp_messages ?? 0)).toLocaleString()} hint={`${(d.whatsapp_messages ?? 0).toLocaleString()} WhatsApp`} />
            <Stat label="Calls" value={(d.calls ?? 0).toLocaleString()} />
            <Stat label="Contacts" value={(d.contacts ?? 0).toLocaleString()} />
            <Stat label="Apps installed" value={(d.apps ?? 0).toLocaleString()} hint={d.system_apps != null ? `and ${d.system_apps.toLocaleString()} system apps` : undefined} />
          </div>
        </Card>
      ))}
      <Card flush>
        <Tabs<Tab> value={tab} onChange={setTab} tabs={[
          { id: 'MESSAGES', label: 'Messages', count: c?.phone_messages },
          { id: 'WHATSAPP', label: 'WhatsApp', count: c?.whatsapp_messages },
          { id: 'PHONE_CALL', label: 'Calls', count: c?.phone_calls },
          { id: 'PHONE_CONTACT', label: 'Contacts', count: c?.phone_contacts },
          { id: 'PHONE_APP', label: 'Apps', count: c?.phone_apps },
          { id: 'PHONE_WIFI', label: 'Wi-Fi networks', count: c?.phone_wifi },
        ]} />
        <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[tab]}</p>
        {tab === 'MESSAGES' || tab === 'WHATSAPP' ? <Messages key={tab} caseId={caseId} whatsapp={tab === 'WHATSAPP'} /> : <Records key={tab} caseId={caseId} type={tab} />}
      </Card>
    </div>
  );
}

function Attachments({ x }: { x: any }) {
  if (!x.attachments?.length) return null;
  return (
    <div>
      {x.attachments.map((a: any, i: number) => (
        <div key={i} className="tiny row" style={{ gap: 6 }}>
          <Paperclip size={12} /> <span className="break">{a.name || 'attachment'}</span>
          <span className="muted">{[a.mime_type, a.size != null ? formatBytes(a.size) : null].filter(Boolean).join(' · ')}</span>
          {a.file ? <ViewButton source={{ kind: 'image', evidenceId: x.evidence_id, inode: a.file.inode, offset: 0, name: a.file.path, volumeId: a.file.volume_id }} />
            : <span className="muted">(not in the extraction)</span>}
        </div>
      ))}
    </div>
  );
}

function Messages({ caseId, whatsapp }: { caseId: string; whatsapp: boolean }) {
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [party, setParty] = useState('');
  const [app, setApp] = useState('');
  const [skip, setSkip] = useState(0);
  const qs = new URLSearchParams({ case_id: caseId, type: 'PHONE_MESSAGE', whatsapp: String(whatsapp), limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (party) qs.set('party', party);
  if (app) qs.set('app', app);
  const path = `/forensics/phones?${qs}`;
  const res = useApi<{ data: any[]; total: number; apps: Record<string, number>; conversations: any[] }>(path);
  const rows = res.data?.data || [];
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <input className="input sm" style={{ maxWidth: 260 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && (setSearch(q.trim()), setSkip(0))}
          placeholder="Search text, names, numbers" aria-label="Search messages" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => { setSearch(q.trim()); setSkip(0); }}>Search</Button>
        {res.data && (
          <select className="input sm" style={{ maxWidth: 280 }} value={party} onChange={(e) => { setParty(e.target.value); setSkip(0); }} aria-label="Conversation">
            <option value="">Every conversation</option>
            {res.data.conversations.map((c) => <option key={c.party ?? ''} value={c.party ?? ''}>{c.name ? `${c.name} (${c.party})` : c.party} · {c.messages}</option>)}
          </select>
        )}
        {res.data && !whatsapp && Object.keys(res.data.apps).length > 1 && (
          <select className="input sm" style={{ maxWidth: 160 }} value={app} onChange={(e) => { setApp(e.target.value); setSkip(0); }} aria-label="App">
            <option value="">Every app</option>
            {Object.entries(res.data.apps).sort().map(([k, n]) => <option key={k} value={k}>{k} ({n})</option>)}
          </select>
        )}
        <span className="small muted">{res.data ? `${res.data.total.toLocaleString()} messages` : ''}</span>
        <span style={{ flex: 1 }} />
        {rows.length > 0 && <ExportButton path={path} what="list of messages" />}
      </div>
      <ErrorBanner error={res.error} />
      {!res.data ? <Loading /> : !rows.length ? <Empty title="No messages" text="No message of this kind was found." /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Time</th><th>App</th><th>With</th><th>Message</th><th>Phone</th><th /></tr></thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x._id}>
                  <td className="small nowrap">{x.time ? time(x.time) : '—'}</td>
                  <td className="small"><Badge tone={DIRECTION_TONE[x.direction] || 'neutral'}>{x.direction === 'outgoing' ? 'sent' : 'received'}</Badge><div className="tiny muted">{x.app}{x.status ? ` · ${x.status}` : ''}</div></td>
                  <td className="small break"><span className="strong">{x.chat_name || x.party_name || x.party || '—'}</span>
                    {(x.chat_name || x.party_name) && <div className="tiny muted mono">{x.party}</div>}
                    {x.group && x.sender && <div className="tiny muted">from {x.sender_name || x.sender}</div>}</td>
                  <td className="small break" style={{ whiteSpace: 'pre-wrap' }}>{x.text || (x.message_type && x.message_type !== 'text' ? <span className="muted">({x.message_type})</span> : '')}
                    <Attachments x={x} /></td>
                  <td className="small">{x.platform}</td>
                  <td className="nowrap right"><TagButton type="PHONE" id={x._id} title={x.text || x.party} /></td>
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

function Records({ caseId, type }: { caseId: string; type: Exclude<Tab, 'MESSAGES' | 'WHATSAPP'> }) {
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [notable, setNotable] = useState(false);
  const [skip, setSkip] = useState(0);
  const qs = new URLSearchParams({ case_id: caseId, type, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (notable) qs.set('notable', 'true');
  const path = `/forensics/phones?${qs}`;
  const res = useApi<{ data: any[]; total: number }>(path);
  const rows = res.data?.data || [];
  const t = (v: any) => (v ? time(v) : '—');
  const cols: Record<typeof type, string[]> = {
    PHONE_CALL: ['Time', 'Call', 'With', 'Length', 'Phone'],
    PHONE_CONTACT: ['Name', 'Numbers', 'Email addresses', 'From', 'Phone'],
    PHONE_APP: ['App', 'Kind', 'Installed', 'Version', 'From', 'Phone'],
    PHONE_WIFI: ['Network', 'Security', 'Last joined', 'Router (MAC)', 'Phone'],
  };
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <input className="input sm" style={{ maxWidth: 300 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && (setSearch(q.trim()), setSkip(0))}
          placeholder="Search" aria-label="Search records" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => { setSearch(q.trim()); setSkip(0); }}>Search</Button>
        {type === 'PHONE_APP' && <label className="check"><input type="checkbox" checked={notable} onChange={(e) => { setNotable(e.target.checked); setSkip(0); }} /> Only what stands out</label>}
        <span className="small muted">{res.data ? `${res.data.total.toLocaleString()} records` : ''}</span>
        <span style={{ flex: 1 }} />
        {rows.length > 0 && <ExportButton path={path} />}
      </div>
      <ErrorBanner error={res.error} />
      {!res.data ? <Loading /> : !rows.length ? <Empty title="Nothing here" text="No record of this kind was found." /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr>{cols[type].map((c) => <th key={c}>{c}</th>)}<th /></tr></thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x._id}>
                  {type === 'PHONE_CALL' && <>
                    <td className="small nowrap">{t(x.time)}</td>
                    <td className="small"><Badge tone={DIRECTION_TONE[x.direction] || 'neutral'}>{x.direction}</Badge><div className="tiny muted">{x.kind}</div></td>
                    <td className="small break"><span className="strong">{x.party_name || x.party || '—'}</span>{x.party_name && <div className="tiny muted mono">{x.party}</div>}</td>
                    <td className="small nowrap">{x.duration ? `${Math.floor(x.duration / 60)}:${String(x.duration % 60).padStart(2, '0')}` : '—'}</td>
                    <td className="small">{x.platform}</td>
                  </>}
                  {type === 'PHONE_CONTACT' && <>
                    <td className="small strong break">{x.name || '—'}{x.organization && <div className="tiny muted">{x.organization}</div>}</td>
                    <td className="mono small break">{(x.numbers || []).join(', ')}</td><td className="small break">{(x.emails || []).join(', ')}</td>
                    <td className="small">{x.source}</td><td className="small">{x.platform}</td>
                  </>}
                  {type === 'PHONE_APP' && <>
                    <td className="small break"><span className="strong">{x.name}</span><div className="tiny muted mono">{x.app_id}</div></td>
                    <td className="small">{x.category ? <Badge tone={x.notable ? 'warn' : 'neutral'}>{x.category}</Badge> : '—'}</td>
                    <td className="small nowrap">{t(x.installed)}</td><td className="small">{x.version || '—'}</td>
                    <td className="small break">{x.installer || '—'}</td><td className="small">{x.platform}</td>
                  </>}
                  {type === 'PHONE_WIFI' && <>
                    <td className="small strong">{x.ssid}{x.hidden && <div className="tiny muted">hidden</div>}</td><td className="small">{x.security || '—'}</td>
                    <td className="small nowrap">{t(x.last_joined)}</td><td className="mono small">{x.router_mac || '—'}</td><td className="small">{x.platform}</td>
                  </>}
                  <td className="nowrap right"><TagButton type="PHONE" id={x._id} title={x.name || x.ssid || x.party_name || x.party} /></td>
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

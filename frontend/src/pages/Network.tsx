import { useState } from 'react';
import { Search, ShieldQuestion } from 'lucide-react';
import { api } from '../lib/api';
import { useCase } from '../lib/caseContext';
import { formatBytes, useTime } from '../lib/format';
import { TagButton } from '../lib/tags';
import { useApi } from '../lib/useApi';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Loading, Modal, PageHeader, Pager, Stat, Tabs } from '../ui';
import { ViewButton } from '../ui/FileViewer';

type Tab = 'HTTP_REQUEST' | 'DNS_QUERY' | 'TLS_HANDSHAKE' | 'NET_CONVERSATION' | 'FILES';
const LIMIT = 200;
const NOTES: Record<Tab, string> = {
  HTTP_REQUEST: 'Every HTTP request with its response, and the files it carried: uploads (the files of a form post) and downloads. Encrypted (HTTPS) requests are not readable; see TLS connections for where they went.',
  DNS_QUERY: 'Every name looked up and the addresses the answer gave.',
  TLS_HANDSHAKE: 'Encrypted connections, with the server name the client asked for (SNI): where HTTPS traffic went even though its content is unreadable.',
  NET_CONVERSATION: 'Each conversation between two ends (protocol, addresses and ports), largest first. The client is the side that sent the first packet; names come from the capture\'s own DNS answers, TLS server names and HTTP hosts.',
  FILES: 'Files HTTP carried, saved from the capture with their hashes and real types. They are indexed with the evidence\'s files, so hash sets, YARA, ClamAV and content search cover them.',
};

export function NetworkPage() {
  const { caseId, overview } = useCase();
  const [tab, setTab] = useState<Tab>('HTTP_REQUEST');
  const c = overview?.counts as any;
  const info = useApi<{ data: any[] }>(`/forensics/network?case_id=${encodeURIComponent(caseId)}&type=CAPTURE_INFO`);
  const time = useTime();
  return (
    <div className="stack">
      <PageHeader title="Network"
        subtitle="Network captures (pcap and pcapng) in the case: HTTP requests and the files they carried, DNS lookups, TLS server names and conversations." />
      {c && !c.captures && <Banner tone="info">No network capture has been analysed in this case. Upload a .pcap or .pcapng file as evidence.</Banner>}
      {(info.data?.data || []).map((x) => (
        <Card key={x._id} title={`Capture ${x.evidence_id}`}>
          <div className="stats">
            <Stat label="Format" value={x.file_type || '—'} hint={x.encapsulation} />
            <Stat label="Packets" value={(x.packets ?? 0).toLocaleString()} hint={formatBytes(x.bytes ?? 0)} />
            <Stat label="First packet" value={x.first ? time(x.first) : '—'} />
            <Stat label="Last packet" value={x.last ? time(x.last) : '—'} />
            <Stat label="Conversations" value={(x.conversations ?? 0).toLocaleString()} />
          </div>
        </Card>
      ))}
      <Card flush>
        <Tabs<Tab> value={tab} onChange={setTab} tabs={[
          { id: 'HTTP_REQUEST', label: 'HTTP', count: c?.http_requests },
          { id: 'DNS_QUERY', label: 'DNS lookups', count: c?.dns_queries },
          { id: 'TLS_HANDSHAKE', label: 'TLS connections', count: c?.tls_handshakes },
          { id: 'NET_CONVERSATION', label: 'Conversations', count: c?.net_conversations },
          { id: 'FILES', label: 'Files carried', count: c?.capture_files },
        ]} />
        <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[tab]}</p>
        {tab === 'FILES' ? <Files key={tab} caseId={caseId} /> : <Records key={tab} caseId={caseId} type={tab} />}
      </Card>
    </div>
  );
}

/** Looks a host name or address up with the configured threat-intelligence providers (an explicit action, audited). */
function LookUp({ caseId, host }: { caseId: string; host: string }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  if (!host) return null;
  const ip = /^[0-9.]+$/.test(host) || host.includes(':');
  const run = async () => {
    setOpen(true); setBusy(true); setError(null);
    try {
      setResult(await api(`/threat-intel/${ip ? 'ip' : 'domain'}/${encodeURIComponent(host)}?case_id=${encodeURIComponent(caseId)}`, { method: 'POST' }));
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setBusy(false);
    }
  };
  const providers = result ? Object.entries(result).filter(([k]) => !['indicator', 'case_id'].includes(k)) : [];
  return (
    <>
      <Button size="sm" variant="ghost" icon={<ShieldQuestion size={13} />} onClick={run} title={`Look ${host} up with threat intelligence`}>Look up</Button>
      <Modal open={open} title={`Threat intelligence: ${host}`} onClose={() => setOpen(false)}>
        {busy ? <Loading /> : error ? <Banner tone="danger">{error}</Banner> : (
          <table className="table">
            <thead><tr><th>Provider</th><th>Result</th></tr></thead>
            <tbody>
              {providers.map(([k, v]: [string, any]) => (
                <tr key={k}>
                  <td className="small strong">{k}</td>
                  <td className="small">
                    <Badge tone={v?.status === 'COMPLETED' ? 'ok' : v?.status === 'NOT_CONFIGURED' ? 'neutral' : 'warn'}>{v?.status || 'no answer'}</Badge>
                    <div className="tiny muted break">{v?.detail || v?.error || (v?.abuse_confidence_score != null ? `abuse confidence ${v.abuse_confidence_score}%, ${v.total_reports} reports` : '')
                      || (v?.pulse_count != null ? `${v.pulse_count} OTX pulses` : '') || (v?.query_status ? `URLhaus: ${v.query_status}` : '')}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Modal>
    </>
  );
}

function Records({ caseId, type }: { caseId: string; type: Exclude<Tab, 'FILES'> }) {
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [uploads, setUploads] = useState(false);
  const [skip, setSkip] = useState(0);
  const qs = new URLSearchParams({ case_id: caseId, type, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (uploads) qs.set('uploads', 'true');
  const res = useApi<{ data: any[]; total: number }>(`/forensics/network?${qs}`);
  const rows = res.data?.data || [];
  const t = (v: any) => (v ? time(v) : '—');
  const cols: Record<typeof type, string[]> = {
    HTTP_REQUEST: ['Time', 'Client', 'Request', 'Response', 'Files', ''],
    DNS_QUERY: ['Time', 'Client', 'Name', 'Type', 'Answers', ''],
    TLS_HANDSHAKE: ['Time', 'Client', 'Server name', 'Server', ''],
    NET_CONVERSATION: ['Protocol', 'Client', 'Server', 'Packets', 'Bytes (to server / back)', 'First', 'Last', ''],
  };
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <input className="input sm" style={{ maxWidth: 300 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && (setSearch(q.trim()), setSkip(0))}
          placeholder="Search hosts, addresses, URLs" aria-label="Search records" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => { setSearch(q.trim()); setSkip(0); }}>Search</Button>
        {type === 'HTTP_REQUEST' && <label className="check"><input type="checkbox" checked={uploads} onChange={(e) => { setUploads(e.target.checked); setSkip(0); }} /> Only uploads</label>}
        <span className="small muted">{res.data ? `${res.data.total.toLocaleString()} records` : ''}</span>
      </div>
      <ErrorBanner error={res.error} />
      {!res.data ? <Loading /> : !rows.length ? <Empty title="Nothing here" text="No record of this kind was found." /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr>{cols[type].map((c, i) => <th key={i}>{c}</th>)}<th /></tr></thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x._id}>
                  {type === 'HTTP_REQUEST' && <>
                    <td className="small nowrap">{t(x.time)}</td><td className="mono small">{x.client}</td>
                    <td className="small break"><span className="strong">{x.method}</span> <span className="mono">{x.url || x.uri}</span>
                      {x.user_agent && <div className="tiny muted break">{x.user_agent}</div>}</td>
                    <td className="small">{x.response_code ?? '—'}<div className="tiny muted">{x.response_type}</div></td>
                    <td className="small">{(x.files || []).filter((f: any) => f.part || f.direction === 'response').map((f: any) => (
                      <div key={`${f.direction}${f.path}`}><Badge tone={f.direction === 'request' ? 'warn' : 'info'}>{f.direction === 'request' ? 'sent' : 'received'}</Badge>{' '}
                        <span className="break">{f.name}</span> <span className="tiny muted">{formatBytes(f.size ?? 0)}</span></div>))}</td>
                    <td className="nowrap"><LookUp caseId={caseId} host={(x.host || '').replace(/:\d+$/, '')} /></td>
                  </>}
                  {type === 'DNS_QUERY' && <>
                    <td className="small nowrap">{t(x.time)}</td><td className="mono small">{x.client}</td><td className="mono small break strong">{x.name}</td>
                    <td className="small">{x.query_type}</td>
                    <td className="mono small break">{(x.answers || []).join(', ') || (x.answered ? 'no address' : <span className="muted">no answer</span>)}</td>
                    <td className="nowrap"><LookUp caseId={caseId} host={x.name} /></td>
                  </>}
                  {type === 'TLS_HANDSHAKE' && <>
                    <td className="small nowrap">{t(x.time)}</td><td className="mono small">{x.client}</td><td className="mono small break strong">{x.server_name || '—'}</td>
                    <td className="mono small">{x.server}:{x.server_port}</td>
                    <td className="nowrap"><LookUp caseId={caseId} host={x.server_name || x.server} /></td>
                  </>}
                  {type === 'NET_CONVERSATION' && <>
                    <td className="small">{x.protocol}<div className="tiny muted">{(x.protocols || []).join(', ')}</div></td>
                    <td className="mono small">{x.client}{x.client_port != null && `:${x.client_port}`}</td>
                    <td className="mono small">{x.server}{x.server_port != null && `:${x.server_port}`}<div className="tiny muted break">{(x.server_names || []).join(', ')}</div></td>
                    <td className="small">{(x.packets ?? 0).toLocaleString()}</td>
                    <td className="small nowrap">{formatBytes(x.bytes_from_client ?? 0)} / {formatBytes(x.bytes_from_server ?? 0)}</td>
                    <td className="small nowrap">{t(x.first)}</td><td className="small nowrap">{t(x.last)}</td>
                    <td className="nowrap"><LookUp caseId={caseId} host={x.server} /></td>
                  </>}
                  <td className="nowrap right"><TagButton type="NETWORK" id={x._id} title={x.url || x.name || x.server_name || `${x.client} ${x.server}`} /></td>
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

function Files({ caseId }: { caseId: string }) {
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [skip, setSkip] = useState(0);
  const qs = new URLSearchParams({ case_id: caseId, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  const res = useApi<{ data: any[]; total: number }>(`/forensics/network/files?${qs}`);
  const rows = res.data?.data || [];
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <input className="input sm" style={{ maxWidth: 300 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && (setSearch(q.trim()), setSkip(0))}
          placeholder="Search names, types, SHA-256" aria-label="Search files" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => { setSearch(q.trim()); setSkip(0); }}>Search</Button>
        <span className="small muted">{res.data ? `${res.data.total.toLocaleString()} files` : ''}</span>
      </div>
      <ErrorBanner error={res.error} />
      {!res.data ? <Loading /> : !rows.length ? <Empty title="No files" text="HTTP carried no files in the case's captures." /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Time</th><th>File</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Hash set</th><th /></tr></thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x._id}>
                  <td className="small nowrap">{x.mtime ? time(x.mtime) : '—'}</td>
                  <td className="small break"><span className="strong">{x.name}</span>{x.container?.note && <> <Badge tone="warn">{x.container.note}</Badge></>}
                    <div className="tiny muted mono break">{x.path}</div></td>
                  <td className="small">{x.mime || '—'}{x.ext_mismatch && <div><Badge tone="danger">renamed</Badge></div>}</td>
                  <td className="small nowrap">{formatBytes(x.size ?? 0)}</td>
                  <td className="mono tiny break">{x.sha256}</td>
                  <td className="small">{x.hash_status && x.hash_status !== 'UNKNOWN' ? <Badge tone={x.hash_status === 'KNOWN_BAD' ? 'danger' : x.hash_status === 'NOTABLE' ? 'warn' : 'neutral'}>{x.hash_status.replace('_', ' ').toLowerCase()}</Badge> : '—'}</td>
                  <td className="nowrap right">
                    <ViewButton source={{ kind: 'member', entryId: x._id, name: x.name }} />
                    <TagButton type="FILE" id={x._id} title={x.path} />
                  </td>
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

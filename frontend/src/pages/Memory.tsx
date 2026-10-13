import { useState } from 'react';
import { Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { useTime } from '../lib/format';
import { TagButton } from '../lib/tags';
import { useApi } from '../lib/useApi';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Pager, Stat, Tabs, type Tone } from '../ui';
import { ExportButton } from '../ui/ExportButton';
import { LookUp } from './Network';

type Tab = 'MEMORY_PROCESS' | 'MEMORY_CONNECTION' | 'MEMORY_INJECTION' | 'MEMORY_SERVICE' | 'MEMORY_DLL';
type Flag = { code: string; label: string; severity: 'high' | 'medium' | 'low' };
const LIMIT = 200;
const SEV_TONE: Record<string, Tone> = { high: 'danger', medium: 'warn', low: 'neutral' };
const NOTES: Record<Tab, string> = {
  MEMORY_PROCESS: 'Processes as Windows held them when the memory was captured, under the process that started them (windows.pstree, with command lines from windows.cmdline). A process stands out for its name, folder or parent, code no file backs, encoded PowerShell, or connections a program rarely makes: leads to examine, not findings.',
  MEMORY_CONNECTION: 'Network endpoints and connections with the process that owned them (windows.netscan). Internet addresses can be looked up with threat intelligence.',
  MEMORY_INJECTION: 'Private memory a process can execute that no file on disk backs (windows.malware.malfind), with its first bytes. Programs that compile code at run time (browsers, .NET) have some; a program header (MZ) in such memory is a program loaded without a file.',
  MEMORY_SERVICE: 'Services and drivers as the service control manager held them (windows.svcscan), with the program each runs.',
  MEMORY_DLL: 'The DLLs loaded in the processes that stand out (windows.dlllist).',
};

function Flags({ flags, all }: { flags?: Flag[]; all?: boolean }) {
  const shown = (flags || []).filter((f) => all || f.severity !== 'low');
  return <>{shown.map((f) => <div key={f.code}><Badge tone={SEV_TONE[f.severity]}>{f.label}</Badge></div>)}</>;
}

export function MemoryPage() {
  const { caseId, overview } = useCase();
  const time = useTime();
  const [tab, setTab] = useState<Tab>('MEMORY_PROCESS');
  const c = overview?.counts;
  const info = useApi<{ data: any[] }>(`/forensics/memory?case_id=${encodeURIComponent(caseId)}&type=MEMORY_INFO`);
  const images = info.data?.data || [];
  const [image, setImage] = useState('');
  const eid = image || images[0]?.evidence_id || '';
  return (
    <div className="stack">
      <PageHeader title="Memory"
        subtitle="Windows memory images read with Volatility 3: the processes and their tree, network connections, code injected into processes, services and the DLLs of the processes that stand out." />
      {c && !c.memory_images && <Banner tone="info">No memory image has been analysed in this case. Upload a memory capture as evidence: a .mem, .vmem or .lime file,
        a complete Windows crash dump (.dmp), or a raw capture marked as a memory image.</Banner>}
      {!!c?.memory_images && info.data && images.length < c.memory_images && (
        <Banner tone="warn">{c.memory_images - images.length} of the {c.memory_images} memory images in this case {c.memory_images - images.length === 1 ? 'has' : 'have'} not been
          read: run the analysis, or open the evidence to see why Volatility could not read {c.memory_images - images.length === 1 ? 'it' : 'them'} (for example, symbols it needed).</Banner>
      )}
      <ErrorBanner error={info.error} />
      {images.map((x) => (
        <Card key={x._id} title={`Memory image ${x.evidence_id}`} subtitle={[x.container, x.volatility && `Volatility ${x.volatility}`].filter(Boolean).join(' · ')}>
          <div className="stats">
            <Stat label="Windows" value={x.windows || '—'} hint={[x.architecture, x.version && `NT ${x.version}`].filter(Boolean).join(' · ')} />
            <Stat label="Build" value={x.build ?? '—'} hint={x.processors ? `${x.processors} processors` : undefined} />
            <Stat label="Captured" value={x.system_time ? time(x.system_time) : '—'} hint="the computer's clock" />
            <Stat label="Processes" value={(x.processes ?? 0).toLocaleString()} hint={`${x.processes_notable ?? 0} stand out`} />
            <Stat label="Connections" value={(x.connections ?? 0).toLocaleString()} hint={`${x.connections_external ?? 0} to internet addresses`} />
            <Stat label="Injected code" value={(x.injections ?? 0).toLocaleString()} hint="regions (malfind)" />
          </div>
        </Card>
      ))}
      {images.length > 0 && (
        <Card flush>
          <Tabs<Tab> value={tab} onChange={setTab} tabs={[
            { id: 'MEMORY_PROCESS', label: 'Processes', count: c?.memory_processes },
            { id: 'MEMORY_CONNECTION', label: 'Connections', count: c?.memory_connections },
            { id: 'MEMORY_INJECTION', label: 'Injected code', count: c?.memory_injections },
            { id: 'MEMORY_SERVICE', label: 'Services', count: c?.memory_services },
            { id: 'MEMORY_DLL', label: 'DLLs' },
          ]} />
          <p className="small muted" style={{ margin: 0, padding: '10px 14px 0' }}>{NOTES[tab]}</p>
          {images.length > 1 && (
            <div className="row" style={{ padding: '10px 14px 0' }}>
              <label className="small strong" htmlFor="memimage">Memory image</label>
              <select id="memimage" className="select sm" style={{ maxWidth: 240 }} value={eid} onChange={(e) => setImage(e.target.value)}>
                {images.map((x) => <option key={x.evidence_id} value={x.evidence_id}>{x.evidence_id} · {x.windows}</option>)}
              </select>
            </div>
          )}
          {tab === 'MEMORY_PROCESS' ? <Processes key={eid} caseId={caseId} evidenceId={eid} /> : <Records key={`${tab}${eid}`} caseId={caseId} evidenceId={eid} type={tab} />}
        </Card>
      )}
    </div>
  );
}

function ProcessRow({ p, depth }: { p: any; depth: number }) {
  const time = useTime();
  return (
    <>
      <tr className={p.notable ? 'row-flagged' : undefined}>
        <td className="small" style={{ paddingLeft: 14 + depth * 18 }}>
          <span className="strong mono">{p.name}</span>{p.exited && <> <Badge tone="neutral">exited</Badge></>}
          {(p.decoded_command || p.cmdline || p.path) && <div className="tiny muted mono break">{p.decoded_command ? `decoded: ${p.decoded_command}` : p.cmdline || p.path}</div>}
        </td>
        <td className="small mono">{p.pid}</td>
        <td className="small nowrap">{p.created ? time(p.created) : '—'}{p.exited && <div className="tiny muted">ended {time(p.exited)}</div>}</td>
        <td className="small"><Flags flags={p.flags} /></td>
        <td className="nowrap right"><TagButton type="MEMORY" id={p._id} title={`${p.name} (PID ${p.pid})`} /></td>
      </tr>
      {(p.children || []).map((ch: any) => <ProcessRow key={ch._id} p={ch} depth={depth + 1} />)}
    </>
  );
}

function Processes({ caseId, evidenceId }: { caseId: string; evidenceId: string }) {
  const [notable, setNotable] = useState(false);
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const listed = notable || !!search;
  const tree = useApi<{ data: any[]; total: number }>(!listed ? `/forensics/memory/tree?case_id=${encodeURIComponent(caseId)}&evidence_id=${encodeURIComponent(evidenceId)}` : null);
  const qs = new URLSearchParams({ case_id: caseId, type: 'MEMORY_PROCESS', evidence_id: evidenceId, limit: '1000' });
  if (notable) qs.set('notable', 'true');
  if (search) qs.set('search', search);
  const path = `/forensics/memory?${qs}`;
  const list = useApi<{ data: any[]; total: number }>(listed ? path : null);
  const res = listed ? list : tree;
  const rows = res.data?.data || [];
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <input className="input sm" style={{ maxWidth: 280 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
          placeholder="Search name, path, command line, PID" aria-label="Search processes" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
        <label className="check"><input type="checkbox" checked={notable} onChange={(e) => setNotable(e.target.checked)} /> Only processes that stand out</label>
        <span className="small muted">{res.data ? `${res.data.total.toLocaleString()} processes${listed ? '' : ', as a tree'}` : ''}</span>
        <span style={{ flex: 1 }} />
        <ExportButton path={path} what="list of processes" />
      </div>
      <ErrorBanner error={res.error} />
      {!res.data ? <Loading /> : !rows.length ? <Empty title="No process" text={listed ? 'No process matches.' : 'Volatility listed no process.'} /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Process</th><th>PID</th><th>Started</th><th>Why it stands out</th><th /></tr></thead>
            <tbody>{rows.map((p) => <ProcessRow key={p._id} p={p} depth={0} />)}</tbody>
          </table>
        </div>
      )}
    </>
  );
}

function Records({ caseId, evidenceId, type }: { caseId: string; evidenceId: string; type: Exclude<Tab, 'MEMORY_PROCESS'> }) {
  const time = useTime();
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [only, setOnly] = useState(false);
  const [skip, setSkip] = useState(0);
  const qs = new URLSearchParams({ case_id: caseId, type, evidence_id: evidenceId, limit: String(LIMIT), skip: String(skip) });
  if (search) qs.set('search', search);
  if (only) qs.set(type === 'MEMORY_CONNECTION' ? 'external' : 'notable', 'true');
  const path = `/forensics/memory?${qs}`;
  const res = useApi<{ data: any[]; total: number }>(path);
  const rows = res.data?.data || [];
  const t = (v: any) => (v ? time(v) : '—');
  const onlyLabel = { MEMORY_CONNECTION: 'Only internet addresses', MEMORY_INJECTION: 'Only those that stand out', MEMORY_SERVICE: 'Only services that stand out',
    MEMORY_DLL: 'Only DLLs that stand out' }[type];
  const cols: Record<typeof type, string[]> = {
    MEMORY_CONNECTION: ['Process', 'Protocol', 'Local', 'Remote', 'State', 'Created', 'Why'],
    MEMORY_INJECTION: ['Process', 'Region', 'Protection', 'First bytes', 'Why'],
    MEMORY_SERVICE: ['Service', 'Program', 'State', 'Start', 'Why'],
    MEMORY_DLL: ['Process', 'DLL', 'Base', 'Loaded', 'Why'],
  };
  return (
    <>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <input className="input sm" style={{ maxWidth: 280 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && (setSearch(q.trim()), setSkip(0))}
          placeholder="Search" aria-label="Search records" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => { setSearch(q.trim()); setSkip(0); }}>Search</Button>
        <label className="check"><input type="checkbox" checked={only} onChange={(e) => { setOnly(e.target.checked); setSkip(0); }} /> {onlyLabel}</label>
        <span className="small muted">{res.data ? `${res.data.total.toLocaleString()} records` : ''}</span>
        <span style={{ flex: 1 }} />
        {rows.length > 0 && <ExportButton path={path} what="list" />}
      </div>
      <ErrorBanner error={res.error} />
      {!res.data ? <Loading /> : !rows.length ? <Empty title="Nothing here" text="No record of this kind." /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr>{cols[type].map((h) => <th key={h}>{h}</th>)}<th /></tr></thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x._id} className={x.notable ? 'row-flagged' : undefined}>
                  {type === 'MEMORY_CONNECTION' && <>
                    <td className="small"><span className="mono">{x.owner || '—'}</span> <span className="muted">({x.pid})</span></td>
                    <td className="small">{x.proto}</td>
                    <td className="mono small nowrap">{x.local_addr}:{x.local_port}</td>
                    <td className="mono small nowrap">{x.foreign_addr}{x.foreign_port ? `:${x.foreign_port}` : ''}
                      {x.external && <div><LookUp caseId={caseId} host={x.foreign_addr} /></div>}</td>
                    <td className="small">{x.state || '—'}</td>
                    <td className="small nowrap">{t(x.created)}</td>
                    <td className="small"><Flags flags={x.flags} /></td>
                  </>}
                  {type === 'MEMORY_INJECTION' && <>
                    <td className="small"><span className="mono">{x.process}</span> <span className="muted">({x.pid})</span></td>
                    <td className="mono small nowrap">{x.start}–{x.end}<div className="tiny muted">{(x.size ?? 0).toLocaleString()} bytes · {x.tag}</div></td>
                    <td className="small">{x.protection}</td>
                    <td className="mono tiny break" style={{ maxWidth: 320 }}>{x.hexdump}
                      {x.disasm && <pre className="tiny muted" style={{ margin: '4px 0 0', whiteSpace: 'pre-wrap' }}>{x.disasm}</pre>}</td>
                    <td className="small"><Flags flags={x.flags} all /></td>
                  </>}
                  {type === 'MEMORY_SERVICE' && <>
                    <td className="small"><span className="strong">{x.name}</span><div className="tiny muted">{x.display}</div></td>
                    <td className="mono small break">{x.binary_registry || x.binary || '—'}{x.dll && <div className="tiny muted">DLL {x.dll}</div>}</td>
                    <td className="small">{(x.state || '').replace('SERVICE_', '').toLowerCase()}{x.pid ? <div className="tiny muted">{x.process || 'PID'} {x.pid}</div> : null}</td>
                    <td className="small">{(x.start || '').replace('SERVICE_', '').replace('_START', '').toLowerCase()}</td>
                    <td className="small"><Flags flags={x.flags} /></td>
                  </>}
                  {type === 'MEMORY_DLL' && <>
                    <td className="small"><span className="mono">{x.process}</span> <span className="muted">({x.pid})</span></td>
                    <td className="mono small break">{x.path || x.name}</td>
                    <td className="mono small">{x.base}</td>
                    <td className="small nowrap">{t(x.load_time)}</td>
                    <td className="small"><Flags flags={x.flags} /></td>
                  </>}
                  <td className="nowrap right"><TagButton type="MEMORY" id={x._id} title={x.process || x.owner || x.name} /></td>
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

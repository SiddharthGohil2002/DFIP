import { useState } from 'react';
import { Cpu, Search } from 'lucide-react';
import { api, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { formatBytes, shortHash, useTime } from '../lib/format';
import { TagButton } from '../lib/tags';
import { useApi } from '../lib/useApi';
import { ViewButton, type ViewSource } from '../ui/FileViewer';
import { Badge, Button, Card, Empty, ErrorBanner, Loading, Modal, Pager, type Tone, useToast } from '../ui';

const LIMIT = 50;
const SIG_TONE: Record<string, Tone> = { valid: 'ok', untrusted: 'warn', expired: 'warn', invalid: 'danger', unsigned: 'neutral', error: 'danger' };
const SIG_LABEL: Record<string, string> = { valid: 'SIGNED', untrusted: 'SIGNED, UNTRUSTED', expired: 'SIGNED, EXPIRED', invalid: 'BAD SIGNATURE',
  unsigned: 'UNSIGNED', error: 'SIGNATURE ERROR' };
const SEV_TONE: Record<string, Tone> = { high: 'danger', medium: 'warn', low: 'neutral' };

function VtBadge({ vt }: { vt?: any }) {
  if (!vt) return <span className="muted small">—</span>;
  if (vt.status !== 'COMPLETED') return <Badge>{String(vt.status).replace('_', ' ')}</Badge>;
  const total = ['malicious', 'suspicious', 'harmless', 'undetected'].reduce((n, k) => n + (vt[k] || 0), 0);
  return <Badge tone={vt.malicious ? 'danger' : 'ok'} title={`${vt.malicious} of ${total} engines say malicious`}>{vt.malicious}/{total}</Badge>;
}

/** Programs on the evidence: those that stand out first, with why, their signature, VirusTotal (when the case turned it on) and capa. */
export function ProgramsCard() {
  const { caseId, activeCase, reloadCases, overview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const [all, setAll] = useState(false);
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [skip, setSkip] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const qs = new URLSearchParams({ case_id: caseId, limit: String(LIMIT), skip: String(skip) });
  if (!all) qs.set('flagged', 'true');
  if (search) qs.set('search', search);
  const { data, error, loading } = useApi<{ data: any[]; total: number }>(`/forensics/executables?${qs}`);
  const status = useApi<any>('/malware/status');
  const auto = !!(activeCase as any)?.threat_intel?.auto_lookup;

  async function toggle() {
    setBusy(true);
    try {
      const r = await api<any>(`/cases/${encodeURIComponent(caseId)}/threat-intel`, { method: 'PUT', json: { auto_lookup: !auto } });
      await reloadCases();
      toast(r.threat_intel.auto_lookup ? `Automatic VirusTotal lookups on; ${r.jobs.length} lookup job(s) started` : 'Automatic VirusTotal lookups off', 'ok');
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Programs that stand out" flush
      subtitle={`${(overview?.counts.programs ?? 0).toLocaleString()} Windows programs analysed (structure, signature, imports; never run). Packed, renamed or masquerading programs, bad or untrusted signatures and suspicious imports are listed first.`}>
      <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
        <input className="input sm" style={{ maxWidth: 260 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
          placeholder="Search path, publisher, signer" aria-label="Search programs" />
        <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
        <label className="check"><input type="checkbox" checked={all} onChange={(e) => { setAll(e.target.checked); setSkip(0); }} /> All programs</label>
        <span className="small muted">{data ? `${data.total.toLocaleString()} programs` : ''}</span>
        <span style={{ flex: 1 }} />
        <label className="check" title={status.data?.virustotal.configured ? 'Only SHA-256 hashes are sent to VirusTotal' : 'No VirusTotal key is configured on the server'}>
          <input type="checkbox" checked={auto} disabled={busy || !can('CASE_UPDATE')} onChange={toggle} aria-label="Automatic VirusTotal lookups" />
          Look up program hashes on VirusTotal for this case{status.data && !status.data.virustotal.configured ? ' (no key configured)' : ''}
        </label>
      </div>
      <ErrorBanner error={error} />
      {loading && !data ? <Loading /> : !data?.data.length ? (
        <Empty title={all ? 'No programs' : 'No program stands out'} text={all ? 'No Windows program was found; programs are analysed by the Standard and Full profiles.' : 'Tick "All programs" to see every program analysed.'} />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Program</th><th>Why it stands out</th><th>Signature</th><th>VirusTotal</th><th>capa</th><th /></tr></thead>
            <tbody>
              {data.data.map((p) => (
                <tr key={p._id}>
                  <td className="small"><button className="link-button mono" onClick={() => setOpen(p.artifact_id)}>{p.path}</button>
                    {p.deleted && <> <Badge tone="danger">DELETED</Badge></>}
                    <div className="tiny muted">{[p.pe?.version_info?.FileDescription, p.pe?.version_info?.CompanyName].filter(Boolean).join(' · ')}</div></td>
                  <td className="small">{(p.flags || []).filter((f: any) => f.severity !== 'low').map((f: any) => (
                    <div key={f.code}><Badge tone={SEV_TONE[f.severity]}>{f.label}</Badge></div>))}</td>
                  <td><Badge tone={SIG_TONE[p.signature?.status] || 'neutral'}>{SIG_LABEL[p.signature?.status] || p.signature?.status}</Badge></td>
                  <td><VtBadge vt={p.vt} /></td>
                  <td className="small">{p.capa ? `${p.capa.capabilities?.length ?? 0} capabilities` : '—'}</td>
                  <td className="nowrap right"><TagButton type="PROGRAM" id={p._id} title={p.path} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />}
      {open && <ProgramDetail id={open} onClose={() => setOpen(null)} />}
    </Card>
  );
}

function ProgramDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const time = useTime();
  const { can } = useAuth();
  const toast = useToast();
  const res = useApi<any>(`/forensics/executables/${encodeURIComponent(id)}`);
  const [running, setRunning] = useState(false);
  const p = res.data;
  const pe = p?.pe;
  const suspicious = new Set<string>((p?.api_groups || []).flatMap((g: any) => g.functions));

  async function runCapa() {
    setRunning(true);
    try {
      await post(`/forensics/executables/${encodeURIComponent(id)}/capa`);
      res.reload();
      toast('capa finished', 'ok');
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setRunning(false);
    }
  }
  const source: ViewSource | null = p ? (p.container ? { kind: 'member', entryId: p.entry_id, name: p.path }
    : { kind: 'image', evidenceId: p.evidence_id, inode: p.inode, offset: p.partition_offset || 0, name: p.path, volumeId: p.volume_id }) : null;

  return (
    <Modal open wide title={p ? p.name : 'Program'} onClose={onClose}>
      <ErrorBanner error={res.error} />
      {!p ? <Loading /> : (
        <div className="stack" style={{ gap: 14 }}>
          <dl className="kv">
            <dt>File</dt><dd className="mono small">{p.path}{p.deleted && <> <Badge tone="danger">DELETED</Badge></>}</dd>
            <dt>Size and hashes</dt><dd className="mono tiny">{formatBytes(p.size)} · SHA-256 {shortHash(p.sha256, 32)} · imphash {pe.imphash || '—'}</dd>
            <dt>Built</dt><dd className="small">{pe.machine}, {pe.bits}-bit {pe.dll ? 'DLL' : 'program'} ({pe.subsystem}) · compile time <span className="mono">{pe.compiled ? time(pe.compiled) : '—'}</span>
              <span className="muted"> (set by the compiler; can be faked)</span></dd>
            {pe.pdb_path && (<><dt>Debug path</dt><dd className="mono small">{pe.pdb_path}</dd></>)}
            {Object.keys(pe.version_info || {}).length > 0 && (<><dt>Version information</dt>
              <dd className="small">{Object.entries(pe.version_info).map(([k, v]) => <div key={k}><span className="muted">{k}:</span> {String(v)}</div>)}</dd></>)}
            <dt>Signature</dt>
            <dd className="small"><Badge tone={SIG_TONE[p.signature.status]}>{SIG_LABEL[p.signature.status] || p.signature.status}</Badge>
              {(p.signature.signers || []).map((s: any, i: number) => (
                <div key={i} style={{ marginTop: 4 }}>
                  <div>{s.signer}{s.program ? ` · "${s.program}"` : ''}{s.more_info ? ` · ${s.more_info}` : ''}</div>
                  <div className="tiny muted">signed {s.signing_time ? time(s.signing_time) : '(no signing time)'} · {s.digest} · chain: {s.certificates.map((c: any) => c.subject.split(',').find((x: string) => x.trim().startsWith('CN='))?.trim() || c.subject).join(' → ')}</div>
                </div>
              ))}
              {p.signature.detail && <div className="tiny muted" style={{ marginTop: 4 }}>{p.signature.detail}</div>}</dd>
            {p.vt && (<><dt>VirusTotal</dt><dd className="small"><VtBadge vt={p.vt} /> <span className="muted">checked {p.vt.queried_at ? time(p.vt.queried_at) : ''}</span></dd></>)}
          </dl>
          {!!p.flags?.length && (
            <div className="stack" style={{ gap: 4 }}>
              <div className="small strong">Why it stands out</div>
              {p.flags.map((f: any) => <div key={f.code} className="small"><Badge tone={SEV_TONE[f.severity]}>{f.severity.toUpperCase()}</Badge> {f.label}
                {f.detail && <span className="muted tiny"> — {f.detail}</span>}</div>)}
            </div>
          )}
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Section</th><th className="right">Size in file</th><th className="right">Size in memory</th><th className="right">Entropy</th><th>Flags</th></tr></thead>
              <tbody>
                {pe.sections.map((s: any, i: number) => (
                  <tr key={i}>
                    <td className="mono small">{s.name}</td><td className="right small">{s.raw_size.toLocaleString()}</td>
                    <td className="right small">{s.virtual_size.toLocaleString()}</td>
                    <td className="right small">{s.entropy > 7.2 ? <Badge tone="warn">{s.entropy.toFixed(2)}</Badge> : s.entropy.toFixed(2)}</td>
                    <td className="small">{[s.executable && 'code', s.writable && 'writable'].filter(Boolean).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <details>
            <summary className="small">Imports ({pe.import_count} functions from {Object.keys(pe.imports).length} DLLs; suspicious ones highlighted)</summary>
            <div className="imports">
              {Object.entries(pe.imports).map(([dll, fns]: [string, any]) => (
                <div key={dll} className="small"><span className="strong mono">{dll}</span>: {fns.map((f: string, i: number) => (
                  <span key={i} className={suspicious.has(f) ? 'import-flag mono' : 'mono muted'}>{f}{i < fns.length - 1 ? ', ' : ''}</span>))}</div>
              ))}
            </div>
          </details>
          <div className="stack" style={{ gap: 6 }}>
            <div className="row">
              <span className="small strong">Capabilities (capa)</span>
              {p.capa && <span className="tiny muted">{p.capa.status === 'limited' ? 'limited: ' + (p.capa.limitations || []).join(', ') : ''} · run {p.capa.ran} · capa {p.capa.version}</span>}
              <span style={{ flex: 1 }} />
              {can('ANALYSIS_RUN') && <Button size="sm" icon={<Cpu size={13} />} disabled={running} onClick={runCapa}>{running ? 'Running capa…' : p.capa ? 'Run capa again' : 'Run capa'}</Button>}
            </div>
            {!p.capa ? <div className="small muted">capa runs automatically on the programs that stand out most; run it on this one on request.</div>
              : p.capa.status === 'failed' || p.capa.status === 'unavailable' ? <div className="small">{p.capa.detail}</div> : (
                <div className="table-wrap">
                  <table className="table">
                    <thead><tr><th>Capability</th><th>Namespace</th><th>ATT&amp;CK</th></tr></thead>
                    <tbody>
                      {(p.capa.capabilities || []).map((c: any) => (
                        <tr key={c.name}><td className="small">{c.name}</td><td className="mono tiny">{c.namespace || '—'}</td>
                          <td className="mono tiny">{(c.attack || []).join(', ') || '—'}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
          </div>
          <div className="row">{source && <ViewButton source={source} />}<TagButton type="PROGRAM" id={p._id} title={p.path} /></div>
        </div>
      )}
    </Modal>
  );
}

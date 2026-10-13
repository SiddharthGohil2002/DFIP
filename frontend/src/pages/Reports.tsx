import { useEffect, useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, Download, FileCheck2, FileCode2, FileText, Save, Share2, Trash2 } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { api, del, downloadExport, downloadFile, post } from '../lib/api';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Indicator, Report, ReportCover, ReportSection, ReportTemplate, ReportTemplateBody, SignatureCheck } from '../lib/types';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Field, Hash, Loading, Modal, PageHeader, useToast } from '../ui';

const EMPTY_COVER: ReportCover = { title: '', organisation: '', reference: '', prepared_for: '', classification: '', scope: '' };
const COVER_FIELDS: [Exclude<keyof ReportCover, 'scope'>, string, string][] = [
  ['title', 'Title', 'Digital Forensics Investigation Report'],
  ['organisation', 'Organisation', 'Your lab or company'],
  ['reference', 'Reference', 'Your file or matter number'],
  ['prepared_for', 'Prepared for', 'Who asked for the report'],
  ['classification', 'Classification', 'Shown at the top and bottom of every page'],
];
const TLPS = ['clear', 'green', 'amber', 'red'] as const;

type Draft = { order: string[]; on: string[]; cover: ReportCover; approved_findings_only: boolean; include_screenshots: boolean };

function draftFrom(all: string[], t?: ReportTemplateBody | null): Draft {
  if (!t) return { order: all, on: all, cover: EMPTY_COVER, approved_findings_only: false, include_screenshots: true };
  return { order: [...t.sections, ...all.filter((s) => !t.sections.includes(s))], on: t.sections, cover: { ...EMPTY_COVER, ...t.cover },
    approved_findings_only: t.approved_findings_only, include_screenshots: t.include_screenshots };
}

function SignatureBadge({ s }: { s?: Report['signature'] }) {
  if (!s) return <Badge tone="neutral" title="Made before reports were signed">Not signed</Badge>;
  if (!s.signed) return <Badge tone="danger" title={s.error}>Not signed</Badge>;
  const ts = s.timestamped ? ', timestamped' : '';
  return s.self_signed
    ? <Badge tone="warn" title="Signed with DFIP's own certificate: it shows the file is unchanged since it was made, not who issued it">Self-signed{ts}</Badge>
    : <Badge tone="ok" title={s.signer}>Signed{ts}</Badge>;
}

function CheckResult({ r }: { r: SignatureCheck }) {
  const time = useTime();
  const yes = (v?: boolean) => (v ? 'Yes' : 'No');
  return (
    <div className="stack" style={{ gap: 12 }}>
      {r.valid ? <Banner tone="ok">The signature is intact and covers the whole file: nothing was changed or added after it was signed.</Banner>
        : <Banner tone="danger">{r.error || 'The signature does not check out.'}</Banner>}
      {r.sha256_matches !== undefined && (r.sha256_matches
        ? <Banner tone="ok">Its SHA-256 matches the one recorded when the report was generated.</Banner>
        : <Banner tone="danger">Its SHA-256 differs from the one recorded when the report was generated.</Banner>)}
      {r.matches_report !== undefined && (r.matches_report
        ? <Banner tone="ok">This file is report {r.matches_report}, byte for byte.</Banner>
        : <Banner tone="info">This file is not, byte for byte, a report of a case you can see.</Banner>)}
      {r.signatures.map((s) => (
        <dl key={s.field} className="kv">
          <dt>Signed by</dt><dd>{s.signer || '—'}{s.self_signed && <> <Badge tone="warn">self-signed</Badge></>}</dd>
          <dt>Certificate trusted</dt><dd>{yes(s.trusted)}{!s.trusted && <span className="small muted"> — {s.self_signed
            ? "DFIP's own certificate: configure an organisation certificate to have reports trusted"
            : 'its issuer is not among the trusted roots configured on the server'}</span>}</dd>
          <dt>Signature intact</dt><dd>{yes(s.intact && s.cryptographically_valid)}</dd>
          <dt>Covers the whole file</dt><dd>{yes(s.covers_whole_file)}</dd>
          <dt>Signing time</dt><dd>{s.signing_time ? time(s.signing_time) : '—'}{s.timestamp ? ' (claimed by the signer)' : ''}</dd>
          <dt>Timestamp</dt><dd>{s.timestamp ? <>{time(s.timestamp.time)} — {s.timestamp.trusted ? 'from a trusted authority' : 'authority not trusted'}
            {!(s.timestamp.intact && s.timestamp.valid) && <Badge tone="danger">broken</Badge>}</> : 'None'}</dd>
          {s.error && <><dt>Error</dt><dd>{s.error}</dd></>}
        </dl>
      ))}
      <div className="small">SHA-256 of the file checked: <Hash value={r.sha256} /></div>
    </div>
  );
}

export function ReportsPage() {
  const { caseId, reloadOverview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const sections = useApi<{ data: ReportSection[] }>('/reports/sections');
  const templates = useApi<{ data: ReportTemplate[] }>('/reports/templates');
  const list = useApi<{ data: Report[] }>(`/reports?case_id=${encodeURIComponent(caseId)}`);
  const reports = (list.data?.data || []).filter((r) => r.case_id === caseId);
  const all = useMemo(() => (sections.data?.data || []).map((s) => s.id), [sections.data]);
  const byId = useMemo(() => Object.fromEntries((sections.data?.data || []).map((s) => [s.id, s])), [sections.data]);
  const [tplId, setTplId] = useState('');
  const [draft, setDraft] = useState<Draft>(() => draftFrom([]));
  const [dirty, setDirty] = useState(false);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [check, setCheck] = useState<{ title: string; result: SignatureCheck } | null>(null);
  const [upload, setUpload] = useState<File | null>(null);
  const tpl = (templates.data?.data || []).find((t) => t.template_id === tplId) || null;

  useEffect(() => {
    if (all.length) { setDraft(draftFrom(all, tpl)); setDirty(false); setName(tpl?.name || ''); }
  }, [all, tplId, templates.data]); // eslint-disable-line react-hooks/exhaustive-deps

  const edit = (d: Partial<Draft>) => { setDraft({ ...draft, ...d }); setDirty(true); };
  const move = (i: number, by: number) => {
    const order = [...draft.order];
    [order[i], order[i + by]] = [order[i + by], order[i]];
    edit({ order });
  };
  const chosen = draft.order.filter((s) => draft.on.includes(s));
  const body = (): ReportTemplateBody => ({ name: name.trim() || 'Custom report', sections: chosen, cover: draft.cover,
    approved_findings_only: draft.approved_findings_only, include_screenshots: draft.include_screenshots });

  async function run(key: string, fn: () => Promise<void>) {
    setBusy(key);
    try { await fn(); } catch (e: any) { toast(e.message, 'danger'); } finally { setBusy(null); }
  }

  const generate = () => run('generate', async () => {
    const r = await post<Report>(`/reports?case_id=${encodeURIComponent(caseId)}`, tpl && !dirty ? { template_id: tpl.template_id } : { template: body() });
    toast(`${r.report_id} (version ${r.version}) generated${r.signature?.signed ? ' and signed' : ''}`, 'ok');
    if (r.signature && !r.signature.signed) toast(`The report could not be signed: ${r.signature.error}`, 'danger');
    list.reload();
    reloadOverview();
  });
  const saveTemplate = (asNew: boolean) => run('save', async () => {
    const t = asNew || !tpl ? await post<ReportTemplate>('/reports/templates', body())
      : await api<ReportTemplate>(`/reports/templates/${encodeURIComponent(tpl.template_id)}`, { method: 'PUT', json: body() });
    toast(`Template "${t.name}" saved`, 'ok');
    templates.reload();
    setTplId(t.template_id);
  });
  const removeTemplate = () => run('delete', async () => {
    if (!tpl) return;
    await del(`/reports/templates/${encodeURIComponent(tpl.template_id)}`);
    toast(`Template "${tpl.name}" deleted`, 'ok');
    setTplId('');
    templates.reload();
  });
  const download = (r: Report, format: 'pdf' | 'html') => run(`${r.report_id}-${format}`, async () => {
    const sha = await downloadFile(`/reports/${encodeURIComponent(r.report_id)}/download?format=${format}`, `${r.report_id}-${r.case_id}.${format}`);
    const want = format === 'pdf' ? r.sha256 : r.html_sha256;
    if (sha && want && sha !== want) toast('Warning: the server returned a different hash than recorded', 'danger');
  });
  const verifyStored = (r: Report) => run(`${r.report_id}-check`, async () => {
    setCheck({ title: `Check ${r.report_id}`, result: await api<SignatureCheck>(`/reports/${encodeURIComponent(r.report_id)}/verify`) });
  });
  const verifyUpload = () => run('upload', async () => {
    if (!upload) return;
    const form = new FormData();
    form.append('file', upload);
    setCheck({ title: `Check ${upload.name}`, result: await api<SignatureCheck>('/reports/verify', { method: 'POST', body: form }) });
  });

  return (
    <div className="stack">
      <PageHeader
        title="Reports"
        subtitle="Each report is a new version built from the case's current data, as a signed PDF and the same content as one HTML file. Their SHA-256 hashes are recorded when they are generated, and the PDF's signature shows any later change."
        actions={can('REPORT_CREATE') && <Button variant="primary" icon={<FileText size={15} />} busy={busy === 'generate'} disabled={!chosen.length} onClick={generate}>Generate report</Button>}
      />
      <div className="grid grid-side" style={{ alignItems: 'start' }}>
        <div className="stack">
          <Card title="Report versions" flush>
            {list.loading && !list.data ? <Loading /> : !reports.length ? (
              <Empty icon={<FileText size={20} />} title="No reports for this case" text="Choose what the report holds, then generate it when the analysis is complete and findings are recorded." />
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Report</th><th>Generated</th><th>Signature</th><th>PDF SHA-256</th><th /></tr></thead>
                  <tbody>
                    {reports.map((r) => (
                      <tr key={r._id}>
                        <td className="nowrap"><span className="mono strong">{r.report_id}</span> <Badge tone="accent">v{r.version}</Badge>
                          <div className="tiny muted">{r.template?.name || 'Full report'}</div></td>
                        <td className="small nowrap">{time(r.created_at)}<div className="tiny muted">{r.created_by_name}</div></td>
                        <td><SignatureBadge s={r.signature} /></td>
                        <td><Hash value={r.sha256} short={12} /></td>
                        <td className="nowrap right">
                          <Button size="sm" icon={<Download size={13} />} busy={busy === `${r.report_id}-pdf`} onClick={() => download(r, 'pdf')} aria-label={`Download ${r.report_id} PDF`}>PDF</Button>{' '}
                          {r.has_html && <><Button size="sm" icon={<FileCode2 size={13} />} busy={busy === `${r.report_id}-html`} onClick={() => download(r, 'html')} aria-label={`Download ${r.report_id} HTML`}>HTML</Button>{' '}</>}
                          <Button size="sm" variant="ghost" icon={<FileCheck2 size={13} />} busy={busy === `${r.report_id}-check`} onClick={() => verifyStored(r)} aria-label={`Check ${r.report_id}`}>Check</Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
          <Card title="Check a report PDF" subtitle="A copy someone was given: its signature, and whether it is, byte for byte, a report DFIP made.">
            <div className="row">
              <input type="file" accept="application/pdf,.pdf" aria-label="Report PDF to check" onChange={(e) => setUpload(e.target.files?.[0] || null)} />
              <Button icon={<FileCheck2 size={14} />} disabled={!upload} busy={busy === 'upload'} onClick={verifyUpload}>Check file</Button>
            </div>
            <p className="small muted" style={{ marginBottom: 0 }}>Without DFIP: <code>Get-FileHash file.pdf -Algorithm SHA256</code> must equal the SHA-256 listed above, and Adobe Reader or <code>pdfsig</code> shows the signature.</p>
          </Card>
          {can('REPORT_EXPORT') && <CaseExports caseId={caseId} />}
        </div>
        <ReportContents
          sections={sections.data?.data} templates={templates.data?.data || []} tplId={tplId} setTplId={setTplId} draft={draft} edit={edit} move={move}
          byId={byId} name={name} setName={setName} dirty={dirty} busy={busy} canSave={can('REPORT_CREATE')} onSave={saveTemplate} onDelete={removeTemplate}
          error={sections.error || templates.error} chosen={chosen.length}
        />
      </div>
      <Modal open={!!check} title={check?.title || ''} onClose={() => setCheck(null)} footer={<Button onClick={() => setCheck(null)}>Close</Button>}>
        {check && <CheckResult r={check.result} />}
      </Modal>
    </div>
  );
}

function ReportContents({ sections, templates, tplId, setTplId, draft, edit, move, byId, name, setName, dirty, busy, canSave, onSave, onDelete, error, chosen }: {
  sections?: ReportSection[]; templates: ReportTemplate[]; tplId: string; setTplId: (v: string) => void; draft: Draft; edit: (d: Partial<Draft>) => void;
  move: (i: number, by: number) => void; byId: Record<string, ReportSection>; name: string; setName: (v: string) => void; dirty: boolean; busy: string | null;
  canSave: boolean; onSave: (asNew: boolean) => void; onDelete: () => void; error?: string | null; chosen: number;
}) {
  const tpl = templates.find((t) => t.template_id === tplId);
  return (
    <Card title="What the report holds" subtitle={`${chosen} of ${sections?.length ?? 0} sections${dirty ? ' · changed' : ''}`}>
      <ErrorBanner error={error} />
      {!sections ? <Loading /> : (
        <div className="stack" style={{ gap: 12 }}>
          <Field label="Template">
            <select className="select" value={tplId} onChange={(e) => setTplId(e.target.value)} aria-label="Template">
              <option value="">Full report (every section)</option>
              {templates.map((t) => <option key={t.template_id} value={t.template_id}>{t.name}</option>)}
            </select>
          </Field>
          <fieldset className="field" style={{ border: 'none', padding: 0, margin: 0 }}>
            <legend className="small strong" style={{ color: 'var(--ink-2)', marginBottom: 6 }}>Sections, in order</legend>
            <div className="row" style={{ marginBottom: 6 }}>
              <Button size="sm" variant="ghost" onClick={() => edit({ on: draft.order })}>All</Button>
              <Button size="sm" variant="ghost" onClick={() => edit({ on: [] })}>None</Button>
              <Button size="sm" variant="ghost" onClick={() => edit({ order: sections.map((s) => s.id) })}>Default order</Button>
            </div>
            <ol className="section-list">
              {draft.order.map((id, i) => byId[id] && (
                <li key={id} className={draft.on.includes(id) ? '' : 'off'}>
                  <label className="check">
                    <input type="checkbox" checked={draft.on.includes(id)}
                      onChange={(e) => edit({ on: e.target.checked ? [...draft.on, id] : draft.on.filter((x) => x !== id) })} />
                    {byId[id].title}
                  </label>
                  <span className="tiny muted">{byId[id].group}</span>
                  <span style={{ flex: 1 }} />
                  <button type="button" className="btn ghost icon-btn" disabled={i === 0} onClick={() => move(i, -1)} aria-label={`Move ${byId[id].title} up`}><ArrowUp size={13} /></button>
                  <button type="button" className="btn ghost icon-btn" disabled={i === draft.order.length - 1} onClick={() => move(i, 1)} aria-label={`Move ${byId[id].title} down`}><ArrowDown size={13} /></button>
                </li>
              ))}
            </ol>
          </fieldset>
          <fieldset className="field" style={{ border: 'none', padding: 0, margin: 0 }}>
            <legend className="small strong" style={{ color: 'var(--ink-2)', marginBottom: 6 }}>Cover</legend>
            {COVER_FIELDS.map(([k, label, hint]) => (
              <Field key={k} label={label}>
                <input className="input" value={draft.cover[k]} placeholder={hint} maxLength={k === 'classification' ? 80 : 200}
                  onChange={(e) => edit({ cover: { ...draft.cover, [k]: e.target.value } })} />
              </Field>
            ))}
            <Field label="Scope" hint="What was asked and what was examined; shown under the case details.">
              <textarea className="textarea" rows={3} maxLength={4000} value={draft.cover.scope} onChange={(e) => edit({ cover: { ...draft.cover, scope: e.target.value } })} />
            </Field>
          </fieldset>
          <label className="check"><input type="checkbox" checked={draft.approved_findings_only} onChange={(e) => edit({ approved_findings_only: e.target.checked })} />
            Only findings approved in peer review</label>
          <label className="check"><input type="checkbox" checked={draft.include_screenshots} onChange={(e) => edit({ include_screenshots: e.target.checked })} />
            Pictures attached to findings</label>
          {canSave && (
            <div className="row" style={{ borderTop: '1px solid var(--border)', paddingTop: 12 }}>
              <input className="input sm" style={{ maxWidth: 220 }} value={name} onChange={(e) => setName(e.target.value)} placeholder="Template name" aria-label="Template name" maxLength={120} />
              {tpl && <Button size="sm" icon={<Save size={13} />} busy={busy === 'save'} disabled={!dirty && name === tpl.name} onClick={() => onSave(false)}>Save template</Button>}
              <Button size="sm" icon={<Save size={13} />} busy={busy === 'save'} disabled={name.trim().length < 2 || !chosen} onClick={() => onSave(true)}>Save as new template</Button>
              {tpl && <Button size="sm" variant="ghost" icon={<Trash2 size={13} />} busy={busy === 'delete'} onClick={onDelete}>Delete template</Button>}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function CaseExports({ caseId }: { caseId: string }) {
  const toast = useToast();
  const [tlp, setTlp] = useState<(typeof TLPS)[number]>('amber');
  const [busy, setBusy] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  const iocs = useApi<{ data: Indicator[] }>(`/exports/cases/${encodeURIComponent(caseId)}/iocs`);
  const items = iocs.data?.data || [];
  const malicious = items.filter((x) => x.verdict === 'malicious-activity').length;

  async function get(key: string, path: string) {
    setBusy(key);
    try {
      const r = await downloadExport(path);
      toast(`Exported${r.sha256 ? `; SHA-256 ${r.sha256.slice(0, 16)}…` : ''}`, 'ok');
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy(null);
    }
  }
  const base = `/exports/cases/${encodeURIComponent(caseId)}`;
  return (
    <Card title="Share the case" subtitle="For other tools: the case as CASE/UCO linked data, and its indicators of compromise as STIX 2.1 or a MISP event. Every export is audited.">
      <div className="row">
        <Button icon={<Share2 size={14} />} busy={busy === 'case'} onClick={() => get('case', `${base}/case-uco`)}>Case as CASE/UCO (JSON-LD)</Button>
      </div>
      <div className="row" style={{ marginTop: 12 }}>
        <label className="small strong" htmlFor="tlp">Sharing (TLP)</label>
        <select id="tlp" className="select sm" style={{ width: 110 }} value={tlp} onChange={(e) => setTlp(e.target.value as typeof tlp)}>
          {TLPS.map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}
        </select>
        <Button size="sm" busy={busy === 'stix'} disabled={!items.length} onClick={() => get('stix', `${base}/stix?tlp=${tlp}`)}>Indicators as STIX 2.1</Button>
        <Button size="sm" busy={busy === 'misp'} disabled={!items.length} onClick={() => get('misp', `${base}/misp?tlp=${tlp}`)}>Indicators as MISP event</Button>
      </div>
      <ErrorBanner error={iocs.error} />
      {iocs.loading && !iocs.data ? <Loading /> : !items.length ? (
        <p className="small muted" style={{ marginBottom: 0 }}>No indicators yet: they come from malware signatures, known-bad hash sets, VirusTotal, programs that stand out and uploads seen in network captures.</p>
      ) : (
        <>
          <p className="small" style={{ margin: '12px 0 6px' }}>{items.length} indicator{items.length === 1 ? '' : 's'}: {malicious} malicious, {items.length - malicious} anomalous.</p>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Indicator</th><th>Why</th></tr></thead>
              <tbody>
                {(all ? items : items.slice(0, 8)).map((x) => (
                  <tr key={`${x.kind}${x.value}`}>
                    <td className="small"><Badge tone={x.verdict === 'malicious-activity' ? 'danger' : 'warn'}>{x.kind}</Badge>{' '}
                      <span className="mono break">{x.name ? `${x.name} ` : ''}{x.kind === 'file' ? <Hash value={x.value} short={12} /> : x.value}</span></td>
                    <td className="small">{x.reasons.join('; ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {items.length > 8 && <Button size="sm" variant="ghost" onClick={() => setAll(!all)}>{all ? 'Show fewer' : `Show all ${items.length}`}</Button>}
        </>
      )}
    </Card>
  );
}

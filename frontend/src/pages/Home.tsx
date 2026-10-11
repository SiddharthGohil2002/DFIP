import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight, Check, FileText, FolderPlus, HardDrive, Play, Upload } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { formatBytes, humanize, useTime } from '../lib/format';
import { post } from '../lib/api';
import { IS_DESKTOP } from '../lib/platform';
import type { CaseCounts, Evidence, Job } from '../lib/types';
import { Badge, Banner, Button, Card, Empty, Loading, ProgressBar, StatusBadge, useToast } from '../ui';
import { NAV } from '../app/nav';
import { WorkstationCard } from '../app/Workstation';
import { CaseFormModal } from './Cases';
import { LegalHoldBadge, LegalHoldButton } from './LegalHold';

const RUNNING = new Set(['QUEUED', 'RUNNING']);

export function HomePage() {
  const { user, can } = useAuth();
  const { caseId, casesLoaded, overview, overviewError, reloadOverview, reloadCases, setCaseId } = useCase();
  const [creating, setCreating] = useState(false);
  const time = useTime();
  const navigate = useNavigate();

  if (!casesLoaded) return <Loading />;

  if (!caseId) {
    return (
      <div className="stack">
        <Card>
          <Empty
            icon={<FolderPlus size={20} />}
            title={`Welcome, ${user?.name}`}
            text="Investigations are organised in cases. Create a case, upload a disk image, run the analysis, then review deleted files, the timeline, browser history and USB activity, and generate the report."
            action={can('CASE_CREATE') ? <Button variant="primary" icon={<FolderPlus size={15} />} onClick={() => setCreating(true)}>Create a case</Button> : <p className="small">You are not assigned to any case yet.</p>}
          />
        </Card>
        {IS_DESKTOP && <WorkstationCard />}
        <CaseFormModal
          open={creating}
          onClose={() => setCreating(false)}
          onSaved={async (c) => {
            await reloadCases();
            setCaseId(c.case_id);
          }}
        />
      </div>
    );
  }

  if (!overview) return overviewError ? <Banner tone="danger">{overviewError}</Banner> : <Loading />;
  const { counts, evidence, jobs } = overview;
  const c = overview.case;
  const tiles = NAV.flatMap((g) => g.items).filter((i) => !i.noTile && (!i.permission || can(i.permission)));

  return (
    <div className="stack">
      <section className="card case-hero">
        <div style={{ minWidth: 0 }}>
          <div className="eyebrow">{c.case_id}{c.demo ? ' · demo data' : ''}</div>
          <h1 style={{ marginTop: 4 }}>{c.name}</h1>
          {c.description && <p className="muted" style={{ margin: '6px 0 0', maxWidth: 760 }}>{c.description}</p>}
          <div className="meta">
            <span>Status <StatusBadge status={c.status} /></span>
            <span>Priority <StatusBadge status={c.priority} /></span>
            <span>Opened {time(c.created_at)}</span>
            {c.legal_hold?.active && <span><LegalHoldBadge caseItem={c} /></span>}
          </div>
        </div>
        <div className="row" style={{ alignItems: 'flex-start' }}>
          <LegalHoldButton caseItem={c} />
          {can('EVIDENCE_UPLOAD') && <Button icon={<Upload size={15} />} onClick={() => navigate('/app/evidence')}>Add evidence</Button>}
          {can('REPORT_CREATE') && <Button variant="primary" icon={<FileText size={15} />} onClick={() => navigate('/app/reports')}>Generate report</Button>}
        </div>
      </section>

      <GettingStarted counts={counts} />

      <div className={IS_DESKTOP ? 'grid grid-side' : 'grid'}>
        <EvidenceCard evidence={evidence} jobs={jobs} onChange={reloadOverview} />
        {IS_DESKTOP && <WorkstationCard />}
      </div>

      <div>
        <h3 style={{ fontSize: 15, margin: '6px 0 12px' }}>Investigation functions</h3>
        <div className="tiles">
          {tiles.map((t) => {
            const Icon = t.icon;
            return (
              <Link key={t.to} to={t.to} className="tile">
                <div className="tile-top">
                  <div className={`tile-icon ${t.tone || ''}`}><Icon size={19} /></div>
                  {t.count && <div className="tile-value">{t.count(counts).toLocaleString()}</div>}
                </div>
                <div>
                  <h4>{t.label}</h4>
                  <p>{t.countLabel ? t.countLabel(counts) : t.description}</p>
                </div>
                {t.countLabel && <p>{t.description}</p>}
              </Link>
            );
          })}
        </div>
      </div>

      <Card title="Recent jobs" subtitle="Background analysis and verification for this case" flush>
        {!jobs.length ? (
          <Empty title="No jobs yet" text="Jobs appear here when you run an analysis or a hash verification." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Job</th><th>Type</th><th>Evidence</th><th>Status</th><th>Progress</th><th>Started</th></tr></thead>
              <tbody>
                {jobs.map((j) => (
                  <tr key={j.job_id}>
                    <td className="mono">{j.job_id}</td>
                    <td>{humanize(j.type)}</td>
                    <td className="mono">{j.payload?.evidence_id}</td>
                    <td><StatusBadge status={j.status} />{j.error && <div className="tiny" style={{ color: 'var(--danger)', marginTop: 4 }}>{j.error}</div>}</td>
                    <td style={{ minWidth: 180 }}>
                      <div className="row"><ProgressBar value={j.progress} /><span className="tiny muted">{j.progress ?? 0}%</span></div>
                      {RUNNING.has(j.status) && <div className="tiny muted">{j.stage}</div>}
                    </td>
                    <td className="nowrap small">{time(j.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function EvidenceCard({ evidence, jobs, onChange }: { evidence: Evidence[]; jobs: Job[]; onChange: () => void }) {
  const { can } = useAuth();
  const toast = useToast();
  const [busy, setBusy] = useState('');

  async function analyze(e: Evidence) {
    setBusy(e.evidence_id);
    try {
      const r = await post<{ job_id: string }>(`/jobs/analysis/${encodeURIComponent(e.evidence_id)}`);
      toast(`Analysis ${r.job_id} queued for ${e.evidence_id}`, 'ok');
      onChange();
    } catch (err: any) {
      toast(err.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  return (
    <Card title="Evidence" subtitle="Disk images in this case" actions={<Link to="/app/evidence" className="btn sm">Manage</Link>} flush>
      {!evidence.length ? (
        <Empty icon={<HardDrive size={20} />} title="No disk images" text="Upload an image on the Evidence page." />
      ) : (
        evidence.map((e) => {
          const job = jobs.find((j) => j.payload?.evidence_id === e.evidence_id && RUNNING.has(j.status));
          const s = e.analysis_summary;
          return (
            <div className="evidence-item" key={e.evidence_id}>
              <div className="evidence-icon"><HardDrive size={18} /></div>
              <div style={{ minWidth: 0 }}>
                <div className="row">
                  <Link to={`/app/evidence/${e.evidence_id}`} className="strong">{e.evidence_id}</Link>
                  <span className="muted small">{e.filename} · {e.format} · {formatBytes(e.size)}</span>
                </div>
                <div className="row" style={{ marginTop: 6 }}>
                  <StatusBadge status={e.verification_status} />
                  {job ? (
                    <div className="row grow" style={{ maxWidth: 360 }}>
                      <ProgressBar value={job.progress} />
                      <span className="tiny muted">{job.stage} · {job.progress ?? 0}%</span>
                    </div>
                  ) : e.analysis_status === 'COMPLETED' && s ? (
                    <span className="small muted">
                      Analyzed: {s.files ?? 0} files ({s.deleted_files ?? 0} deleted) · {s.timeline_events ?? 0} events · {(s.browser_history ?? 0) + (s.browser_downloads ?? 0)} browser · {s.usb_devices ?? 0} USB{s.programs_run !== undefined && ` · ${(s.programs_run ?? 0) + (s.recent_files ?? 0) + (s.recycle_bin_items ?? 0)} activity`}
                    </span>
                  ) : (
                    <Badge tone={e.analysis_status === 'FAILED' ? 'danger' : 'warn'}>{e.demo ? 'Demo record' : e.analysis_status === 'FAILED' ? 'Analysis failed' : 'Not analyzed'}</Badge>
                  )}
                </div>
              </div>
              <div className="row">
                {can('ANALYSIS_RUN') && !e.demo && (
                  <Button size="sm" variant={e.analysis_status === 'COMPLETED' ? 'default' : 'primary'} icon={<Play size={13} />} busy={busy === e.evidence_id} disabled={!!job} onClick={() => analyze(e)}>
                    {job ? 'Running' : e.analysis_status === 'COMPLETED' ? 'Re-run' : 'Analyze'}
                  </Button>
                )}
                <Link to={`/app/evidence/${e.evidence_id}`} className="btn sm">Open</Link>
              </div>
            </div>
          );
        })
      )}
    </Card>
  );
}

/** Four steps from an empty case to a report, ticked off from the case's own data; hidden when complete
 * or when the user's role can do none of the remaining steps (e.g. a viewer). */
function GettingStarted({ counts }: { counts: CaseCounts }) {
  const { can } = useAuth();
  const steps = [
    { label: 'Upload a disk image', hint: 'E01, RAW/DD or AFF; hashed and sealed read-only', done: counts.evidence > 0, to: '/app/evidence', action: 'Upload', permission: 'EVIDENCE_UPLOAD' },
    { label: 'Run the full analysis', hint: 'Files, timeline, browser history, USB devices', done: counts.evidence_analyzed > 0, to: '/app/evidence', action: 'Analyze', permission: 'ANALYSIS_RUN' },
    { label: 'Review and record findings', hint: 'Deleted files, timeline, indicators', done: counts.findings > 0, to: '/app/findings', action: 'Add finding', permission: 'FINDING_CREATE' },
    { label: 'Generate the report', hint: 'Hash-sealed PDF for the case file', done: counts.reports > 0, to: '/app/reports', action: 'Generate', permission: 'REPORT_CREATE' },
  ];
  const done = steps.filter((s) => s.done).length;
  if (done === steps.length || !steps.some((s) => !s.done && can(s.permission))) return null;
  const next = steps.findIndex((s) => !s.done);
  return (
    <section className="card getting-started">
      <div className="row between">
        <div>
          <h3 style={{ fontSize: 15 }}>Getting started</h3>
          <div className="small muted">{done} of {steps.length} steps done</div>
        </div>
        <div style={{ width: 220 }}><ProgressBar value={(done / steps.length) * 100} /></div>
      </div>
      <ol className="steps-list">
        {steps.map((s, i) => (
          <li key={s.label} className={s.done ? 'done' : i === next ? 'current' : ''}>
            <span className="step-mark" aria-hidden="true">{s.done ? <Check size={14} /> : i + 1}</span>
            <div className="grow">
              <div className="strong small">{s.label}</div>
              <div className="tiny muted">{s.hint}</div>
            </div>
            {i === next && can(s.permission) && <Link className="btn sm primary" to={s.to}>{s.action} <ArrowRight size={13} /></Link>}
          </li>
        ))}
      </ol>
    </section>
  );
}

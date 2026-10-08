import { useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, CheckCircle2, HardDriveDownload, Play, ShieldCheck, XCircle } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { post } from '../lib/api';
import { formatBytes, formatNumber, useTime } from '../lib/format';
import { IS_DESKTOP, hasNativeRuntime, native, type LocalHash } from '../lib/platform';
import { useApi } from '../lib/useApi';
import type { Evidence, Job } from '../lib/types';
import { Banner, Button, Card, Empty, ErrorBanner, Field, Hash, Loading, PageHeader, ProgressBar, Stat, StatusBadge, useToast } from '../ui';

const RUNNING = new Set(['QUEUED', 'RUNNING']);

export function EvidenceDetailPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const { reloadOverview } = useCase();
  const toast = useToast();
  const time = useTime();
  const ev = useApi<Evidence>(`/evidence/${encodeURIComponent(id)}`);
  const e = ev.data;
  const jobPath = e?.last_analysis_job ? `/jobs/${encodeURIComponent(e.last_analysis_job)}` : null;
  const [queued, setQueued] = useState<string | null>(null);
  const [polling, setPolling] = useState(true);
  const job = useApi<Job>(queued ? `/jobs/${queued}` : jobPath, { pollMs: polling ? 1500 : undefined });
  const custody = useApi<{ data: any[] }>(e ? `/chain?evidence_id=${encodeURIComponent(e.evidence_id)}` : null);
  const [busy, setBusy] = useState('');

  const j = job.data;
  const running = !!j && RUNNING.has(j.status);
  const prevStatus = useRef<string | undefined>(undefined);
  useEffect(() => {
    const status = j?.status;
    setPolling(!status || RUNNING.has(status));
    // When a job leaves the running state, refresh the evidence record (summary, status) and custody once.
    if (prevStatus.current && RUNNING.has(prevStatus.current) && status && !RUNNING.has(status)) {
      ev.reload();
      custody.reload();
      reloadOverview();
    }
    prevStatus.current = status;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [j?.status, j?.job_id]);

  if (ev.loading && !e) return <Loading />;
  if (ev.error || !e) return <ErrorBanner error={ev.error || 'Evidence not found'} />;

  async function verify() {
    setBusy('verify');
    try {
      const r = await post<{ verification_status: string }>(`/evidence/${encodeURIComponent(e!.evidence_id)}/verify`);
      toast(r.verification_status === 'VERIFIED' ? 'SHA-256 matches the acquisition hash' : 'INTEGRITY FAILED: the stored image no longer matches', r.verification_status === 'VERIFIED' ? 'ok' : 'danger');
      ev.reload();
      custody.reload();
    } catch (err: any) {
      toast(err.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  async function analyze() {
    setBusy('analyze');
    try {
      const r = await post<{ job_id: string }>(`/jobs/analysis/${encodeURIComponent(e!.evidence_id)}`);
      setQueued(r.job_id);
      setPolling(true);
      toast(`Analysis ${r.job_id} queued`, 'ok');
      reloadOverview();
    } catch (err: any) {
      toast(err.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  const summary = j?.status === 'COMPLETED' ? j.result?.summary : null;
  const counts = e.analysis_summary;

  return (
    <div className="stack">
      <Link to="/app/evidence" className="small row"><ArrowLeft size={14} /> Evidence register</Link>
      <PageHeader
        eyebrow={e.case_id}
        title={`${e.evidence_id} · ${e.filename}`}
        subtitle={`${e.format} image · ${formatBytes(e.size)} · acquired ${time(e.created_at)}`}
        actions={
          !e.demo && (
            <>
              {can('EVIDENCE_VERIFY') && <Button icon={<ShieldCheck size={15} />} busy={busy === 'verify'} onClick={verify}>Verify integrity</Button>}
              {can('ANALYSIS_RUN') && (
                <Button variant="primary" icon={<Play size={15} />} busy={busy === 'analyze'} disabled={running} onClick={analyze}>
                  {running ? 'Analysis running' : e.analysis_status === 'COMPLETED' ? 'Re-run analysis' : 'Run full analysis'}
                </Button>
              )}
            </>
          )
        }
      />
      {e.demo && <Banner tone="warn">This is a synthetic demo record, not a real disk image; it cannot be verified or analyzed.</Banner>}

      <div className="grid cols-2">
        <Card title="Evidence manifest">
          <dl className="kv">
            <dt>Evidence ID</dt><dd className="mono">{e.evidence_id}</dd>
            <dt>Case</dt><dd className="mono">{e.case_id}</dd>
            <dt>File name</dt><dd>{e.filename}</dd>
            <dt>Format / size</dt><dd>{e.format} · {formatNumber(e.size)} bytes</dd>
            <dt>SHA-256</dt><dd><Hash value={e.sha256} /></dd>
            <dt>SHA-512</dt><dd><Hash value={e.sha512} /></dd>
            <dt>Integrity</dt><dd><StatusBadge status={e.verification_status} /> <span className="small muted">last checked {time(e.verified_at)}</span></dd>
            <dt>Storage</dt><dd className="small">Original sealed read-only on the server; analysis reads it, never writes.</dd>
          </dl>
        </Card>
        <Card title="Chain of custody" subtitle="For this evidence item" flush>
          {!custody.data?.data.length ? (
            <Empty title="No custody records" />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Time</th><th>Action</th><th>By</th><th>Result</th></tr></thead>
                <tbody>
                  {custody.data.data.map((c) => (
                    <tr key={c._id}>
                      <td className="small nowrap">{time(c.timestamp)}</td>
                      <td className="small strong">{c.action}</td>
                      <td className="small">{c.user_name || c.user_id}</td>
                      <td className="small">{c.status || c.result || ''}{c.original_path && <div className="muted break">{c.original_path}</div>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {IS_DESKTOP && <LocalVerifyCard expected={e.sha256} />}

      <Card title="Disk image analysis" subtitle="Sleuth Kit partition and filesystem examination, MACB timeline, browser and USB artifact extraction, YARA scan.">
        {!j && !e.analysis_status && <Empty title="Not analyzed yet" text={e.demo ? undefined : 'Run the full analysis to index files, build the timeline and extract browser and USB artifacts.'} />}
        {j && (
          <div className="stack" style={{ gap: 14 }}>
            <div className="row">
              <span className="mono strong">{j.job_id}</span>
              <StatusBadge status={j.status} />
              <ProgressBar value={j.progress} />
              <span className="small muted nowrap">{j.stage} · {j.progress ?? 0}%</span>
            </div>
            {j.status === 'FAILED' && <Banner tone="danger">{j.error}</Banner>}
            {j.status === 'COMPLETED' && counts && (
              <>
                <div className="grid cols-4">
                  <Stat label="Files indexed" value={formatNumber(counts.files)} hint={`${formatNumber(counts.deleted_files)} deleted`} />
                  <Stat label="Timeline events" value={formatNumber(counts.timeline_events)} hint={`analyzed ${time(e.analyzed_at)}`} />
                  <Stat label="Browser records" value={formatNumber((counts.browser_history ?? 0) + (counts.browser_downloads ?? 0))} hint={`${formatNumber(counts.browser_downloads)} downloads`} />
                  <Stat label="USB devices" value={formatNumber(counts.usb_devices)} hint={`${formatNumber(counts.yara_matches)} YARA matches`} />
                </div>
                <div className="row">
                  <Link className="btn sm" to={`/app/files?evidence=${e.evidence_id}`}>Deleted files</Link>
                  <Link className="btn sm" to="/app/timeline">Timeline</Link>
                  <Link className="btn sm" to="/app/browser">Browser history</Link>
                  <Link className="btn sm" to="/app/usb">USB devices</Link>
                  <Link className="btn sm" to="/app/indicators">Indicators</Link>
                </div>
              </>
            )}
            {summary && <AnalysisDetails summary={summary} />}
          </div>
        )}
      </Card>
    </div>
  );
}

function AnalysisDetails({ summary }: { summary: any }) {
  const partitions: any[] = summary.partitions || [];
  const filesystems: any[] = summary.filesystems || [];
  return (
    <div className="grid cols-2">
      <div>
        <h4 style={{ fontSize: 13.5, marginBottom: 8 }}>Partition table (mmls)</h4>
        {!partitions.length ? (
          <p className="small muted">No partition table: the image was examined as a single filesystem.</p>
        ) : (
          <table className="table">
            <thead><tr><th>Slot</th><th>Start</th><th>Length</th><th>Description</th></tr></thead>
            <tbody>
              {partitions.map((p) => (
                <tr key={`${p.index}-${p.start}`}>
                  <td className="mono small">{p.slot}</td>
                  <td className="mono small">{p.start}</td>
                  <td className="mono small">{p.length}</td>
                  <td className="small">{p.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div>
        <h4 style={{ fontSize: 13.5, marginBottom: 8 }}>Filesystems examined</h4>
        <table className="table">
          <thead><tr><th>Sector offset</th><th>Type</th><th>Entries</th><th>Deleted</th></tr></thead>
          <tbody>
            {filesystems.map((f) => (
              <tr key={f.partition_offset}>
                <td className="mono small">{f.partition_offset}</td>
                <td className="small">{f.filesystem_type || <span className="muted">unreadable</span>}</td>
                <td className="small">{formatNumber(f.files)}</td>
                <td className="small">{formatNumber(f.deleted_files)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {summary.integrity && (
          <p className="small" style={{ marginTop: 10 }}>
            {summary.integrity.verified ? <CheckCircle2 size={14} color="var(--ok)" /> : <XCircle size={14} color="var(--danger)" />} Pre-analysis integrity check: SHA-256 {summary.integrity.verified ? 'matched' : 'did NOT match'} the acquisition hash.
          </p>
        )}
        {summary.warnings?.length > 0 && (
          <Banner tone="warn"><div>{summary.warnings.map((w: string) => <div key={w}>{w}</div>)}</div></Banner>
        )}
      </div>
    </div>
  );
}

/** Desktop only: hash a local copy of the image on this workstation and compare with the acquisition hash. */
function LocalVerifyCard({ expected }: { expected: string }) {
  const [path, setPath] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LocalHash | null>(null);
  const [error, setError] = useState('');
  const nativeOk = hasNativeRuntime();

  async function run() {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      setResult(await native.hashFile(path.trim()));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const match = result && result.sha256.toLowerCase() === expected.toLowerCase();
  return (
    <Card title={<span className="row"><HardDriveDownload size={16} /> Verify a local copy</span>} subtitle="Desktop app: hashes a file on this workstation (nothing is uploaded) and compares it with the acquisition SHA-256.">
      {!nativeOk ? (
        <p className="small muted" style={{ margin: 0 }}>Available in the installed DFIP desktop app.</p>
      ) : (
        <div className="stack" style={{ gap: 10 }}>
          <div className="row">
            <div className="grow">
              <Field label="Full path of the local image or source media file">
                <input className="input" value={path} onChange={(e) => setPath(e.target.value)} placeholder="D:\\evidence\\laptop.E01" />
              </Field>
            </div>
            <Button style={{ alignSelf: 'flex-end' }} busy={busy} disabled={!path.trim()} onClick={run}>Hash and compare</Button>
          </div>
          {error && <Banner tone="danger">{error}</Banner>}
          {result && (
            <Banner tone={match ? 'ok' : 'danger'}>
              {match ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
              <div>
                <div className="strong">{match ? 'Match: the local file is identical to the registered evidence.' : 'MISMATCH: the local file differs from the registered evidence.'}</div>
                <div className="small">Local SHA-256 <Hash value={result.sha256} /> · {formatNumber(result.bytes)} bytes in {(result.elapsed_ms / 1000).toFixed(1)} s</div>
              </div>
            </Banner>
          )}
        </div>
      )}
    </Card>
  );
}

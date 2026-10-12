import { useRef, useState, type DragEvent } from 'react';
import { Link } from 'react-router-dom';
import { CheckCircle2, Copy, Play, ShieldCheck, Trash2, UploadCloud } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { post, uploadEvidence } from '../lib/api';
import { formatBytes, useTime } from '../lib/format';
import type { Evidence } from '../lib/types';
import { Badge, Banner, Button, Card, Empty, Hash, PageHeader, ProgressBar, StatusBadge, useToast } from '../ui';
import { DeleteEvidenceModal } from './DeleteEvidence';

const SUPPORTED = ['E01', 'EX01', 'RAW', 'DD', 'IMG', 'AFF', 'AFF4', 'VHD', 'VHDX', 'VMDK', 'QCOW2', 'QCOW'];
/** A disk image file name: a known extension, an EnCase segment (.E02, .EAA, .Ex02) or a numbered part (.001). */
const supportedName = (name: string) => {
  const ext = name.split('.').pop()?.toUpperCase() || '';
  return SUPPORTED.includes(ext) || /^\d{3,4}$/.test(ext) || /^E(X?\d\d|[A-Z]{2})$/.test(ext);
};

export function EvidencePage() {
  const { can } = useAuth();
  const { overview, activeCase, reloadOverview } = useCase();
  const held = !!(overview?.case.legal_hold?.active || activeCase?.legal_hold?.active);
  const toast = useToast();
  const time = useTime();
  const [busy, setBusy] = useState('');
  const [deleting, setDeleting] = useState<Evidence | null>(null);
  const evidence = overview?.evidence || [];
  const running = new Set((overview?.jobs || []).filter((j) => ['QUEUED', 'RUNNING'].includes(j.status)).map((j) => j.payload?.evidence_id));

  async function run(e: Evidence, kind: 'analysis' | 'verify') {
    setBusy(`${kind}:${e.evidence_id}`);
    try {
      if (kind === 'verify') {
        const r = await post<{ verification_status: string }>(`/evidence/${encodeURIComponent(e.evidence_id)}/verify`);
        toast(`${e.evidence_id}: ${r.verification_status === 'VERIFIED' ? 'SHA-256 matches the acquisition hash' : 'INTEGRITY FAILED'}`, r.verification_status === 'VERIFIED' ? 'ok' : 'danger');
      } else {
        const r = await post<{ job_id: string }>(`/jobs/analysis/${encodeURIComponent(e.evidence_id)}`);
        toast(`Analysis ${r.job_id} queued for ${e.evidence_id}`, 'ok');
      }
      reloadOverview();
    } catch (err: any) {
      toast(err.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Evidence"
        subtitle={`Disk images for ${activeCase?.case_id || 'this case'}. Each upload is hashed (SHA-256 and SHA-512) on the server, stored read-only, and logged to the chain of custody.`}
      />
      {can('EVIDENCE_UPLOAD') && <UploadCard evidence={evidence} onUploaded={reloadOverview} />}

      <Card title="Evidence register" subtitle="Integrity is re-verified automatically before every analysis run." flush>
        {!evidence.length ? (
          <Empty title="No evidence in this case" text="Upload a disk image above." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Evidence</th><th>Image</th><th>Acquisition SHA-256</th><th>Integrity</th><th>Analysis</th><th>Acquired</th><th /></tr></thead>
              <tbody>
                {evidence.map((e) => (
                  <tr key={e.evidence_id}>
                    <td><Link to={`/app/evidence/${e.evidence_id}`} className="mono strong">{e.evidence_id}</Link></td>
                    <td><div className="strong">{e.filename}</div><div className="small muted">{e.format} · {formatBytes(e.size)}</div></td>
                    <td><Hash value={e.sha256} short={20} /></td>
                    <td><StatusBadge status={e.verification_status} /></td>
                    <td>{running.has(e.evidence_id) ? <StatusBadge status="RUNNING" /> : e.demo ? <Badge>Demo record</Badge> : <StatusBadge status={e.analysis_status || 'NOT_RUN'} label={e.analysis_status ? undefined : 'NOT RUN'} />}</td>
                    <td className="small nowrap">{time(e.created_at)}</td>
                    <td className="nowrap right">
                      {!e.demo && can('EVIDENCE_VERIFY') && (
                        <Button size="sm" icon={<ShieldCheck size={13} />} busy={busy === `verify:${e.evidence_id}`} onClick={() => run(e, 'verify')}>Verify</Button>
                      )}{' '}
                      {!e.demo && can('ANALYSIS_RUN') && (
                        <Button size="sm" variant="primary" icon={<Play size={13} />} disabled={running.has(e.evidence_id)} busy={busy === `analysis:${e.evidence_id}`} onClick={() => run(e, 'analysis')}>
                          {e.analysis_status === 'COMPLETED' ? 'Re-run' : 'Analyze'}
                        </Button>
                      )}{' '}
                      <Link to={`/app/evidence/${e.evidence_id}`} className="btn sm">Details</Link>
                      {can('EVIDENCE_DELETE') && (
                        <>
                          {' '}
                          <Button size="sm" variant="danger" icon={<Trash2 size={13} />} disabled={running.has(e.evidence_id) || held}
                            title={held ? 'The case is under legal hold: evidence cannot be deleted' : running.has(e.evidence_id) ? 'An analysis is running for this evidence' : `Delete ${e.evidence_id}`}
                            onClick={() => setDeleting(e)}>
                            Delete
                          </Button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <DeleteEvidenceModal evidence={deleting} onClose={() => setDeleting(null)} onDeleted={() => { setDeleting(null); reloadOverview(); }} />
    </div>
  );
}

function UploadCard({ evidence, onUploaded }: { evidence: Evidence[]; onUploaded: () => void }) {
  const { caseId } = useCase();
  const toast = useToast();
  const input = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [over, setOver] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [result, setResult] = useState<Evidence | null>(null);
  const [error, setError] = useState('');
  const [analyzing, setAnalyzing] = useState(false);

  const file = files.length === 1 ? files[0] : null;
  const ext = file?.name.split('.').pop()?.toUpperCase() || '';
  const unsupported = files.filter((f) => !supportedName(f.name));
  const supported = !unsupported.length;
  const total = files.reduce((n, f) => n + f.size, 0);
  // Early hint only: the server compares SHA-256 and refuses an image already registered in the case.
  const lookalike = file && evidence.find((e) => e.filename === file.name && e.size === file.size);

  function choose(list: FileList | null) {
    setFiles(list ? Array.from(list).sort((a, b) => a.name.localeCompare(b.name)) : []);
    setResult(null);
    setError('');
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setOver(false);
    choose(e.dataTransfer.files);
  }

  async function upload() {
    if (!files.length) return;
    setError('');
    setProgress(0);
    try {
      const ev = await uploadEvidence(caseId, files, setProgress);
      setResult(ev);
      setFiles([]);
      toast(`${ev.evidence_id} registered and sealed read-only`, 'ok');
      onUploaded();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setProgress(null);
    }
  }

  async function analyze() {
    if (!result) return;
    setAnalyzing(true);
    try {
      const r = await post<{ job_id: string }>(`/jobs/analysis/${encodeURIComponent(result.evidence_id)}`);
      toast(`Analysis ${r.job_id} queued`, 'ok');
      setResult(null);
      onUploaded();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setAnalyzing(false);
    }
  }

  return (
    <Card title="Add a disk image" subtitle="E01 (with all its segments), raw/dd (also split into numbered parts .001, .002 ...), VHD, VHDX, VMDK, QCOW2 (with their parent disks) and AFF. Choose every file of one image together; large images upload directly to the server's evidence store.">
      <div className="stack" style={{ gap: 12 }}>
        <div
          className={`dropzone ${over ? 'over' : ''}`}
          onClick={() => input.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setOver(true); }}
          onDragLeave={() => setOver(false)}
          onDrop={onDrop}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && input.current?.click()}
        >
          <UploadCloud size={28} color="var(--accent)" />
          <div className="strong" style={{ marginTop: 8 }}>{file ? file.name : files.length ? `${files.length} files of one image` : 'Drop a disk image here or click to choose'}</div>
          <div className="small muted">{file ? `${formatBytes(file.size)} · ${ext}` : files.length ? `${formatBytes(total)} · ${files.map((f) => f.name).slice(0, 6).join(', ')}${files.length > 6 ? ' …' : ''}`
            : 'The original files on your computer are never modified.'}</div>
          <input ref={input} type="file" multiple hidden aria-label="Disk image files" onChange={(e) => choose(e.target.files)} />
        </div>
        {!supported && <Banner tone="warn">{unsupported.map((f) => f.name).join(', ')}: not a supported forensic image format.</Banner>}
        {lookalike && (
          <Banner tone="warn">
            <Copy size={16} style={{ flex: 'none' }} />
            <div>This file has the same name and size as <span className="mono strong">{lookalike.evidence_id}</span>, already in this case. An image is registered only once per case: if the contents are identical, the server will refuse the upload.</div>
          </Banner>
        )}
        {progress !== null && (
          <div className="row">
            <ProgressBar value={progress * 100} />
            <span className="small muted nowrap">{progress < 1 ? `Uploading ${Math.round(progress * 100)}%` : 'Hashing on server…'}</span>
          </div>
        )}
        {error && <Banner tone="danger">{error}</Banner>}
        {result && (
          <Banner tone="ok">
            <CheckCircle2 size={18} style={{ flex: 'none' }} />
            <div className="grow">
              <div className="strong">{result.evidence_id} registered · {result.filename}</div>
              <div className="small">SHA-256 <Hash value={result.sha256} /></div>
              <div className="small">SHA-512 <Hash value={result.sha512} short={32} /></div>
            </div>
            <Button size="sm" variant="primary" icon={<Play size={13} />} busy={analyzing} onClick={analyze}>Run analysis</Button>
          </Banner>
        )}
        <div className="row">
          <Button variant="primary" icon={<UploadCloud size={15} />} disabled={!files.length || !supported || progress !== null} busy={progress !== null} onClick={upload}>
            Upload and seal
          </Button>
          {files.length > 0 && progress === null && <Button variant="ghost" onClick={() => choose(null)}>Clear</Button>}
        </div>
      </div>
    </Card>
  );
}

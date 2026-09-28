import React, { useState } from 'react';
import * as I from 'lucide-react';
import { api } from '../services/api';

interface Props {
  operation: string;
  description?: string;
  jobType?: string;
  jobPayload?: any;
  onCancel?: () => void;
  onJobCreated?: (jobId: string) => void;
}

export default function DesktopRequired({ operation, description, jobType, jobPayload, onCancel, onJobCreated }: Props) {
  const [submitting, setSubmitting] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState('');

  async function requestDesktopJob() {
    if (!jobType) return;
    setSubmitting(true);
    setError('');
    try {
      const res = await api<{ job_id: string; status: string }>('/desktop/jobs/create', {
        method: 'POST',
        body: JSON.stringify({ job_type: jobType, payload: jobPayload || {} }),
      });
      setJobId(res.job_id);
      if (onJobCreated) onJobCreated(res.job_id);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSubmitting(false);
    }
  }

  if (jobId) {
    return (
      <div className="card" style={{ padding: 24, textAlign: 'center' }}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 12 }}>
          <div style={{ width: 44, height: 44, borderRadius: 999, background: 'var(--bg-subtle)', display: 'grid', placeItems: 'center', color: 'var(--green)' }}>
            <I.CheckCircle size={22} />
          </div>
        </div>
        <div style={{ fontWeight: 700, marginBottom: 6 }}>Job Queued for Desktop</div>
        <div className="muted" style={{ fontSize: 13 }}>Job <span className="mono" style={{ fontWeight: 600 }}>{jobId}</span> is pending. Your DFIP Desktop will pick it up automatically.</div>
        <div style={{ marginTop: 16 }}>
          <span className="badge warn" style={{ fontSize: 11 }}>PENDING DESKTOP</span>
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ padding: 28, textAlign: 'center', border: '1.5px dashed var(--border)' }}>
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 14 }}>
        <div style={{ width: 52, height: 52, borderRadius: 999, background: 'var(--bg-subtle)', display: 'grid', placeItems: 'center', color: 'var(--ink-light)' }}>
          <I.Monitor size={26} />
        </div>
      </div>
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 8 }}>Desktop Required</div>
      <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 8 }}>{operation}</div>
      {description && <div className="muted" style={{ fontSize: 13.5, marginBottom: 16, maxWidth: 380, margin: '0 auto 16px' }}>{description}</div>}
      <div className="muted" style={{ fontSize: 12.5, marginBottom: 20 }}>
        This operation requires direct access to the investigator's local forensic workstation.<br />
        Open DFIP Desktop on the workstation where the evidence is located.
      </div>
      {error && <div className="badge danger" style={{ marginBottom: 12, display: 'block' }}>{error}</div>}
      <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
        {jobType && (
          <button className="btn primary" onClick={requestDesktopJob} disabled={submitting}>
            <I.Send size={14} />{submitting ? 'Queuing...' : 'Queue for Desktop'}
          </button>
        )}
        <a
          href="/downloads/DFIP-Investigator-Windows-x64.exe"
          download="DFIP-Investigator-Windows-x64.exe"
          className="btn primary"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
          title="Direct download DFIP Investigator Windows Installer (v2.0.0)"
        >
          <I.Download size={14} /> Download Desktop Client (.exe)
        </a>
        <a
          href="/download"
          className="btn"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
        >
          <I.Info size={14} /> Setup & SHA-256 Info
        </a>
        {onCancel && (
          <button className="btn ghost" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}

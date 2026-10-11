import { useMemo, useState } from 'react';
import { Clock3 } from 'lucide-react';
import { api } from '../lib/api';
import type { Evidence, EvidenceTimeZone } from '../lib/types';
import { Banner, Button, Field, Modal, useToast } from '../ui';

/** "America/New_York (Eastern Standard Time, from the SYSTEM hive)" and similar. */
export function describeTimeZone(tz?: EvidenceTimeZone | null): string {
  if (!tz) return 'Not analysed yet';
  if (tz.source === 'override') return `${tz.zone} (set by ${tz.override?.set_by_name || 'an investigator'}: ${tz.override?.reason})`;
  if (tz.source === 'registry') return `${tz.zone} (${tz.detected?.key_name || 'Windows time zone'}, from the SYSTEM hive)`;
  return `${tz.zone} (no time zone found in the evidence)`;
}

const COMMON = ['UTC', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London', 'Europe/Berlin',
  'Asia/Kolkata', 'Asia/Dubai', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney'];

/** Which time zone local times (FAT file times, setupapi.dev.log) were read in, with a way to change it. */
export function TimeZoneBanner({ evidence, canEdit, running, onQueued }: {
  evidence: Evidence;
  canEdit: boolean;
  running: boolean;
  onQueued: (jobId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const tz = evidence.time_zone;
  if (!tz) return null;
  return (
    <>
      <Banner tone={tz.source === 'default' ? 'warn' : 'info'}>
        <div className="row" style={{ justifyContent: 'space-between', width: '100%' }}>
          <span>
            <Clock3 size={14} style={{ verticalAlign: -2, marginRight: 6 }} />
            <span className="strong">Computer time zone:</span> {describeTimeZone(tz)}.{' '}
            {tz.source === 'default'
              ? 'File systems that store local time (FAT) are shown as recorded. Set the time zone if you know it.'
              : 'FAT file times and setupapi.dev.log, which Windows stores in local time, are converted to UTC with it.'}
          </span>
          {canEdit && <Button size="sm" disabled={running} onClick={() => setOpen(true)}>Change time zone</Button>}
        </div>
      </Banner>
      <TimeZoneModal evidence={evidence} open={open} onClose={() => setOpen(false)} onQueued={onQueued} />
    </>
  );
}

function TimeZoneModal({ evidence, open, onClose, onQueued }: { evidence: Evidence; open: boolean; onClose: () => void; onQueued: (jobId: string) => void }) {
  const toast = useToast();
  const tz = evidence.time_zone;
  const [mode, setMode] = useState<'set' | 'registry'>('set');
  const [zone, setZone] = useState(tz?.source === 'override' ? tz.zone : 'UTC');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const zones = useMemo<string[]>(() => {
    const all = (Intl as any).supportedValuesOf?.('timeZone') as string[] | undefined;
    return all?.length ? ['UTC', ...all.filter((z) => z !== 'UTC')] : COMMON;
  }, []);

  async function save() {
    setBusy(true);
    setError('');
    try {
      const r = await api<{ job_id: string }>(`/evidence/${encodeURIComponent(evidence.evidence_id)}/time-zone`, {
        method: 'PUT', json: { zone: mode === 'registry' ? null : zone.trim(), reason: reason.trim() },
      });
      toast(`Re-indexing with the new time zone (${r.job_id})`, 'ok');
      onQueued(r.job_id);
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} title="Computer time zone" onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="primary" busy={busy} disabled={reason.trim().length < 5 || (mode === 'set' && !zone.trim())} onClick={save}>Save and re-index</Button>
        </>
      }>
      <div className="stack" style={{ gap: 12 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Windows stores FAT file times and setupapi.dev.log in the computer's local time. The file system index and
          what is built on it are re-run with the zone you choose; the change and your reason go to the audit log.
          {tz?.detected?.zone && <> The SYSTEM hive says <span className="strong">{tz.detected.key_name}</span> ({tz.detected.zone}).</>}
        </p>
        <label className="check">
          <input type="radio" name="tzmode" checked={mode === 'set'} onChange={() => setMode('set')} />
          <span className="strong">Use this time zone</span>
        </label>
        {mode === 'set' && (
          <Field label="Time zone (IANA name)" hint="For example America/New_York, Europe/London or Asia/Kolkata; UTC reads the times as recorded.">
            <input className="input" list="tz-names" value={zone} onChange={(e) => setZone(e.target.value)} aria-label="Time zone" />
            <datalist id="tz-names">{zones.map((z) => <option key={z} value={z} />)}</datalist>
          </Field>
        )}
        <label className="check">
          <input type="radio" name="tzmode" checked={mode === 'registry'} onChange={() => setMode('registry')} disabled={tz?.source !== 'override'} />
          <span className="strong">Use the time zone in the SYSTEM hive</span>
          {tz?.source !== 'override' && <span className="small muted">(already in use)</span>}
        </label>
        <Field label="Reason" hint="Why the time zone is being changed; recorded in the audit log.">
          <textarea className="input" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Reason" />
        </Field>
        {error && <Banner tone="danger">{error}</Banner>}
      </div>
    </Modal>
  );
}

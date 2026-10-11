import { useState } from 'react';
import { Trash2 } from 'lucide-react';
import { del } from '../lib/api';
import { formatBytes } from '../lib/format';
import type { Evidence } from '../lib/types';
import { Banner, Button, Field, Hash, Modal, useToast } from '../ui';

const MIN_REASON = 5;

export interface DeleteResult {
  evidence_id: string;
  findings_unlinked: number;
  warnings: string[];
}

/** Confirms and performs the deletion of one evidence item. The reason goes to the chain of custody and audit log. */
export function DeleteEvidenceModal({ evidence, onClose, onDeleted }: {
  evidence: Evidence | null;
  onClose: () => void;
  onDeleted: (r: DeleteResult) => void;
}) {
  const toast = useToast();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  function close() {
    if (busy) return;
    setReason('');
    setError('');
    onClose();
  }

  async function confirm() {
    if (!evidence) return;
    setBusy(true);
    setError('');
    try {
      const r = await del<DeleteResult>(`/evidence/${encodeURIComponent(evidence.evidence_id)}`, { reason: reason.trim() });
      const linked = r.findings_unlinked ? `; ${r.findings_unlinked} finding${r.findings_unlinked === 1 ? '' : 's'} no longer link to it` : '';
      if (r.warnings?.length) toast(`${r.evidence_id} deleted, but some stored files could not be removed: ${r.warnings.join('; ')}`, 'danger');
      else toast(`${r.evidence_id} deleted${linked}`, 'ok');
      setReason('');
      onDeleted(r);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const ok = reason.trim().length >= MIN_REASON;
  return (
    <Modal
      open={!!evidence}
      title={`Delete ${evidence?.evidence_id || 'evidence'}`}
      onClose={close}
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={busy}>Cancel</Button>
          <Button variant="danger" icon={<Trash2 size={15} />} busy={busy} disabled={!ok} onClick={confirm}>
            Delete {evidence?.evidence_id}
          </Button>
        </>
      }
    >
      {evidence && (
        <div className="stack" style={{ gap: 12 }}>
          <Banner tone="danger">This permanently deletes the disk image and everything DFIP extracted from it. It cannot be undone.</Banner>
          <dl className="kv" style={{ gridTemplateColumns: '110px 1fr' }}>
            <dt>Evidence</dt><dd><span className="mono strong">{evidence.evidence_id}</span> · {evidence.filename}</dd>
            <dt>Size</dt><dd>{evidence.format} · {formatBytes(evidence.size)}</dd>
            <dt>SHA-256</dt><dd><Hash value={evidence.sha256} /></dd>
          </dl>
          <div className="small">
            <p style={{ margin: '0 0 6px' }}><span className="strong">Removed:</span> the stored image and its E01 working copy, recovered and carved files, the file index, timeline events, browser, USB and Windows activity records, YARA results, analysis jobs and tags on its items.</p>
            <p style={{ margin: 0 }}><span className="strong">Kept:</span> the chain of custody and the audit log (a deletion record with your reason is added), findings (their link to this evidence is removed) and reports already generated.</p>
          </div>
          <Field label="Reason for deletion" hint="Recorded in the chain of custody and the audit log.">
            <textarea className="textarea" value={reason} maxLength={500} autoFocus onChange={(e) => setReason(e.target.value)}
              placeholder="For example: duplicate upload of the wrong image" />
          </Field>
          {error && <Banner tone="danger">{error}</Banner>}
        </div>
      )}
    </Modal>
  );
}

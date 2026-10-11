import { useState } from 'react';
import { Lock, LockOpen } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { post } from '../lib/api';
import { useTime } from '../lib/format';
import type { CaseItem } from '../lib/types';
import { Badge, Banner, Button, Field, Modal, useToast } from '../ui';

/** "Legal hold" badge, with who placed it, when and why in the tooltip. */
export function LegalHoldBadge({ caseItem }: { caseItem?: CaseItem | null }) {
  const time = useTime();
  const hold = caseItem?.legal_hold;
  if (!hold?.active) return null;
  return (
    <span title={`Legal hold since ${time(hold.set_at)} by ${hold.set_by_name}: ${hold.reason}`}>
      <Badge tone="danger"><Lock size={11} style={{ marginRight: 4, verticalAlign: -1 }} />Legal hold</Badge>
    </span>
  );
}

/** Places or releases the legal hold on a case; a reason is required either way. */
export function LegalHoldButton({ caseItem }: { caseItem: CaseItem }) {
  const { can } = useAuth();
  const { reloadCases, reloadOverview } = useCase();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  if (!can('LEGAL_HOLD_MANAGE')) return null;
  const active = !!caseItem.legal_hold?.active;

  async function submit() {
    setBusy(true);
    setError('');
    try {
      await post(`/cases/${encodeURIComponent(caseItem.case_id)}/legal-hold`, { active: !active, reason: reason.trim() });
      toast(active ? `Legal hold released on ${caseItem.case_id}` : `${caseItem.case_id} is now under legal hold`, 'ok');
      setOpen(false);
      setReason('');
      await reloadCases();
      reloadOverview();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Button icon={active ? <LockOpen size={15} /> : <Lock size={15} />} onClick={() => setOpen(true)}>
        {active ? 'Release legal hold' : 'Place legal hold'}
      </Button>
      <Modal
        open={open}
        title={active ? `Release the legal hold on ${caseItem.case_id}` : `Place ${caseItem.case_id} under legal hold`}
        onClose={() => !busy && setOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={busy}>Cancel</Button>
            <Button variant={active ? 'default' : 'primary'} busy={busy} disabled={reason.trim().length < 5} onClick={submit}>
              {active ? 'Release hold' : 'Place hold'}
            </Button>
          </>
        }
      >
        <div className="stack" style={{ gap: 12 }}>
          <p className="small" style={{ margin: 0 }}>
            {active
              ? 'Releasing the hold allows evidence in this case to be deleted again.'
              : 'While the case is under legal hold, none of its evidence can be deleted. This is separate from the case status "On hold", which only describes the work.'}
          </p>
          <Field label={active ? 'Reason for releasing the hold' : 'Reason for the hold'} hint="Recorded in the audit log and shown in the case report.">
            <textarea className="textarea" value={reason} maxLength={500} autoFocus onChange={(e) => setReason(e.target.value)}
              placeholder={active ? 'For example: matter closed by legal counsel' : 'For example: litigation hold requested by legal counsel'} />
          </Field>
          {error && <Banner tone="danger">{error}</Banner>}
        </div>
      </Modal>
    </>
  );
}

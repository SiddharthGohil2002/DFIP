import { useState } from 'react';
import { post } from '../lib/api';
import { Banner, Button, ErrorBanner, Field, Modal, useToast } from '../ui';

/** Lets the signed-in user replace their password (for example the initial one an administrator set). */
export function ChangePasswordModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const mismatch = confirm.length > 0 && confirm !== next;
  const valid = current.length > 0 && next.length >= 12 && next === confirm;

  function close() {
    setCurrent('');
    setNext('');
    setConfirm('');
    setError('');
    onClose();
  }

  async function save() {
    setBusy(true);
    setError('');
    try {
      await post('/auth/change-password', { current_password: current, new_password: next });
      toast('Password changed. Use the new password the next time you sign in.', 'ok');
      close();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The password could not be changed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      title="Change password"
      onClose={close}
      footer={
        <>
          <Button onClick={close}>Cancel</Button>
          <Button variant="primary" busy={busy} disabled={!valid} onClick={save}>Change password</Button>
        </>
      }
    >
      <form className="stack" onSubmit={(e) => { e.preventDefault(); if (valid) save(); }}>
        <ErrorBanner error={error} />
        <Field label="Current password">
          <input className="input" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} autoFocus />
        </Field>
        <Field label="New password" hint="At least 12 characters.">
          <input className="input" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Field label="Confirm new password">
          <input className="input" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </Field>
        {mismatch && <Banner tone="warn">The passwords do not match.</Banner>}
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}

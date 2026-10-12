import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound, Lock, LockOpen, Trash2 } from 'lucide-react';
import { del, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Evidence } from '../lib/types';
import { Badge, Banner, Button, Card, ErrorBanner, Field, Hash, Modal, ProgressBar, StatusBadge, useToast } from '../ui';

const METHOD_LABEL: Record<string, string> = { password: 'password', recovery_password: 'recovery password' };
const METHODS: Record<string, string[]> = { BitLocker: ['password', 'recovery_password'], LUKS: ['password'] };

/** The files an image came in, the raw working copy every tool reads, and the volume a decrypted image came from. */
export function ImageFilesCard({ evidence: e }: { evidence: Evidence }) {
  const time = useTime();
  const wc = e.working_copy;
  if (!e.image_files?.length && !wc && !e.derived_from) return null;
  return (
    <Card title="Image files and working copy" flush
      subtitle={e.derived_from ? undefined : 'Each file of the image is hashed on its own and in order as a whole (the SHA-256 above). Images that are not raw are read through a raw working copy, made once and hashed.'}>
      <div className="stack" style={{ gap: 0 }}>
        {e.derived_from && (
          <div style={{ padding: '12px 16px' }}>
            <Banner tone="info">
              <LockOpen size={16} style={{ flex: 'none' }} />
              <div>Decrypted {e.derived_from.kind} volume <span className="mono">{e.derived_from.volume_id}</span> of{' '}
                <Link to={`/app/evidence/${encodeURIComponent(e.derived_from.evidence_id)}`} className="mono">{e.derived_from.evidence_id}</Link>,
                unlocked with a {METHOD_LABEL[e.derived_from.method] || e.derived_from.method} (stored encrypted as {e.derived_from.key_id}).
                The encrypted original is unchanged.</div>
            </Banner>
          </div>
        )}
        {!!e.image_files?.length && (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>File ({e.image_set?.label})</th><th>Role</th><th className="right">Size</th><th>SHA-256</th></tr></thead>
              <tbody>
                {e.image_files.map((f) => (
                  <tr key={f.name}><td className="mono small">{f.name}</td><td className="small">{f.role}</td>
                    <td className="right small">{formatBytes(f.size)}</td><td><Hash value={f.sha256} short={16} /></td></tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {wc && (
          <dl className="kv" style={{ padding: '12px 16px' }}>
            <dt>Working copy</dt><dd className="small">Raw, {formatBytes(wc.size)}, made with {wc.method || 'ewfexport'} {wc.created_at ? `on ${time(wc.created_at)}` : ''}
              {wc.stored_md5_match && <> · matches the MD5 stored in the E01</>}</dd>
            <dt>Working copy SHA-256</dt><dd><Hash value={wc.sha256} /></dd>
          </dl>
        )}
      </div>
    </Card>
  );
}

/** The volumes the analysis found, with encrypted ones offered for unlocking and their shadow copies. */
export function VolumesCard({ evidence: e, onChanged }: { evidence: Evidence; onChanged: () => void }) {
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const [polling, setPolling] = useState(false);
  const res = useApi<{ data: any[] }>(`/evidence/${encodeURIComponent(e.evidence_id)}/volumes`, { pollMs: polling ? 2000 : undefined });
  const [unlocking, setUnlocking] = useState<any>(null);
  const vols = res.data?.data || [];
  const decrypting = vols.some((v) => v.job);
  useEffect(() => {
    if (polling && !decrypting) onChanged();  // a decryption finished: the new evidence is in the case now
    setPolling(decrypting);
  }, [decrypting]);  // eslint-disable-line react-hooks/exhaustive-deps
  if (!vols.length) return null;

  async function forget(v: any) {
    try {
      await del(`/evidence/${encodeURIComponent(e.evidence_id)}/volumes/${encodeURIComponent(v.volume_id)}/key`);
      toast(`The stored key of ${v.volume_id} was deleted`, 'ok');
      res.reload();
    } catch (err: any) {
      toast(err.message, 'danger');
    }
  }

  return (
    <Card title="Volumes" subtitle="The file systems the analysis found. Encrypted volumes are unlocked with their password or recovery key; the decrypted volume becomes evidence of its own." flush>
      <ErrorBanner error={res.error} />
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Volume</th><th>File system</th><th className="right">Files</th><th>Encryption</th><th>Shadow copies</th><th /></tr></thead>
          <tbody>
            {vols.map((v) => (
              <tr key={v.volume_id}>
                <td className="mono small">{v.volume_id}{v.length ? <div className="tiny muted">{formatBytes(v.length)}</div> : null}</td>
                <td className="small">{v.filesystem_type || <span className="muted">unreadable</span>}</td>
                <td className="right small">{v.files?.toLocaleString() ?? '—'}</td>
                <td className="small">
                  {!v.encryption ? <span className="muted">none</span> : (
                    <>
                      <Badge tone={v.decrypted ? 'ok' : 'warn'}>{v.encryption}{v.decrypted ? ', UNLOCKED' : ', LOCKED'}</Badge>
                      {v.decrypted && <div className="tiny">decrypted as <Link className="mono" to={`/app/evidence/${encodeURIComponent(v.decrypted.evidence_id)}`}>{v.decrypted.evidence_id}</Link></div>}
                      {v.key && <div className="tiny muted">{METHOD_LABEL[v.key.method]} stored encrypted ({v.key.key_id}) by {v.key.created_by_name}, {time(v.key.created_at)}</div>}
                      {v.job && <div className="row" style={{ gap: 6 }}><StatusBadge status={v.job.status} /><ProgressBar value={v.job.progress} /></div>}
                    </>
                  )}
                </td>
                <td className="small">{v.shadow_copies?.length ? <Link to="/app/shadow-copies">{v.shadow_copies.length} shadow cop{v.shadow_copies.length === 1 ? 'y' : 'ies'}</Link> : <span className="muted">none</span>}</td>
                <td className="right nowrap">
                  {v.encryption && !v.decrypted && !v.job && can('EVIDENCE_UPLOAD') && (
                    <Button size="sm" icon={<KeyRound size={13} />} onClick={() => setUnlocking(v)}>Unlock</Button>
                  )}
                  {v.key && can('EVIDENCE_UPLOAD') && (
                    <Button size="sm" variant="ghost" icon={<Trash2 size={13} />} aria-label={`Delete the stored key of ${v.volume_id}`} onClick={() => forget(v)}>Forget key</Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {unlocking && <UnlockModal evidence={e} volume={unlocking} onClose={() => setUnlocking(null)}
        onStarted={(job) => { toast(`Unlocked; decrypting ${unlocking.volume_id} (${job})`, 'ok'); setUnlocking(null); setPolling(true); res.reload(); }} />}
    </Card>
  );
}

function UnlockModal({ evidence: e, volume: v, onClose, onStarted }: { evidence: Evidence; volume: any; onClose: () => void; onStarted: (job: string) => void }) {
  const methods = METHODS[v.encryption] || ['password'];
  const [method, setMethod] = useState(methods[0]);
  const [secret, setSecret] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError('');
    try {
      const r = await post<{ job_id: string }>(`/evidence/${encodeURIComponent(e.evidence_id)}/volumes/${encodeURIComponent(v.volume_id)}/unlock`, { method, secret });
      setSecret('');
      onStarted(r.job_id);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open title={`Unlock ${v.encryption} volume ${v.volume_id}`} onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" icon={<Lock size={14} />} disabled={!secret || busy} busy={busy} onClick={submit}>Unlock and decrypt</Button></>}>
      <div className="stack">
        <ErrorBanner error={error} />
        {methods.length > 1 && (
          <Field label="Unlock with">
            <select className="input" value={method} onChange={(ev) => setMethod(ev.target.value)}>
              {methods.map((m) => <option key={m} value={m}>{m === 'password' ? 'Password' : 'Recovery password (48 digits)'}</option>)}
            </select>
          </Field>
        )}
        <Field label={method === 'recovery_password' ? 'Recovery password' : 'Password'}
          hint={method === 'recovery_password' ? '8 groups of 6 digits, for example 123456-…' : undefined}>
          <input className="input mono" type="password" autoComplete="off" value={secret} onChange={(ev) => setSecret(ev.target.value)}
            onKeyDown={(ev) => ev.key === 'Enter' && secret && submit()} />
        </Field>
        <p className="small muted">The key is checked now. It is stored encrypted on the server, used only by the decryption job and never shown again;
          every use is in the audit log. The decrypted volume ({v.length ? formatBytes(v.length) : 'its size'}) is written once, hashed, recorded in the chain of custody and analysed.</p>
      </div>
    </Modal>
  );
}

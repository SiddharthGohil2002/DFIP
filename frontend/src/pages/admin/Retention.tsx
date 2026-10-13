import { useEffect, useState } from 'react';
import { CalendarClock, Play, Trash2 } from 'lucide-react';
import { api, del, post } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import { useTime } from '../../lib/format';
import { useApi } from '../../lib/useApi';
import { Badge, Banner, Button, Card, Empty, Field, Loading, Modal, PageHeader, useToast } from '../../ui';

interface Row { case_id: string; name: string; status?: string; closed_at?: string; due_at?: string; notified_at?: string; legal_hold?: boolean }
interface View {
  policy: { enabled: boolean; days: number; set_by_name?: string; set_at?: string };
  due: Row[]; closed: Row[]; runs: { at: string; due: string[]; held: string[]; notified: string[] }[];
  deleted: { case_id: string; name: string; deleted_at: string; deleted_by_name: string; reason: string }[];
}

export function RetentionPage() {
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const res = useApi<View>('/admin/retention');
  const [enabled, setEnabled] = useState(true);
  const [days, setDays] = useState('2555');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [target, setTarget] = useState<Row | null>(null);
  const [confirm, setConfirm] = useState('');
  const [reason, setReason] = useState('');
  useEffect(() => { if (res.data) { setEnabled(res.data.policy.enabled); setDays(String(res.data.policy.days)); } }, [res.data?.policy.days, res.data?.policy.enabled]);

  async function save() {
    setBusy('save'); setError('');
    try { await api('/admin/retention', { method: 'PUT', json: { enabled, days: Number(days) } }); res.reload(); toast('Retention policy saved', 'ok'); }
    catch (e: any) { setError(e.message); } finally { setBusy(''); }
  }
  async function run() {
    setBusy('run'); setError('');
    try {
      const r = await post<{ due: string[]; notified: string[]; held: string[] }>('/admin/retention/run');
      toast(`${r.due.length} case(s) due${r.held.length ? `, ${r.held.length} held` : ''}; administrators notified of ${r.notified.length}`, 'ok');
      res.reload();
    } catch (e: any) { setError(e.message); } finally { setBusy(''); }
  }
  async function remove() {
    if (!target) return;
    setBusy('delete'); setError('');
    try {
      const r = await del<{ removed: Record<string, number>; files_removed: number }>(`/cases/${encodeURIComponent(target.case_id)}`, { confirm: confirm.trim(), reason: reason.trim() });
      toast(`${target.case_id} deleted: ${r.removed.evidence ?? 0} evidence item(s), ${r.files_removed} file(s) removed`, 'ok');
      setTarget(null); setConfirm(''); setReason('');
      res.reload();
    } catch (e: any) { setError(e.message); } finally { setBusy(''); }
  }
  const v = res.data;
  const years = Number(days) / 365;
  return (
    <div className="stack">
      <PageHeader title="Retention" subtitle="How long closed cases are kept. When a case is completed or archived its retention period starts; a daily check tells administrators which cases are due. Nothing is deleted automatically, and a case under legal hold is never due." />
      {res.error && <Banner tone="danger">{res.error}</Banner>}
      {!v ? <Loading /> : <>
        <Card title="Policy" subtitle={v.policy.set_by_name ? `Last set by ${v.policy.set_by_name}, ${time(v.policy.set_at)}. Applies to cases closed from now on.` : 'Applies to cases closed from now on.'}>
          <div className="row" style={{ alignItems: 'flex-end', flexWrap: 'wrap', gap: 14 }}>
            <label className="check"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Give closed cases a retention date</label>
            <Field label="Keep closed cases for (days)" hint={Number.isFinite(years) && years > 0 ? `About ${years.toFixed(1)} years` : undefined}>
              <input className="input" type="number" min={1} max={36500} value={days} onChange={(e) => setDays(e.target.value)} style={{ maxWidth: 160 }} />
            </Field>
            <Button variant="primary" busy={busy === 'save'} disabled={!(Number(days) >= 1 && Number(days) <= 36500)} onClick={save}>Save</Button>
            <Button icon={<Play size={14} />} busy={busy === 'run'} onClick={run}>Run the check now</Button>
          </div>
          {error && <Banner tone="danger">{error}</Banner>}
        </Card>
        <Card title="Due for deletion" subtitle="Closed cases whose retention period has ended." flush>
          {!v.due.length ? <Empty icon={<CalendarClock size={20} />} title="No case is due" text="Cases appear here when their retention date has passed." /> : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Case</th><th>Closed</th><th>Due</th><th>Administrators told</th><th /></tr></thead>
              <tbody>{v.due.map((c) => (
                <tr key={c.case_id}>
                  <td className="small"><b>{c.case_id}</b> {c.name}{c.legal_hold && <div><Badge tone="warn">legal hold</Badge></div>}</td>
                  <td className="small nowrap">{time(c.closed_at)}</td><td className="small nowrap">{time(c.due_at)}</td><td className="small nowrap">{c.notified_at ? time(c.notified_at) : '—'}</td>
                  <td className="nowrap right">{can('CASE_DELETE') && <Button size="sm" variant="danger" icon={<Trash2 size={13} />} disabled={c.legal_hold}
                    title={c.legal_hold ? 'Release the legal hold first' : undefined} onClick={() => { setTarget(c); setConfirm(''); setReason(''); setError(''); }}>Delete case</Button>}</td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
        </Card>
        <Card title="Closed cases" subtitle="Every closed case with the date it is due." flush>
          {!v.closed.length ? <p className="small muted" style={{ padding: 14, margin: 0 }}>No closed case has a retention date.</p> : (
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Case</th><th>Status</th><th>Closed</th><th>Due</th></tr></thead>
              <tbody>{v.closed.map((c) => <tr key={c.case_id}><td className="small"><b>{c.case_id}</b> {c.name}</td><td className="small">{c.status?.toLowerCase()}</td>
                <td className="small nowrap">{time(c.closed_at)}</td><td className="small nowrap">{time(c.due_at)}</td></tr>)}</tbody>
            </table></div>
          )}
        </Card>
        {!!v.runs.length && (
          <Card title="Recent checks" flush>
            <div className="table-wrap"><table className="table">
              <thead><tr><th>When</th><th>Due</th><th>Held</th><th>Told about</th></tr></thead>
              <tbody>{v.runs.map((r) => <tr key={r.at}><td className="small nowrap">{time(r.at)}</td><td className="small">{r.due.join(', ') || '—'}</td>
                <td className="small">{r.held.join(', ') || '—'}</td><td className="small">{r.notified.join(', ') || '—'}</td></tr>)}</tbody>
            </table></div>
          </Card>
        )}
        {!!v.deleted.length && (
          <Card title="Deleted cases" subtitle="Kept as a record that they existed, with the chain of custody and the audit trail." flush>
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Case</th><th>Deleted</th><th>By</th><th>Reason</th></tr></thead>
              <tbody>{v.deleted.map((c) => <tr key={c.case_id}><td className="small"><b>{c.case_id}</b> {c.name}</td><td className="small nowrap">{time(c.deleted_at)}</td>
                <td className="small">{c.deleted_by_name}</td><td className="small break">{c.reason}</td></tr>)}</tbody>
            </table></div>
          </Card>
        )}
      </>}
      <Modal open={!!target} title={`Delete ${target?.case_id ?? ''}`} onClose={() => setTarget(null)}
        footer={<><Button onClick={() => setTarget(null)}>Cancel</Button>
          <Button variant="danger" busy={busy === 'delete'} disabled={confirm.trim() !== target?.case_id || reason.trim().length < 5} onClick={remove}>Delete the case's data</Button></>}>
        <Banner tone="warn">This permanently deletes every evidence item of {target?.case_id} with its analysis results, findings, comments, tags, reports and physical-evidence records. The chain of custody and the audit trail are kept.</Banner>
        <Field label={`Type ${target?.case_id} to confirm`}><input className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoFocus /></Field>
        <Field label="Reason" hint="At least 5 characters; recorded in the audit log."><textarea className="textarea" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
        {error && <Banner tone="danger">{error}</Banner>}
      </Modal>
    </div>
  );
}

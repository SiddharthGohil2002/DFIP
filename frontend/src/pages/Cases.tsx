import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FolderPlus, Pencil } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { api, patch, post } from '../lib/api';
import { useTime } from '../lib/format';
import type { CaseItem, User } from '../lib/types';
import { Banner, Button, Card, Empty, Field, Modal, PageHeader, StatusBadge, useToast } from '../ui';

const PRIORITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const STATUSES = ['OPEN', 'IN_PROGRESS', 'ON_HOLD', 'COMPLETED', 'ARCHIVED'];

export function CaseFormModal({ open, onClose, onSaved, existing }: {
  open: boolean;
  onClose: () => void;
  onSaved: (c: CaseItem) => void | Promise<void>;
  existing?: CaseItem | null;
}) {
  const { can } = useAuth();
  const toast = useToast();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('MEDIUM');
  const [status, setStatus] = useState('OPEN');
  const [investigator, setInvestigator] = useState('');
  const [members, setMembers] = useState<string[]>([]);
  const [people, setPeople] = useState<User[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(existing?.name || '');
    setDescription(existing?.description || '');
    setPriority(existing?.priority || 'MEDIUM');
    setStatus(existing?.status || 'OPEN');
    setInvestigator(existing?.investigator_id || '');
    setMembers(existing?.member_ids || []);
    setError('');
    if (can('CASE_UPDATE')) api<{ data: User[] }>('/admin/investigators?all=true').then((r) => setPeople(r.data)).catch(() => setPeople([]));
  }, [open, existing, can]);

  async function save() {
    setBusy(true);
    setError('');
    try {
      const body: Record<string, unknown> = { name: name.trim(), description, priority };
      if (investigator) body.investigator_id = investigator;
      const saved = existing
        ? await patch<CaseItem>(`/cases/${encodeURIComponent(existing.case_id)}`, { ...body, status })
        : await post<CaseItem>('/cases', body);
      if (existing && [...members].sort().join() !== [...(existing.member_ids || [])].sort().join()) {
        await api(`/cases/${encodeURIComponent(existing.case_id)}/members`, { method: 'PUT', json: { member_ids: members } });
      }
      toast(existing ? `${saved.case_id} updated` : `${saved.case_id} created`, 'ok');
      await onSaved(saved);
      onClose();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      title={existing ? `Edit ${existing.case_id}` : 'New case'}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={busy} disabled={name.trim().length < 2} onClick={save}>
            {existing ? 'Save changes' : 'Create case'}
          </Button>
        </>
      }
    >
      <Field label="Case title">
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Suspected payroll data exfiltration" autoFocus />
      </Field>
      <Field label="Description">
        <textarea className="textarea" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Scope, source of the evidence, legal authority…" />
      </Field>
      <div className="grid cols-2">
        <Field label="Priority">
          <select className="select" value={priority} onChange={(e) => setPriority(e.target.value)}>
            {PRIORITIES.map((p) => <option key={p}>{p}</option>)}
          </select>
        </Field>
        {existing && (
          <Field label="Status">
            <select className="select" value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
            </select>
          </Field>
        )}
      </div>
      {people.length > 0 && (
        <Field label="Lead investigator" hint="Assigned investigators can open the case and its evidence.">
          <select className="select" value={investigator} onChange={(e) => setInvestigator(e.target.value)}>
            <option value="">{existing ? 'Unchanged' : 'Me'}</option>
            {people.filter((p) => p.role !== 'VIEWER').map((p) => <option key={p._id} value={p._id}>{p.name} ({p.role.toLowerCase()})</option>)}
          </select>
        </Field>
      )}
      {existing && people.length > 0 && (
        <fieldset className="field" style={{ border: 'none', padding: 0, margin: 0 }}>
          <legend className="small strong" style={{ marginBottom: 6 }}>Team</legend>
          <p className="tiny muted" style={{ margin: '0 0 6px' }}>Members can open the case, comment and be asked to review findings, as their role allows. Added members are notified.</p>
          <div className="row" style={{ flexWrap: 'wrap' }}>
            {people.filter((p) => p._id !== existing.investigator_id && p._id !== existing.created_by && p.role !== 'ADMIN').map((p) => (
              <label key={p._id} className="check small">
                <input type="checkbox" checked={members.includes(p._id)} onChange={(e) => setMembers(e.target.checked ? [...members, p._id] : members.filter((m) => m !== p._id))} />
                {p.name} <span className="muted">({p.role.toLowerCase()})</span>
              </label>
            ))}
          </div>
        </fieldset>
      )}
      {existing && ['COMPLETED', 'ARCHIVED'].includes(status) && !['COMPLETED', 'ARCHIVED'].includes(existing.status) && (
        <p className="tiny muted" style={{ margin: 0 }}>Closing the case starts its retention period (see Administration &gt; Retention).</p>
      )}
      {error && <Banner tone="danger">{error}</Banner>}
    </Modal>
  );
}

export function CasesPage() {
  const { can } = useAuth();
  const { cases, caseId, setCaseId, reloadCases, reloadOverview } = useCase();
  const [editing, setEditing] = useState<CaseItem | null>(null);
  const [creating, setCreating] = useState(false);
  const time = useTime();
  const navigate = useNavigate();

  return (
    <div className="stack">
      <PageHeader
        title="Cases"
        subtitle="Cases you lead, created or are a member of. Open one to make it the active case for every workspace page."
        actions={can('CASE_CREATE') && <Button variant="primary" icon={<FolderPlus size={15} />} onClick={() => setCreating(true)}>New case</Button>}
      />
      <Card flush>
        {!cases.length ? (
          <Empty title="No cases" text="Create a case to start an investigation." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Case</th><th>Title</th><th>Status</th><th>Priority</th><th>Opened</th><th>Updated</th><th /></tr></thead>
              <tbody>
                {cases.map((c) => (
                  <tr key={c.case_id}>
                    <td className="mono strong nowrap">{c.case_id}{c.case_id === caseId && <div className="tiny" style={{ color: 'var(--accent)' }}>active</div>}</td>
                    <td>
                      <div className="strong">{c.name}</div>
                      {c.description && <div className="small muted">{c.description}</div>}
                    </td>
                    <td><StatusBadge status={c.status} /></td>
                    <td><StatusBadge status={c.priority} /></td>
                    <td className="small nowrap">{time(c.created_at)}</td>
                    <td className="small nowrap">{time(c.updated_at)}</td>
                    <td className="nowrap right">
                      {can('CASE_UPDATE') && <Button size="sm" variant="ghost" icon={<Pencil size={13} />} onClick={() => setEditing(c)}>Edit</Button>}
                      <Button size="sm" variant={c.case_id === caseId ? 'default' : 'primary'} onClick={() => { setCaseId(c.case_id); navigate('/app'); }}>
                        Open
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <CaseFormModal
        open={creating}
        onClose={() => setCreating(false)}
        onSaved={async (c) => {
          await reloadCases();
          setCaseId(c.case_id);
        }}
      />
      <CaseFormModal
        open={!!editing}
        existing={editing}
        onClose={() => setEditing(null)}
        onSaved={async () => {
          await reloadCases();
          reloadOverview();
        }}
      />
    </div>
  );
}

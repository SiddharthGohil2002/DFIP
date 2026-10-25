import { useState } from 'react';
import { UserPlus } from 'lucide-react';
import { useAuth } from '../../lib/auth';
import { patch, post } from '../../lib/api';
import { useTime } from '../../lib/format';
import { useApi } from '../../lib/useApi';
import type { User } from '../../lib/types';
import { Banner, Button, Card, Empty, Field, Loading, Modal, PageHeader, StatusBadge, useToast } from '../../ui';
import { ExportButton } from '../../ui/ExportButton';

const ROLES = ['ADMIN', 'INVESTIGATOR', 'ANALYST', 'VIEWER'];
const ROLE_NOTES: Record<string, string> = {
  ADMIN: 'Everything, including users and roles',
  INVESTIGATOR: 'Cases, evidence, analysis, findings, reports',
  ANALYST: 'Analysis and findings on assigned cases',
  VIEWER: 'Read-only access to assigned cases',
};

export function UsersPage() {
  const { can, user: me } = useAuth();
  const toast = useToast();
  const time = useTime();
  const path = can('USER_MANAGE') ? '/admin/users' : null;
  const rolesPath = can('ROLE_MANAGE') ? '/admin/roles' : null;
  const list = useApi<{ data: (User & { created_at?: string; last_login_at?: string })[] }>(path);
  const roles = useApi<{ data: { name: string; permissions: string[] }[] }>(rolesPath);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: '', email: '', role: 'INVESTIGATOR', password: '' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  // Rejecting and suspending lock a person out, so they are confirmed first; approving and reactivating are not.
  const [confirm, setConfirm] = useState<{ user: User; status: 'SUSPENDED' | 'DISABLED' } | null>(null);

  if (!can('USER_MANAGE')) return <Banner tone="warn">Only administrators can manage users.</Banner>;

  const pending = (list.data?.data || []).filter((u) => u.status === 'PENDING');
  const others = (list.data?.data || []).filter((u) => u.status !== 'PENDING');

  async function create() {
    setBusy(true);
    setError('');
    try {
      await post('/admin/users', form);
      toast(`${form.email} created`, 'ok');
      setOpen(false);
      list.reload();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function update(u: User, change: Partial<User>) {
    try {
      await patch(`/admin/users/${u._id}`, change);
      toast(`${u.email} updated`, 'ok');
      list.reload();
    } catch (e: any) {
      toast(e.message, 'danger');
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Users"
        subtitle="Accounts and roles. Every permission is enforced by the server; the interface only hides actions a role cannot perform."
        actions={<Button variant="primary" icon={<UserPlus size={15} />} onClick={() => { setForm({ name: '', email: '', role: 'INVESTIGATOR', password: '' }); setError(''); setOpen(true); }}>Add user</Button>}
      />
      {pending.length > 0 && (
        <Card title={`Waiting for approval (${pending.length})`} subtitle="Accounts created from the sign-in page. Choose a role and approve, or reject." flush>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Name</th><th>Email</th><th>Requested</th><th>Role on approval</th><th /></tr></thead>
              <tbody>
                {pending.map((u) => (
                  <PendingRow key={u._id} user={u} requested={time(u.created_at)}
                    onDecide={(change) => change.status === 'DISABLED' ? setConfirm({ user: u, status: 'DISABLED' }) : update(u, change)} />
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <Card flush actions={can('REPORT_EXPORT') && !!list.data?.data.length && <ExportButton path={path} what="list of users" />}>
        {list.loading && !list.data ? <Loading /> : !others.length ? <Empty title="No users" /> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last sign-in</th></tr></thead>
              <tbody>
                {others.map((u) => {
                  const self = u._id === me?._id;
                  return (
                    <tr key={u._id}>
                      <td className="strong">{u.name}{self && <span className="tiny muted"> (you)</span>}</td>
                      <td className="small">{u.email}</td>
                      <td>
                        <select className="select sm" style={{ width: 150 }} value={u.role} disabled={self} onChange={(e) => update(u, { role: e.target.value as User['role'] })} aria-label={`Role of ${u.email}`}>
                          {ROLES.map((r) => <option key={r}>{r}</option>)}
                        </select>
                      </td>
                      <td>
                        <div className="row">
                          <StatusBadge status={u.status} />
                          {!self && (
                            <Button size="sm" variant="ghost" onClick={() => u.status === 'ACTIVE' ? setConfirm({ user: u, status: 'SUSPENDED' }) : update(u, { status: 'ACTIVE' })}>
                              {u.status === 'ACTIVE' ? 'Suspend' : 'Reactivate'}
                            </Button>
                          )}
                        </div>
                      </td>
                      <td className="small nowrap">{time(u.last_login_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {roles.data && (
        <Card title="Role permissions" flush actions={<ExportButton path={rolesPath} what="list of roles" />}>
          <table className="table">
            <thead><tr><th>Role</th><th>Can</th><th>Permissions</th></tr></thead>
            <tbody>
              {roles.data.data.map((r) => (
                <tr key={r.name}>
                  <td className="strong">{r.name}</td>
                  <td className="small">{ROLE_NOTES[r.name]}</td>
                  <td className="tiny mono">{(r.permissions || []).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Modal
        open={open}
        title="Add user"
        onClose={() => setOpen(false)}
        footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} onClick={create} disabled={!form.name || !form.email || form.password.length < 12}>Create user</Button></>}
      >
        <Field label="Full name"><input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} autoFocus /></Field>
        <Field label="Email"><input className="input" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
        <Field label="Role" hint={ROLE_NOTES[form.role]}>
          <select className="select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            {ROLES.map((r) => <option key={r}>{r}</option>)}
          </select>
        </Field>
        <Field label="Initial password" hint="At least 12 characters. Share it securely; the user can change it after signing in.">
          <input className="input" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </Field>
        {error && <Banner tone="danger">{error}</Banner>}
      </Modal>

      <Modal
        open={!!confirm}
        title={confirm ? `${confirm.status === 'SUSPENDED' ? 'Suspend' : 'Reject'} ${confirm.user.email}?` : ''}
        onClose={() => setConfirm(null)}
        footer={confirm && <>
          <Button onClick={() => setConfirm(null)}>Cancel</Button>
          <Button variant="danger" onClick={() => { update(confirm.user, { status: confirm.status }); setConfirm(null); }}>
            {confirm.status === 'SUSPENDED' ? 'Suspend account' : 'Reject account'}
          </Button>
        </>}
      >
        {confirm?.status === 'SUSPENDED'
          ? <p>{confirm.user.name} is signed out at once: every request is refused until an administrator reactivates the account. Their cases, findings and audit records are kept.</p>
          : <p>{confirm?.user.name} cannot sign in. The account stays in the list as disabled, so an administrator can still reactivate it later.</p>}
      </Modal>
    </div>
  );
}

function PendingRow({ user, requested, onDecide }: { user: User; requested: string; onDecide: (change: Partial<User>) => void }) {
  const [role, setRole] = useState<User['role']>('INVESTIGATOR');
  return (
    <tr>
      <td className="strong">{user.name}</td>
      <td className="small">{user.email}</td>
      <td className="small nowrap">{requested}</td>
      <td>
        <select className="select sm" style={{ width: 150 }} value={role} onChange={(e) => setRole(e.target.value as User['role'])} aria-label={`Role for ${user.email}`}>
          {ROLES.map((r) => <option key={r}>{r}</option>)}
        </select>
        <div className="tiny muted" style={{ marginTop: 4 }}>{ROLE_NOTES[role]}</div>
      </td>
      <td className="nowrap right">
        <Button size="sm" variant="primary" onClick={() => onDecide({ status: 'ACTIVE', role })}>Approve</Button>{' '}
        <Button size="sm" variant="danger" onClick={() => onDecide({ status: 'DISABLED' })}>Reject</Button>
      </td>
    </tr>
  );
}

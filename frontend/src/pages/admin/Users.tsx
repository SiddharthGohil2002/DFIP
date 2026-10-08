import { useState } from 'react';
import { UserPlus } from 'lucide-react';
import { useAuth } from '../../lib/auth';
import { patch, post } from '../../lib/api';
import { useTime } from '../../lib/format';
import { useApi } from '../../lib/useApi';
import type { User } from '../../lib/types';
import { Banner, Button, Card, Empty, Field, Loading, Modal, PageHeader, StatusBadge, useToast } from '../../ui';

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
  const list = useApi<{ data: (User & { created_at?: string; last_login_at?: string })[] }>(can('USER_MANAGE') ? '/admin/users' : null);
  const roles = useApi<{ data: { name: string; permissions: string[] }[] }>(can('ROLE_MANAGE') ? '/admin/roles' : null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: '', email: '', role: 'INVESTIGATOR', password: '' });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  if (!can('USER_MANAGE')) return <Banner tone="warn">Only administrators can manage users.</Banner>;

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
      <Card flush>
        {list.loading && !list.data ? <Loading /> : !list.data?.data.length ? <Empty title="No users" /> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last sign-in</th></tr></thead>
              <tbody>
                {list.data.data.map((u) => {
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
                            <Button size="sm" variant="ghost" onClick={() => update(u, { status: u.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE' })}>
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
        <Card title="Role permissions" flush>
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
    </div>
  );
}

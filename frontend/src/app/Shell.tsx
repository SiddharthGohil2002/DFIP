import { useContext, useState, type ReactNode } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { KeyRound, LogOut, Plus, Search, Server } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { TimeModeContext } from '../lib/format';
import { IS_DESKTOP } from '../lib/platform';
import { serverUrl } from '../lib/api';
import { useApi } from '../lib/useApi';
import { Button, StatusBadge } from '../ui';
import { CaseFormModal } from '../pages/Cases';
import { Logo } from './Logo';
import { DesktopDownload } from './DesktopDownload';
import { ChangePasswordModal } from './ChangePassword';
import { NAV } from './nav';

function initials(name: string) {
  return name.split(/\s+/).map((p) => p[0]).slice(0, 2).join('').toUpperCase();
}

export function Shell({ children }: { children: ReactNode }) {
  const { user, logout, can } = useAuth();
  const { cases, caseId, setCaseId, activeCase, overview, reloadCases } = useCase();
  const { mode, setMode } = useContext(TimeModeContext);
  const [creating, setCreating] = useState(false);
  const [query, setQuery] = useState('');
  const navigate = useNavigate();
  const counts = overview?.counts;
  const [signingOut, setSigningOut] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);
  async function signOut() {
    setSigningOut(true);
    // Clearing the session sends every workspace route to the sign-in page.
    await logout();
  }
  // Administrators see how many self-created accounts are waiting for approval.
  const users = useApi<{ data: { status: string }[] }>(can('USER_MANAGE') ? '/admin/users' : null, { pollMs: 60000 });
  const pendingUsers = (users.data?.data || []).filter((u) => u.status === 'PENDING').length;

  return (
    <div className="shell">
      <aside className="sidebar">
        <Logo />
        <nav className="nav" aria-label="Workspace">
          {NAV.map((group) => {
            const items = group.items.filter((i) => !i.permission || can(i.permission));
            if (!items.length) return null;
            return (
              <div className="nav-group" key={group.title}>
                <div className="nav-group-title">{group.title}</div>
                {items.map((item) => {
                  const Icon = item.icon;
                  const count = item.to === '/app/admin/users' ? pendingUsers : counts && item.count ? item.count(counts) : null;
                  return (
                    <NavLink key={item.to} to={item.to} end={item.to === '/app'} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
                      <Icon size={17} />
                      {item.label}
                      {count !== null && count > 0 && (
                        <span className={`nav-count ${(counts && item.alert?.(counts)) || item.to === '/app/admin/users' ? 'alert' : ''}`} title={item.to === '/app/admin/users' ? 'Accounts waiting for approval' : undefined}>{count.toLocaleString()}</span>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            );
          })}
        </nav>
        <DesktopDownload variant="sidebar" />
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="case-switch">
            <span className="small muted strong">Case</span>
            <select className="select" value={caseId} onChange={(e) => setCaseId(e.target.value)} aria-label="Active case">
              {!cases.length && <option value="">No cases yet</option>}
              {cases.map((c) => (
                <option key={c.case_id} value={c.case_id}>
                  {c.case_id} — {c.name}
                </option>
              ))}
            </select>
            {activeCase && <StatusBadge status={activeCase.status} />}
            {can('CASE_CREATE') && (
              <Button size="sm" icon={<Plus size={14} />} onClick={() => setCreating(true)}>
                New case
              </Button>
            )}
          </div>
          {caseId && (
            <form
              className="topbar-search hide-narrow"
              role="search"
              onSubmit={(e) => {
                e.preventDefault();
                if (query.trim().length >= 2) navigate(`/app/search?q=${encodeURIComponent(query.trim())}`);
              }}
            >
              <Search size={15} />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search this case…" aria-label="Search this case" />
            </form>
          )}
          <div className="spacer" />
          {IS_DESKTOP && (
            <span className="small muted row hide-narrow" title="DFIP server">
              <Server size={14} /> {serverUrl().replace(/^https?:\/\//, '')}
            </span>
          )}
          <div className="row" role="group" aria-label="Time display">
            <Button size="sm" variant={mode === 'utc' ? 'primary' : 'default'} onClick={() => { setMode('utc'); }}>
              UTC
            </Button>
            <Button size="sm" variant={mode === 'local' ? 'primary' : 'default'} onClick={() => { setMode('local'); }}>
              Local
            </Button>
          </div>
          <div className="topbar-user">
            <div className="avatar" aria-hidden="true">{initials(user?.name || '?')}</div>
            <div className="who hide-narrow">
              <b>{user?.name}</b>
              <span>{user?.role}</span>
            </div>
            <Button size="sm" variant="ghost" icon={<KeyRound size={14} />} onClick={() => setChangingPassword(true)}
              title="Change password" aria-label="Change password" />
            <Button size="sm" icon={<LogOut size={14} />} busy={signingOut} onClick={signOut} title="Sign out of DFIP">
              Sign out
            </Button>
          </div>
        </header>
        <main className="content">
          <div className="content-inner">{children}</div>
        </main>
      </div>

      <ChangePasswordModal open={changingPassword} onClose={() => setChangingPassword(false)} />
      <CaseFormModal
        open={creating}
        onClose={() => setCreating(false)}
        onSaved={async (c) => {
          await reloadCases();
          setCaseId(c.case_id);
          navigate('/app');
        }}
      />
    </div>
  );
}

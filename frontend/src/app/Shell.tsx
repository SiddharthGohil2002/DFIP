import { useContext, useState, type ReactNode } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { LogOut, Plus, Server } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { TimeModeContext } from '../lib/format';
import { IS_DESKTOP } from '../lib/platform';
import { serverUrl } from '../lib/api';
import { Button, StatusBadge } from '../ui';
import { CaseFormModal } from '../pages/Cases';
import { Logo } from './Logo';
import { NAV } from './nav';

function initials(name: string) {
  return name.split(/\s+/).map((p) => p[0]).slice(0, 2).join('').toUpperCase();
}

export function Shell({ children }: { children: ReactNode }) {
  const { user, logout, can } = useAuth();
  const { cases, caseId, setCaseId, activeCase, overview, reloadCases } = useCase();
  const { mode, setMode } = useContext(TimeModeContext);
  const [creating, setCreating] = useState(false);
  const navigate = useNavigate();
  const counts = overview?.counts;

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
                  const count = counts && item.count ? item.count(counts) : null;
                  return (
                    <NavLink key={item.to} to={item.to} end={item.to === '/app'} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
                      <Icon size={17} />
                      {item.label}
                      {count !== null && count > 0 && (
                        <span className={`nav-count ${counts && item.alert?.(counts) ? 'alert' : ''}`}>{count.toLocaleString()}</span>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <div className="avatar">{initials(user?.name || '?')}</div>
          <div className="who">
            <b>{user?.name}</b>
            <span>{user?.role}</span>
          </div>
          <Button
            size="sm"
            icon={<LogOut size={14} />}
            title="Sign out"
            onClick={async () => {
              await logout();
              navigate('/login');
            }}
          />
        </div>
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
          <div className="spacer" />
          {IS_DESKTOP && (
            <span className="small muted row" title="DFIP server">
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
        </header>
        <main className="content">
          <div className="content-inner">{children}</div>
        </main>
      </div>

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

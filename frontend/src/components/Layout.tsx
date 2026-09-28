import { ReactNode, useContext, useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import * as I from 'lucide-react';
import { AuthContext } from '../main';
import { WS, api } from '../services/api';
import { isDesktop } from '../native';
import DesktopStatus from './DesktopStatus';


const invNav: any[] = [
  ['Overview', [
    ['Dashboard', '/investigator/dashboard', I.LayoutDashboard]
  ]],
  ['Intake & Evidence', [
    ['Cases', '/investigator/cases', I.Folders],
    ['Evidence Register', '/investigator/evidence', I.Shield],
    ['Acquisition', '/investigator/acquisition', I.Upload],
    ['Background Jobs', '/investigator/jobs', I.ListTodo],
    ['Forensic Tooling', '/investigator/tooling', I.Wrench],
    ['Desktop Operations', '/investigator/desktop-operations', I.Cpu]
  ]],
  ['Forensic Lab', [
    ['Functions & Capabilities', '/investigator/functions', I.Sparkles],
    ['Timeline Analysis', '/investigator/timeline', I.Clock3],
    ['Filesystem Recovery', '/investigator/file-recovery', I.FileSearch],
    ['Signature Carving', '/investigator/carving', I.Layers],
    ['Threat Intelligence', '/investigator/threat-intel', I.Radar]
  ]],
  ['Artifact Parsers', [
    ['Browser Forensics', '/investigator/browser', I.Globe],
    ['USB Removable Media', '/investigator/usb', I.Usb],
    ['Email Forensics', '/investigator/email', I.Mail],
    ['Network & PCAP', '/investigator/network', I.Network],
    ['Malware Indicators', '/investigator/malware', I.Bug],
    ['Pattern Detection', '/investigator/patterns', I.Activity],
    ['Anomaly Scoring', '/investigator/anomalies', I.BrainCircuit],
    ['AI Forensic Assistant', '/investigator/ai-assistant', I.Sparkles]
  ]],
  ['Documentation & Legal', [
    ['Case Findings', '/investigator/findings', I.FileCheck],
    ['Forensic Reports', '/investigator/reports', I.FileText],
    ['Chain of Custody', '/investigator/chain-of-custody', I.GitBranch],
    ['Tamper-Evident Audit', '/investigator/audit', I.ListChecks],
    ['Alert Center', '/investigator/notifications', I.Bell]
  ]],
];

const adminNav: any[] = [
  ['Platform Command', [
    ['Admin Dashboard', '/admin/dashboard', I.LayoutDashboard],
    ['User Management', '/admin/users', I.Users],
    ['Roles & RBAC Policies', '/admin/roles', I.KeyRound],
    ['Active Cases', '/admin/cases', I.Folders],
    ['Evidence Register', '/admin/evidence', I.Shield],
    ['Security Telemetry', '/admin/security', I.ShieldAlert],
    ['Audit Hash Chain', '/admin/audit', I.ListChecks],
    ['Job Orchestration', '/admin/jobs', I.ListTodo],
    ['Tooling Inventory', '/admin/tooling', I.Wrench],
    ['Forensic Reports', '/admin/reports', I.FileText],
    ['System Settings', '/admin/settings', I.Settings]
  ]],
];

export function AppLayout({ children, admin: adminMode = false }: { children: ReactNode; admin?: boolean }) {
  const { user, setUser } = useContext(AuthContext);
  const nav = useNavigate();
  const loc = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const [unread, setUnread] = useState(0);
  const [cmdOpen, setCmdOpen] = useState(false);
  const [wsOnline, setWsOnline] = useState(false);

  useEffect(() => {
    api<any>('/notifications')
      .then((r: any) => setUnread((r.data || []).filter((x: any) => !x.read).length))
      .catch(() => {});

    let ws: WebSocket | null = null;
    let timer: any = null;
    let active = true;

    function connect() {
      if (!active) return;
      const token = localStorage.getItem('dfip_token') || '';
      const client = isDesktop ? 'desktop' : 'web';
      ws = new WebSocket(`${WS}?client=${client}&token=${token}`);

      ws.onopen = () => {
        if (!active) return;
        setWsOnline(true);
      };

      ws.onmessage = (e) => {
        try {
          const m = JSON.parse(e.data);
          if (m.type === 'notification' || m.event === 'NOTIFICATION_CREATED') {
            setUnread((x) => x + 1);
          }
          window.dispatchEvent(new CustomEvent('dfip-ws-event', { detail: m }));
        } catch {}
      };

      ws.onerror = () => {
        setWsOnline(false);
      };

      ws.onclose = () => {
        setWsOnline(false);
        if (active) {
          timer = setTimeout(connect, 3000);
        }
      };
    }

    connect();

    const handleKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCmdOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', handleKey);

    return () => {
      active = false;
      if (timer) clearTimeout(timer);
      if (ws) ws.close();
      window.removeEventListener('keydown', handleKey);
    };
  }, [user]);

  async function logout() {
    const rt = localStorage.getItem('dfip_refresh');
    if (rt) {
      try {
        await api('/auth/logout', { method: 'POST', body: JSON.stringify({ refresh_token: rt }) });
      } catch {}
    }
    localStorage.removeItem('dfip_token');
    localStorage.removeItem('dfip_refresh');
    setUser(null);
    nav('/login');
  }

  const groups = adminMode ? adminNav : invNav;

  return (
    <div style={{ minHeight: '100vh', display: 'flex', background: 'var(--bg)' }}>
      {/* Sleek Enterprise Sidebar */}
      <aside
        className="glass"
        style={{
          width: collapsed ? 76 : 260,
          position: 'fixed',
          inset: '0 auto 0 0',
          zIndex: 30,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '16px 12px',
          borderRight: '1px solid var(--border)',
          transition: 'width 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
          background: 'var(--surface)'
        }}
      >
        {/* Brand Header */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 8px 18px', borderBottom: '1px solid var(--border)' }}>
            <Link
              to={adminMode ? '/admin/dashboard' : '/investigator/dashboard'}
              style={{ display: 'flex', alignItems: 'center', gap: 10, overflow: 'hidden' }}
            >
              <span
                style={{
                  width: 36,
                  height: 36,
                  borderRadius: 8,
                  display: 'grid',
                  placeItems: 'center',
                  background: 'var(--red)',
                  color: '#FFFFFF',
                  flexShrink: 0,
                  boxShadow: '0 2px 6px var(--red-glow)'
                }}
              >
                <I.ShieldCheck size={20} />
              </span>
              {!collapsed && (
                <div>
                  <div style={{ fontWeight: 800, fontSize: 16, letterSpacing: '-0.02em', color: 'var(--ink)', lineHeight: 1.1 }}>DFIP</div>
                  <div style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                    {adminMode ? 'ADMIN CONSOLE' : 'INVESTIGATOR'}
                  </div>
                </div>
              )}
            </Link>

            <button
              className="btn ghost sm"
              style={{ padding: 6, color: 'var(--muted)' }}
              onClick={() => setCollapsed(!collapsed)}
              title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {collapsed ? <I.ChevronRight size={16} /> : <I.ChevronLeft size={16} />}
            </button>
          </div>

          {/* Navigation Links */}
          <div style={{ overflowY: 'auto', maxHeight: 'calc(100vh - 170px)', padding: '12px 0' }}>
            {groups.map(([title, items]: any) => (
              <div key={title} style={{ marginBottom: 16 }}>
                {!collapsed && (
                  <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--muted)', padding: '0 10px 6px' }}>
                    {title}
                  </div>
                )}
                {items.map(([label, path, Icon]: any) => {
                  const active = loc.pathname === path || (path !== '/investigator/dashboard' && path !== '/admin/dashboard' && loc.pathname.startsWith(path + '/'));
                  return (
                    <Link
                      key={path}
                      to={path}
                      title={collapsed ? label : ''}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 11,
                        padding: '8px 10px',
                        borderRadius: 'var(--radius-sm)',
                        marginBottom: 2,
                        fontSize: 13,
                        fontWeight: active ? 600 : 500,
                        textDecoration: 'none',
                        color: active ? 'var(--red)' : 'var(--ink-light)',
                        background: active ? 'var(--red-light)' : 'transparent',
                        borderLeft: active ? '3px solid var(--red)' : '3px solid transparent',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      <Icon size={17} style={{ flexShrink: 0, color: active ? 'var(--red)' : 'var(--muted)' }} />
                      {!collapsed && <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>}
                      {!collapsed && label === 'Alert Center' && unread > 0 && (
                        <span className="badge danger" style={{ marginLeft: 'auto', padding: '1px 6px', fontSize: 10 }}>{unread}</span>
                      )}
                    </Link>
                  );
                })}
              </div>
            ))}
          </div>
        </div>

        {/* Desktop Status (desktop mode) or Download Client (web mode) */}
        {isDesktop && !collapsed && (
          <div style={{ padding: '8px 4px 0', borderTop: '1px solid var(--border)', marginTop: 4 }}>
            <DesktopStatus compact />
          </div>
        )}
        {!isDesktop && !collapsed && (
          <div style={{ padding: '8px 8px', borderTop: '1px solid var(--border)', marginTop: 4, background: 'var(--bg-subtle)', borderRadius: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--ink)' }}>Desktop Workstation</span>
              <span className="badge info" style={{ fontSize: 9, padding: '1px 5px' }}>v2.0.0</span>
            </div>
            <div className="muted" style={{ fontSize: 10.5, marginBottom: 6 }}>For local disk acquisition & tools.</div>
            <a
              href="/downloads/DFIP-Investigator-Windows-x64.exe"
              download="DFIP-Investigator-Windows-x64.exe"
              className="btn primary sm"
              style={{ width: '100%', fontSize: 11, padding: '5px 8px', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: 5, textDecoration: 'none' }}
              title="Direct download DFIP Investigator Windows Installer (v2.0.0)"
            >
              <I.Download size={12} /> Download Client (.exe)
            </a>
          </div>
        )}

        {/* User Card & Sign Out */}

        <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12 }}>
          {!collapsed && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 8px 10px' }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: 'var(--bg-subtle)', border: '1px solid var(--border)', display: 'grid', placeItems: 'center', fontWeight: 700, fontSize: 12, color: 'var(--ink)' }}>
                {user?.name ? user.name.slice(0, 2).toUpperCase() : 'DF'}
              </div>
              <div style={{ flex: 1, overflow: 'hidden' }}>
                <div style={{ fontSize: 12.5, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user?.name}</div>
                <div style={{ fontSize: 10.5, color: 'var(--muted)', textTransform: 'uppercase', fontWeight: 600 }}>{user?.role}</div>
              </div>
            </div>
          )}
          <button
            className="btn ghost"
            style={{ width: '100%', justifyContent: collapsed ? 'center' : 'flex-start', padding: '8px 10px', fontSize: 13, color: 'var(--muted)' }}
            onClick={logout}
            title="Sign out of DFIP"
          >
            <I.LogOut size={16} />
            {!collapsed && <span>Sign Out</span>}
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div style={{ marginLeft: collapsed ? 76 : 260, flex: 1, minHeight: '100vh', display: 'flex', flexDirection: 'column', transition: 'margin-left 0.2s cubic-bezier(0.4, 0, 0.2, 1)' }}>
        {/* Top Header Bar */}
        <header
          className="glass"
          style={{
            height: 64,
            position: 'sticky',
            top: 0,
            zIndex: 20,
            padding: '0 32px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'rgba(255, 255, 255, 0.88)',
            borderBottom: '1px solid var(--border)'
          }}
        >
          {/* Quick Search / Command Palette Trigger */}
          <button
            className="btn ghost"
            style={{ padding: '7px 14px', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', background: 'var(--surface)' }}
            onClick={() => setCmdOpen(true)}
          >
            <I.Search size={14} className="muted" />
            <span className="muted" style={{ fontSize: 13 }}>Quick navigation…</span>
            <kbd style={{ marginLeft: 12, padding: '2px 6px', fontSize: 10, background: 'var(--bg-subtle)', borderRadius: 4, border: '1px solid var(--border)', color: 'var(--muted)' }}>
              Ctrl K
            </kbd>
          </button>

          {/* Right Header Status Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {/* Architectural Mode Badge */}
            {isDesktop ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', background: 'var(--green-bg)', border: '1px solid var(--green-border)', borderRadius: 999, fontSize: 11, fontWeight: 700, color: 'var(--green-dark)' }}>
                <span className="beacon active" />
                <span>WORKSTATION ONLINE — OPERATIONAL</span>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', background: 'rgba(200, 16, 46, 0.08)', border: '1px solid rgba(200, 16, 46, 0.25)', borderRadius: 999, fontSize: 11, fontWeight: 700, color: 'var(--red)' }}>
                <I.Eye size={12} />
                <span>WEB PORTAL — READ-ONLY MONITORING</span>
              </div>
            )}

            {/* WebSocket Event Bus Health */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 10px', background: 'var(--bg-subtle)', border: '1px solid var(--border)', borderRadius: 999, fontSize: 11 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: wsOnline ? 'var(--green)' : 'var(--amber)' }} />
              <span style={{ fontWeight: 600, color: 'var(--muted)' }}>{wsOnline ? 'Live Event Bus' : 'Reconnecting…'}</span>
            </div>

            {/* Desktop connection status — shown on web for awareness */}
            {!isDesktop && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 10px', border: '1px solid var(--border)', borderRadius: 999, fontSize: 11, background: 'var(--surface)' }}>
                <I.Monitor size={12} style={{ color: 'var(--muted)' }} />
                <DesktopStatus compact />
              </div>
            )}

            {/* Notification Bell */}
            {!adminMode && (
              <Link
                to="/investigator/notifications"
                className="btn ghost sm"
                style={{ padding: 8, position: 'relative', borderRadius: 8 }}
                title="Notifications"
              >
                <I.Bell size={17} />
                {unread > 0 && (
                  <span
                    style={{
                      position: 'absolute',
                      top: 4,
                      right: 4,
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: 'var(--red)',
                      boxShadow: '0 0 0 2px #FFF'
                    }}
                  />
                )}
              </Link>
            )}

            {/* Role Chip */}
            <span className="badge ok">{user?.role}</span>
          </div>
        </header>

        {/* Page View Container */}
        <main className="page" style={{ flex: 1, width: '100%' }}>
          {children}
        </main>
      </div>

      {/* Interactive Command Palette Modal */}
      {cmdOpen && (
        <CommandPalette
          close={() => setCmdOpen(false)}
          admin={adminMode}
        />
      )}
    </div>
  );
}

function CommandPalette({ close, admin: adminMode }: { close: () => void; admin: boolean }) {
  const nav = useNavigate();
  const [query, setQuery] = useState('');
  const items = (adminMode ? adminNav : invNav)
    .flatMap((x: any) => x[1])
    .map((x: any) => ({ label: x[0], path: x[1], icon: x[2] }))
    .filter((item) => item.label.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="modal" onClick={close}>
      <div className="modal-card glass" onClick={(e) => e.stopPropagation()} style={{ padding: 20, maxWidth: 540 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
          <I.Search size={18} className="muted" />
          <input
            autoFocus
            className="input"
            style={{ border: 'none', boxShadow: 'none', padding: '4px 0', fontSize: 15 }}
            placeholder="Type a module or workspace name..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') close();
              if (e.key === 'Enter' && items.length > 0) {
                nav(items[0].path);
                close();
              }
            }}
          />
          <kbd style={{ fontSize: 11, padding: '2px 6px', background: 'var(--bg-subtle)', borderRadius: 4, border: '1px solid var(--border)' }}>ESC</kbd>
        </div>

        <div style={{ marginTop: 12, maxHeight: 360, overflowY: 'auto' }}>
          {items.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.path}
                className="btn ghost"
                style={{
                  width: '100%',
                  justifyContent: 'space-between',
                  padding: '10px 12px',
                  borderRadius: 8,
                  marginBottom: 4,
                  fontSize: 13.5
                }}
                onClick={() => {
                  nav(item.path);
                  close();
                }}
              >
                <span style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <Icon size={16} className="muted" />
                  <b>{item.label}</b>
                </span>
                <I.ArrowRight size={14} className="muted" />
              </button>
            );
          })}
          {items.length === 0 && (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              No matching modules found.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

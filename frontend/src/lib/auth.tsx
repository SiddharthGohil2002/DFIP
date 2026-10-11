import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, ApiError, deviceId, health, post, session } from './api';
import { IS_DESKTOP, hasNativeRuntime, native } from './platform';
import type { User } from './types';

interface AuthState {
  user: User | null;
  ready: boolean;
  /** True after the user signed out in this session, until the next sign-in. */
  signedOut: boolean;
  login: (email: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
  /** Mirrors the server's RBAC check; the server enforces it regardless. */
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

// Permissions that change data. When the server runs with REQUIRE_DESKTOP_FOR_WRITES,
// the web portal is read-only and hides these actions.
const WRITE_PERMISSIONS = new Set([
  'CASE_CREATE', 'CASE_UPDATE', 'LEGAL_HOLD_MANAGE', 'EVIDENCE_UPLOAD', 'EVIDENCE_VERIFY', 'EVIDENCE_DELETE', 'ANALYSIS_RUN', 'FINDING_CREATE', 'REPORT_CREATE', 'JOB_CANCEL',
]);

/** Desktop only: registers this workstation so the server can attribute (and, if configured, require) desktop writes. */
async function registerWorkstation() {
  let name = 'DFIP desktop';
  let os = 'unknown';
  if (hasNativeRuntime()) {
    try {
      const info = await native.systemInfo();
      name = info.hostname || name;
      os = info.os || os;
    } catch {
      /* system info is optional */
    }
  }
  const id = deviceId();
  const res = await post<{ device_token: string }>('/desktop/register', {
    device_id: id,
    device_name: name,
    app_version: import.meta.env.VITE_APP_VERSION || '2.1.0',
    os,
  });
  if (res?.device_token) session.setDevice(id, res.device_token);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);
  const [signedOut, setSignedOut] = useState(false);
  const [webReadOnly, setWebReadOnly] = useState(false);

  useEffect(() => {
    if (!IS_DESKTOP) health().then((h) => setWebReadOnly(!!h.require_desktop_for_writes)).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!session.hasToken()) {
      setReady(true);
      return;
    }
    api<User>('/auth/me')
      .then(setUser)
      // Only a rejected token ends the session; an unreachable or restarting server keeps it for the next try.
      .catch((e) => {
        if (!(e instanceof ApiError) || (e.status > 0 && e.status < 500)) session.clear();
      })
      .finally(() => setReady(true));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const r = await post<{ access_token: string; refresh_token: string; user: User }>('/auth/login', {
      email: email.trim(),
      password,
      client: IS_DESKTOP ? 'desktop' : 'web',
    });
    session.set(r.access_token, r.refresh_token);
    if (IS_DESKTOP) await registerWorkstation().catch(() => undefined);
    setSignedOut(false);
    setUser(r.user);
    return r.user;
  }, []);

  const logout = useCallback(async () => {
    const rt = session.refreshToken();
    if (rt) await post('/auth/logout', { refresh_token: rt }).catch(() => undefined);
    session.clear();
    setSignedOut(true);
    setUser(null);
  }, []);

  const can = useCallback(
    (permission: string) =>
      !!user &&
      !(webReadOnly && WRITE_PERMISSIONS.has(permission)) &&
      (user.role === 'ADMIN' || (user.permissions || []).includes(permission)),
    [user, webReadOnly],
  );

  const value = useMemo(() => ({ user, ready, signedOut, login, logout, can }), [user, ready, signedOut, login, logout, can]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}

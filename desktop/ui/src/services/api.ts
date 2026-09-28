export function getServerBaseUrl(): string {
  if (typeof window !== 'undefined') {
    const custom = localStorage.getItem('dfip_server_url');
    if (custom) return custom.replace(/\/+$/, '');
  }
  if (import.meta.env.VITE_API_URL) {
    return (import.meta.env.VITE_API_URL as string).replace(/\/+$/, '');
  }
  // If running inside Tauri or Vite desktop dev port (1420), route directly to local FastAPI server on 8000
  if (typeof window !== 'undefined') {
    const isDesktopTauri = Boolean((window as any).__TAURI_INTERNALS__);
    const isDesktopDev = window.location.port === '1420';
    if (isDesktopTauri || isDesktopDev) {
      return 'http://127.0.0.1:8000/api';
    }
  }
  return '/api';
}

export function setServerBaseUrl(url: string) {
  if (typeof window !== 'undefined') {
    if (url.trim()) {
      localStorage.setItem('dfip_server_url', url.trim());
    } else {
      localStorage.removeItem('dfip_server_url');
    }
  }
}

export function getWsUrl(): string {
  const custom = typeof window !== 'undefined' ? localStorage.getItem('dfip_ws_url') : null;
  if (custom) return custom;
  if (import.meta.env.VITE_WS_URL) return import.meta.env.VITE_WS_URL as string;

  const apiBase = getServerBaseUrl();
  if (apiBase.startsWith('http://127.0.0.1:8000') || apiBase.startsWith('http://localhost:8000')) {
    return 'ws://127.0.0.1:8000/ws';
  }
  if (typeof window !== 'undefined') {
    return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';
  }
  return 'ws://127.0.0.1:8000/ws';
}

export async function checkServerHealth(): Promise<{ ok: boolean; latencyMs: number; error?: string }> {
  const start = Date.now();
  const base = getServerBaseUrl().replace(/\/api$/, '');
  const url = `${base}/health`;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 3000);
    const res = await fetch(url, { signal: ctrl.signal });
    clearTimeout(timer);
    return { ok: res.ok, latencyMs: Date.now() - start };
  } catch (err: any) {
    return { ok: false, latencyMs: Date.now() - start, error: String(err) };
  }
}

let refreshing: Promise<boolean> | null = null;
async function refresh() {
  const rt = localStorage.getItem('dfip_refresh');
  if (!rt) return false;
  const API = getServerBaseUrl();
  if (!refreshing) {
    refreshing = fetch(API + '/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: rt }),
    })
      .then(async (r) => {
        if (!r.ok) return false;
        const x = await r.json();
        localStorage.setItem('dfip_token', x.access_token);
        localStorage.setItem('dfip_refresh', x.refresh_token);
        return true;
      })
      .catch(() => false)
      .finally(() => {
        refreshing = null;
      });
  }
  return refreshing;
}

export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const API = getServerBaseUrl();
  const token = localStorage.getItem('dfip_token');
  const deviceId = localStorage.getItem('dfip_device_id');
  const deviceToken = localStorage.getItem('dfip_device_token');
  const headers = new Headers(options.headers);
  if (!(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (deviceId) headers.set('X-DFIP-Device-Id', deviceId);
  if (deviceToken) headers.set('X-DFIP-Device-Token', deviceToken);

  let r = await fetch(API + path, { ...options, headers });
  if (r.status === 401 && (await refresh())) {
    const h = new Headers(options.headers);
    if (!(options.body instanceof FormData)) h.set('Content-Type', 'application/json');
    h.set('Authorization', `Bearer ${localStorage.getItem('dfip_token')}`);
    if (deviceId) h.set('X-DFIP-Device-Id', deviceId);
    if (deviceToken) h.set('X-DFIP-Device-Token', deviceToken);
    r = await fetch(API + path, { ...options, headers: h });
  }
  if (!r.ok) {
    const e = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(e.detail || e.error?.message || 'Request failed');
  }
  return r.status === 204 ? (undefined as any) : ((await r.json()) as T);
}

export async function uploadEvidence(form: FormData) {
  const API = getServerBaseUrl();
  const token = localStorage.getItem('dfip_token');
  const deviceId = localStorage.getItem('dfip_device_id');
  const deviceToken = localStorage.getItem('dfip_device_token');
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (deviceId) headers['X-DFIP-Device-Id'] = deviceId;
  if (deviceToken) headers['X-DFIP-Device-Token'] = deviceToken;

  const r = await fetch(API + '/evidence/upload', {
    method: 'POST',
    headers,
    body: form,
  });
  if (!r.ok) throw new Error((await r.json()).detail || 'Upload failed');
  return r.json();
}

export async function downloadReport(id: string) {
  const API = getServerBaseUrl();
  const r = await fetch(API + '/reports/' + encodeURIComponent(id) + '/download', {
    headers: { Authorization: `Bearer ${localStorage.getItem('dfip_token') || ''}` },
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({ detail: 'Download failed' }))).detail || 'Download failed');
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = id + '.pdf';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function downloadDesktopApp(format: 'exe' | 'zip' = 'exe') {
  const filename = format === 'exe' ? 'DFIP-Investigator-Windows-x64.exe' : 'DFIP-Investigator-v1.0.0-Windows-x64.zip';
  const a = document.createElement('a');
  a.href = `/downloads/${filename}`;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

export const WS = getWsUrl();



import { IS_DESKTOP } from './platform';

const TOKEN = 'dfip_token';
const REFRESH = 'dfip_refresh';
const SERVER = 'dfip_server';
const DEVICE_ID = 'dfip_device_id';
const DEVICE_TOKEN = 'dfip_device_token';

export const DEFAULT_DESKTOP_SERVER = 'http://localhost:8000';

/** Origin of the DFIP server. Web: same origin (nginx proxies /api). Desktop: configurable. */
export function serverUrl(): string {
  if (!IS_DESKTOP) return ((import.meta.env.VITE_API_ORIGIN as string | undefined) || '').replace(/\/+$/, '');
  return (localStorage.getItem(SERVER) || DEFAULT_DESKTOP_SERVER).replace(/\/+$/, '');
}

export function setServerUrl(url: string) {
  const clean = url.trim().replace(/\/+$/, '');
  if (clean) localStorage.setItem(SERVER, clean);
  else localStorage.removeItem(SERVER);
}

const apiBase = () => serverUrl() + '/api';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const session = {
  hasToken: () => Boolean(localStorage.getItem(TOKEN)),
  refreshToken: () => localStorage.getItem(REFRESH),
  set(access: string, refresh: string) {
    localStorage.setItem(TOKEN, access);
    localStorage.setItem(REFRESH, refresh);
  },
  clear() {
    localStorage.removeItem(TOKEN);
    localStorage.removeItem(REFRESH);
    localStorage.removeItem(DEVICE_TOKEN);
  },
  setDevice(id: string, token: string) {
    localStorage.setItem(DEVICE_ID, id);
    localStorage.setItem(DEVICE_TOKEN, token);
  },
};

export function deviceId(): string {
  let id = localStorage.getItem(DEVICE_ID);
  if (!id) {
    id = `DFIP-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
    localStorage.setItem(DEVICE_ID, id);
  }
  return id;
}

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = {};
  const token = localStorage.getItem(TOKEN);
  if (token) h.Authorization = `Bearer ${token}`;
  // A registered desktop workstation identifies itself so servers running with
  // REQUIRE_DESKTOP_FOR_WRITES=true accept its writes.
  if (IS_DESKTOP) {
    const id = localStorage.getItem(DEVICE_ID);
    const dt = localStorage.getItem(DEVICE_TOKEN);
    if (id && dt) {
      h['X-DFIP-Device-Id'] = id;
      h['X-DFIP-Device-Token'] = dt;
    }
  }
  return h;
}

let refreshing: Promise<boolean> | null = null;
function refreshSession(): Promise<boolean> {
  const rt = localStorage.getItem(REFRESH);
  if (!rt) return Promise.resolve(false);
  refreshing ??= fetch(apiBase() + '/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: rt }),
  })
    .then(async (r) => {
      if (!r.ok) return false;
      const x = await r.json();
      session.set(x.access_token, x.refresh_token);
      return true;
    })
    .catch(() => false)
    .finally(() => {
      refreshing = null;
    });
  return refreshing;
}

async function errorFrom(r: Response): Promise<ApiError> {
  const body = await r.json().catch(() => null);
  const detail = body?.detail;
  const message = typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map((d: any) => d.msg).join('; ') : r.statusText;
  return new ApiError(r.status, message || `Request failed (${r.status})`);
}

async function authedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const run = () => {
    const headers = new Headers(init.headers);
    Object.entries(authHeaders()).forEach(([k, v]) => headers.set(k, v));
    if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    return fetch(apiBase() + path, { ...init, headers });
  };
  let r: Response;
  try {
    r = await run();
  } catch {
    throw new ApiError(0, `Cannot reach the DFIP server at ${serverUrl() || window.location.origin}`);
  }
  if (r.status === 401 && path !== '/auth/login' && (await refreshSession())) r = await run();
  return r;
}

/** JSON API call. `json` is sent as the request body. */
export async function api<T = any>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const { json, ...rest } = init;
  const r = await authedFetch(path, json === undefined ? rest : { ...rest, body: JSON.stringify(json) });
  if (!r.ok) throw await errorFrom(r);
  return r.status === 204 ? (undefined as T) : ((await r.json()) as T);
}

export const post = <T = any>(path: string, json?: unknown) => api<T>(path, { method: 'POST', json });
export const patch = <T = any>(path: string, json?: unknown) => api<T>(path, { method: 'PATCH', json });

/** Uploads an evidence image with progress (XHR: fetch has no upload progress). */
export function uploadEvidence(caseId: string, file: File, onProgress: (fraction: number) => void): Promise<any> {
  const send = (): Promise<{ status: number; body: any }> =>
    new Promise((resolve, reject) => {
      const form = new FormData();
      form.append('case_id', caseId);
      form.append('file', file);
      const xhr = new XMLHttpRequest();
      xhr.open('POST', apiBase() + '/evidence/upload');
      Object.entries(authHeaders()).forEach(([k, v]) => xhr.setRequestHeader(k, v));
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
      xhr.onload = () => {
        let body: any = null;
        try {
          body = JSON.parse(xhr.responseText);
        } catch {
          /* non-JSON error page */
        }
        resolve({ status: xhr.status, body });
      };
      xhr.onerror = () => reject(new ApiError(0, 'Upload failed: the server could not be reached'));
      xhr.send(form);
    });
  return send().then(async (res) => {
    if (res.status === 401 && (await refreshSession())) res = await send();
    if (res.status < 200 || res.status >= 300) throw new ApiError(res.status, res.body?.detail || `Upload failed (${res.status})`);
    return res.body;
  });
}

/** Downloads an authenticated file and saves it under `filename`. Returns the server-recorded SHA-256, if sent. */
export async function downloadFile(path: string, filename: string): Promise<string | null> {
  const r = await authedFetch(path);
  if (!r.ok) throw await errorFrom(r);
  const sha = r.headers.get('X-DFIP-SHA256') || r.headers.get('X-DFIP-Report-SHA256');
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  return sha;
}

export interface Health {
  status: string;
  database: string;
  version?: string;
  demo_mode?: boolean;
  require_desktop_for_writes?: boolean;
}

export async function health(base = serverUrl()): Promise<Health> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const r = await fetch(base.replace(/\/+$/, '') + '/health', { signal: ctrl.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return (await r.json()) as Health;
  } finally {
    clearTimeout(timer);
  }
}

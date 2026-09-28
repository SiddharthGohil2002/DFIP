import { api } from '../api';

const DEVICE_ID_KEY = 'dfip_device_id';
const DEVICE_NAME_KEY = 'dfip_device_name';

export function getDeviceId(): string {
  let id = localStorage.getItem(DEVICE_ID_KEY);
  if (!id) {
    id = `DFIP-${Math.random().toString(36).slice(2, 10).toUpperCase()}-${Date.now().toString(36).toUpperCase()}`;
    localStorage.setItem(DEVICE_ID_KEY, id);
  }
  return id;
}

export function getDeviceName(): string {
  return localStorage.getItem(DEVICE_NAME_KEY) || `DFIP-WORKSTATION-${getDeviceId().slice(5, 13)}`;
}

export async function registerDevice() {
  const deviceId = getDeviceId();
  const deviceName = getDeviceName();
  let os = 'unknown';
  try {
    const n = await import('../../native');
    const info = await n.nativeSystemInfo();
    os = info?.os || 'windows';
  } catch {}
  return api<any>('/desktop/register', {
    method: 'POST',
    body: JSON.stringify({
      device_id: deviceId,
      device_name: deviceName,
      app_version: '1.0.0',
      os,
    }),
  });
}

export async function sendHeartbeat() {
  const deviceId = getDeviceId();
  return api<any>(`/desktop/heartbeat?device_id=${encodeURIComponent(deviceId)}`, { method: 'POST' });
}

export async function getDeviceStatus() {
  return api<{
    devices: any[];
    online_count: number;
    is_online: boolean;
    pending_desktop_jobs: number;
  }>('/desktop/status');
}

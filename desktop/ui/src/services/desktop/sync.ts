import { api } from '../api';
import { getDeviceId } from './device';

const OFFLINE_QUEUE_KEY = 'dfip_offline_queue';

export interface OfflineRecord {
  record_type: 'finding' | 'custody_event' | 'audit_event' | 'case_update';
  record_id: string;
  case_id?: string;
  data: any;
  local_created_at: string;
  local_modified_at: string;
  sync_status: 'LOCAL_ONLY' | 'PENDING_SYNC' | 'SYNCING' | 'SYNCED' | 'SYNC_CONFLICT' | 'SYNC_FAILED';
}

export function getOfflineQueue(): OfflineRecord[] {
  try {
    return JSON.parse(localStorage.getItem(OFFLINE_QUEUE_KEY) || '[]');
  } catch {
    return [];
  }
}

export function addToOfflineQueue(record: Omit<OfflineRecord, 'sync_status'>) {
  const q = getOfflineQueue();
  q.push({ ...record, sync_status: 'PENDING_SYNC' });
  localStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(q));
}

export function clearSyncedRecords() {
  const q = getOfflineQueue().filter((r) => r.sync_status !== 'SYNCED');
  localStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(q));
}

export async function pushOfflineData(): Promise<{ synced: number; conflicts: number; failed: number }> {
  const q = getOfflineQueue().filter((r) => r.sync_status === 'PENDING_SYNC');
  if (!q.length) return { synced: 0, conflicts: 0, failed: 0 };

  const res = await api<{ results: { record_id: string; status: string; error?: string }[] }>(
    '/desktop/sync/push',
    {
      method: 'POST',
      body: JSON.stringify({ device_id: getDeviceId(), records: q }),
    }
  );

  const statusMap = new Map(res.results.map((r) => [r.record_id, r.status]));
  const all = getOfflineQueue();
  for (const rec of all) {
    if (statusMap.has(rec.record_id)) {
      const s = statusMap.get(rec.record_id)!;
      rec.sync_status = s as OfflineRecord['sync_status'];
    }
  }
  localStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(all));

  return {
    synced: res.results.filter((r) => r.status === 'SYNCED').length,
    conflicts: res.results.filter((r) => r.status === 'SYNC_CONFLICT').length,
    failed: res.results.filter((r) => r.status === 'SYNC_FAILED').length,
  };
}

export async function pullLatest(since?: string) {
  const url = since ? `/desktop/sync/pull?since=${encodeURIComponent(since)}` : '/desktop/sync/pull';
  return api<{
    pull_timestamp: string;
    cases: any[];
    evidence: any[];
    jobs: any[];
    findings: any[];
    notifications: any[];
  }>(url);
}

export async function claimJob(jobId: string) {
  return api<any>(`/desktop/jobs/${jobId}/claim?device_id=${encodeURIComponent(getDeviceId())}`, { method: 'POST' });
}

export async function completeJob(jobId: string, result: any, summary?: string) {
  return api<any>(`/desktop/jobs/${jobId}/complete`, {
    method: 'POST',
    body: JSON.stringify({ result, summary }),
  });
}

export async function failJob(jobId: string, error: string, traceback?: string) {
  return api<any>(`/desktop/jobs/${jobId}/fail`, {
    method: 'POST',
    body: JSON.stringify({ error, traceback }),
  });
}

export async function getDesktopJobs() {
  return api<{ data: any[] }>('/desktop/jobs');
}

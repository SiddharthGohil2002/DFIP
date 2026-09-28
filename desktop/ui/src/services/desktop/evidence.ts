import { api } from '../api';

// These functions only work in the desktop (Tauri) environment.
// Importing native functions conditionally to avoid errors in the web build.
async function getNative() {
  try {
    return await import('../../native');
  } catch {
    return null;
  }
}

export async function hashLocalFile(path: string): Promise<{
  algorithm: string;
  sha256: string;
  bytes: number;
}> {
  const n = await getNative();
  if (!n) throw new Error('Native operations are only available in the DFIP Desktop application.');
  return n.nativeHashFile(path);
}

export async function copyEvidence(source: string, destination: string): Promise<{
  source: string;
  destination: string;
  sha256: string;
  bytes: number;
  readonly: boolean;
}> {
  const n = await getNative();
  if (!n) throw new Error('Native operations are only available in the DFIP Desktop application.');
  return n.nativeCopyEvidence(source, destination);
}

export async function setReadOnly(path: string): Promise<boolean> {
  const n = await getNative();
  if (!n) throw new Error('Native operations are only available in the DFIP Desktop application.');
  return n.nativeReadonly(path);
}

export async function listDirectory(path: string, recursive = false) {
  const n = await getNative();
  if (!n) throw new Error('Native operations are only available in the DFIP Desktop application.');
  return n.nativeListDirectory(path, recursive);
}

export async function registerEvidenceWithBackend(data: {
  case_id: string;
  filename: string;
  format: string;
  size: number;
  sha256: string;
  local_path: string;
  device_id: string;
  acquisition_timestamp: string;
}) {
  return api<any>('/desktop/sync/push', {
    method: 'POST',
    body: JSON.stringify({
      device_id: data.device_id,
      records: [{
        record_type: 'custody_event',
        record_id: `acq-${Date.now()}`,
        case_id: data.case_id,
        data: {
          evidence_id: null,
          case_id: data.case_id,
          action: 'EVIDENCE_ACQUIRED',
          sha256: data.sha256,
          filename: data.filename,
          format: data.format,
          size: data.size,
          local_path: data.local_path,
          device_id: data.device_id,
          timestamp: data.acquisition_timestamp,
        },
        local_created_at: data.acquisition_timestamp,
        local_modified_at: data.acquisition_timestamp,
        device_id: data.device_id,
      }],
    }),
  });
}

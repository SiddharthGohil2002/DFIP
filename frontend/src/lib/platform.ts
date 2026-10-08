/**
 * Build target and desktop-only capabilities.
 *
 * The same UI is built twice (see vite.config.ts): the web portal, and the
 * desktop app that runs inside the Tauri shell (desktop/src-tauri). Native
 * commands exist only in that shell; in a browser they reject with a clear error.
 */
export const IS_DESKTOP = import.meta.env.VITE_TARGET === 'desktop';

export interface WorkstationInfo {
  app: string;
  version: string;
  os: string;
  arch: string;
  hostname: string;
  cpu_cores: string;
}

export interface LocalHash {
  algorithm: string;
  sha256: string;
  sha512: string;
  bytes: number;
  elapsed_ms: number;
}

export interface LocalTool {
  name: string;
  path: string | null;
  available: boolean;
  version?: string;
  hint: string;
}

/** True only inside the Tauri desktop shell, where native commands are available. */
export function hasNativeRuntime(): boolean {
  return IS_DESKTOP && typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

async function invokeNative<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!hasNativeRuntime()) throw new Error('This action needs the DFIP desktop application.');
  const { invoke } = await import('@tauri-apps/api/core');
  try {
    return await invoke<T>(command, args);
  } catch (err) {
    throw new Error(typeof err === 'string' ? err : (err as Error)?.message || `Native command ${command} failed`);
  }
}

export const native = {
  systemInfo: () => invokeNative<WorkstationInfo>('system_info'),
  /** Streams a local file through SHA-256/SHA-512 on the workstation (no upload). */
  hashFile: (path: string) => invokeNative<LocalHash>('hash_file', { path }),
  toolInventory: () => invokeNative<LocalTool[]>('tool_inventory'),
};

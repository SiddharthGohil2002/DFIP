import { invoke } from '@tauri-apps/api/core';

export const isDesktop = true;

async function executeNative<T>(cmd: string, args?: Record<string, any>): Promise<T> {
  if (typeof window !== 'undefined' && Boolean((window as any).__TAURI_INTERNALS__)) {
    try {
      return await invoke<T>(cmd, args);
    } catch (err: any) {
      throw new Error(`Native forensic command '${cmd}' failed: ${err?.message || err}`);
    }
  }
  throw new Error(`Native forensic operation '${cmd}' requires the authorized DFIP Desktop application runtime.`);
}

export async function nativeSystemInfo() {
  return executeNative<{
    app: string;
    version: string;
    os: string;
    arch: string;
    hostname: string;
    cpu_cores: string;
    timestamp: number;
  }>('system_info');
}

export async function nativeHashFile(path: string) {
  if (!path) throw new Error('Path is required for file hashing');
  return executeNative<{
    algorithm: string;
    sha256: string;
    sha512: string;
    bytes: number;
    elapsed_ms: number;
  }>('hash_file', { path });
}

export async function nativeCopyEvidence(source: string, destination: string) {
  if (!source || !destination) throw new Error('Source and destination paths are required');
  return executeNative<{
    source: string;
    destination: string;
    sha256: string;
    sha512: string;
    bytes: number;
    readonly: boolean;
    elapsed_ms: number;
  }>('copy_evidence', { source, destination });
}

export async function nativeListDirectory(path: string, recursive = false) {
  if (!path) throw new Error('Directory path is required');
  return executeNative<Array<{
    path: string;
    size: number;
    modified: number;
    is_dir: boolean;
  }>>('list_directory', { path, recursive });
}

export async function nativeToolInventory() {
  return executeNative<Array<{
    name: string;
    path: string | null;
    available: boolean;
    version?: string;
    hint: string;
  }>>('tool_inventory');
}

export async function nativeRunTool(tool: string, args: string[], timeout_seconds = 60) {
  if (!tool) throw new Error('Tool identifier is required');
  return executeNative<{
    tool: string;
    success: boolean;
    code: number | null;
    stdout: string;
    stderr: string;
    timed_out: boolean;
    duration_ms: number;
    timeout_seconds: number;
  }>('run_forensic_tool', { req: { tool, args, timeout_seconds } });
}

export async function nativeReadonly(path: string) {
  if (!path) throw new Error('Path is required');
  return executeNative<boolean>('set_readonly', { path });
}

export async function nativeDataDir() {
  return executeNative<string>('app_data_dir');
}

export async function nativeCreateCase(name: string) {
  if (!name) throw new Error('Case name is required');
  return executeNative<{
    case_id: string;
    name: string;
    created_at: number;
    mode: string;
    workspace_path: string;
  }>('create_local_case', { name });
}

export async function nativeListCases() {
  return executeNative<Array<{
    case_id: string;
    name: string;
    created_at: number;
    mode: string;
    workspace_path?: string;
  }>>('list_local_cases');
}

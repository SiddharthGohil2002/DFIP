// Web build: native Tauri operations are not available.
export const isDesktop = false;
// Server-side writes are allowed from the web unless the backend runs with REQUIRE_DESKTOP_FOR_WRITES=true.
export const canWrite = import.meta.env.VITE_REQUIRE_DESKTOP_FOR_WRITES !== 'true';
export async function nativeSystemInfo(): Promise<any> { throw new Error('Desktop only'); }
export async function nativeHashFile(_path: string): Promise<any> { throw new Error('Desktop only'); }
export async function nativeCopyEvidence(_source: string, _destination: string): Promise<any> { throw new Error('Desktop only'); }
export async function nativeListDirectory(_path: string, _recursive?: boolean): Promise<any> { throw new Error('Desktop only'); }
export async function nativeToolInventory(): Promise<any[]> { throw new Error('Desktop only'); }
export async function nativeRunTool(_tool: string, _args: string[], _timeout?: number): Promise<any> { throw new Error('Desktop only'); }
export async function nativeReadonly(_path: string): Promise<boolean> { throw new Error('Desktop only'); }
export async function nativeDataDir(): Promise<string> { throw new Error('Desktop only'); }
export async function nativeCreateCase(_name: string): Promise<any> { throw new Error('Desktop only'); }
export async function nativeListCases(): Promise<any[]> { return []; }

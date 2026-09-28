const ALLOWED_TOOLS = new Set(['fls', 'istat', 'fsstat', 'mmls', 'icat', 'exiftool', 'tshark', 'yara', 'vol', 'strings', 'file']);

async function getNative() {
  try { return await import('../../native'); } catch { return null; }
}

export async function toolInventory() {
  const n = await getNative();
  if (!n) throw new Error('Tool inventory is only available in the DFIP Desktop application.');
  return n.nativeToolInventory();
}

export async function runTool(
  tool: string,
  args: string[],
  timeoutSeconds = 60
): Promise<{ tool: string; success: boolean; stdout: string; stderr: string; timed_out: boolean; code?: number }> {
  if (!ALLOWED_TOOLS.has(tool)) {
    throw new Error(`Tool '${tool}' is not on the DFIP allow-list. Allowed: ${[...ALLOWED_TOOLS].join(', ')}`);
  }
  const n = await getNative();
  if (!n) throw new Error('Forensic tool execution is only available in the DFIP Desktop application.');
  const res: any = await n.nativeRunTool(tool, args, timeoutSeconds);
  return {
    tool: res.tool || tool,
    success: res.success ?? (res.exit_code === 0 || res.code === 0),
    timed_out: res.timed_out ?? false,
    code: res.code ?? res.exit_code ?? 0,
    stdout: res.stdout || '',
    stderr: res.stderr || ''
  };
}

export { ALLOWED_TOOLS };

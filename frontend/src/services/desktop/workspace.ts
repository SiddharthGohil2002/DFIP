async function getNative() {
  try { return await import('../../native'); } catch { return null; }
}

export async function createLocalCase(name: string) {
  const n = await getNative();
  if (!n) throw new Error('Local case creation is only available in the DFIP Desktop application.');
  return n.nativeCreateCase(name);
}

export async function listLocalCases() {
  const n = await getNative();
  if (!n) return [];
  return n.nativeListCases();
}

export async function getDataDir(): Promise<string> {
  const n = await getNative();
  if (!n) throw new Error('Data directory is only available in the DFIP Desktop application.');
  return n.nativeDataDir();
}

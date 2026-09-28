import React, { useCallback, useEffect, useRef, useState } from 'react';
import * as I from 'lucide-react';
import { isDesktop, nativeSystemInfo } from '../native';
import { hashLocalFile, copyEvidence, setReadOnly, listDirectory } from '../services/desktop/evidence';
import { toolInventory, runTool, ALLOWED_TOOLS } from '../services/desktop/forensicTools';
import { createLocalCase, listLocalCases, getDataDir } from '../services/desktop/workspace';
import { registerDevice, sendHeartbeat, getDeviceStatus, getDeviceId, getDeviceName } from '../services/desktop/device';
import { getOfflineQueue, pushOfflineData, clearSyncedRecords, getDesktopJobs } from '../services/desktop/sync';
import { startJobAgent, stopJobAgent } from '../services/desktop/jobAgent';
import { checkServerHealth } from '../services/api';

// ─── Primitives ──────────────────────────────────────────────────────────────
const Card = ({ children, style, className = '' }: { children: any; style?: any; className?: string }) => (
  <div className={`card ${className}`} style={{ borderRadius: 'var(--radius)', ...style }}>{children}</div>
);
const Btn = ({ children, onClick, primary = false, danger = false, ghost = false, sm = false, disabled = false, style }: any) => (
  <button className={`btn ${primary ? 'primary' : ''} ${danger ? 'danger' : ''} ${ghost ? 'ghost' : ''} ${sm ? 'sm' : ''}`}
    onClick={onClick} disabled={disabled} style={style}>{children}</button>
);
const Badge = ({ children, cls = 'badge' }: { children: any; cls?: string }) => <span className={cls}>{children}</span>;

const TOOL_PRESETS: Record<string, { label: string; args: string; desc: string }[]> = {
  fls:      [{ label: 'Recursive List', args: '-r -p', desc: 'List all files and directories recursively with path prefixes' },
             { label: 'Deleted Only', args: '-r -d', desc: 'Show deleted/unallocated inode entries only' }],
  mmls:     [{ label: 'Partition Layout', args: '-B', desc: 'Show partition table with sector offsets' }],
  fsstat:   [{ label: 'Filesystem Details', args: '', desc: 'Show file system structure and metadata parameters' }],
  istat:    [{ label: 'Inode Info', args: '', desc: 'Display inode metadata (provide inode number as arg)' }],
  icat:     [{ label: 'Extract File', args: '', desc: 'Extract file content by inode (pipe to output file)' }],
  exiftool: [{ label: 'All Metadata', args: '-all', desc: 'Extract all embedded EXIF, XMP, IPTC metadata' }],
  strings:  [{ label: 'ASCII Strings (8+)', args: '-a -n 8', desc: 'Extract printable ASCII strings ≥8 characters' }],
  file:     [{ label: 'Magic Detection', args: '-b', desc: 'Identify file type without prepending filename' }],
  tshark:   [{ label: 'Packet Summary', args: '-c 50', desc: 'Read first 50 packets with protocol breakdown' }],
  yara:     [{ label: 'Scan Target', args: '-s', desc: 'Scan evidence and print matching strings' }],
  vol:      [{ label: 'Image Info', args: 'imageinfo', desc: 'Identify memory image profile' }],
};

type Tab = 'acquisition' | 'analysis' | 'workspace' | 'status';

// ─── Main Component ───────────────────────────────────────────────────────────
export default function DesktopOperations() {
  const [tab, setTab] = useState<Tab>('acquisition');

  if (!isDesktop) {
    return (
      <div className="fade">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 16, marginBottom: 24 }}>
          <div>
            <div className="eyebrow" style={{ marginBottom: 6 }}>DFIP / DESKTOP OPERATIONS</div>
            <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.02em', margin: 0 }}>Desktop Workstation</h1>
            <div className="muted" style={{ fontSize: 13.5, marginTop: 4 }}>Local forensic operations require the DFIP Desktop application.</div>
          </div>
        </div>
        <Card style={{ padding: 40, textAlign: 'center', border: '1.5px dashed var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 20 }}>
            <div style={{ width: 64, height: 64, borderRadius: 999, background: 'var(--bg-subtle)', display: 'grid', placeItems: 'center', color: 'var(--ink-light)' }}>
              <I.Monitor size={30} />
            </div>
          </div>
          <div style={{ fontWeight: 800, fontSize: 18, marginBottom: 8 }}>DFIP Desktop Application Required</div>
          <div className="muted" style={{ fontSize: 14, marginBottom: 24, maxWidth: 480, margin: '0 auto 24px' }}>
            Desktop Operations provide direct access to local forensic workstation capabilities:
            evidence acquisition, native forensic tools (mmls, fls, YARA, Volatility), local filesystem
            access, and offline investigation support.
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, maxWidth: 600, margin: '0 auto 28px', textAlign: 'left' }}>
            {[
              ['Evidence Acquisition', I.HardDrive],
              ['Local Hash Computation', I.Hash],
              ['Forensic Tool Runner', I.Terminal],
              ['Offline Case Workspace', I.FolderOpen],
              ['Device Synchronization', I.RefreshCw],
              ['Evidence Preservation', I.Lock],
            ].map(([label, Icon]: any) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8, fontSize: 13 }}>
                <Icon size={15} color="var(--muted)" /> {label}
              </div>
            ))}
          </div>
          <a href="/download" className="btn primary" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <I.Download size={15} /> Download DFIP Desktop
          </a>
        </Card>
      </div>
    );
  }

  const tabs: { id: Tab; label: string; icon: any }[] = [
    { id: 'acquisition', label: 'Acquisition', icon: I.HardDrive },
    { id: 'analysis',    label: 'Analysis',    icon: I.Terminal },
    { id: 'workspace',   label: 'Workspace',   icon: I.FolderOpen },
    { id: 'status',      label: 'Status',      icon: I.Activity },
  ];

  return (
    <div className="fade">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 16, marginBottom: 24 }}>
        <div>
          <div className="eyebrow" style={{ marginBottom: 6 }}>DFIP / DESKTOP OPERATIONS</div>
          <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.02em', margin: 0 }}>Desktop Workstation</h1>
          <div className="muted" style={{ fontSize: 13.5, marginTop: 4 }}>Local forensic operations — running on the investigator's workstation.</div>
        </div>
        <span className="badge ok" style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <I.Monitor size={12} /> DFIP Desktop Active
        </span>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, borderBottom: '1px solid var(--border)', paddingBottom: 0 }}>
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '9px 18px',
              fontSize: 13.5, fontWeight: 600, border: 'none', background: 'transparent', cursor: 'pointer',
              borderBottom: tab === id ? '2px solid var(--red)' : '2px solid transparent',
              color: tab === id ? 'var(--ink)' : 'var(--muted)',
            }}
          >
            <Icon size={14} /> {label}
          </button>
        ))}
      </div>

      {tab === 'acquisition' && <AcquisitionTab />}
      {tab === 'analysis' && <AnalysisTab />}
      {tab === 'workspace' && <WorkspaceTab />}
      {tab === 'status' && <StatusTab />}
    </div>
  );
}

// ─── ACQUISITION TAB ─────────────────────────────────────────────────────────
function AcquisitionTab() {
  // Hash Evidence
  const [hashPath, setHashPath] = useState('');
  const [hashing, setHashing] = useState(false);
  const [hashResult, setHashResult] = useState<any>(null);
  const [hashError, setHashError] = useState('');
  const [verifyAgainst, setVerifyAgainst] = useState('');

  // Copy Evidence
  const [srcPath, setSrcPath] = useState('');
  const [dstPath, setDstPath] = useState('');
  const [copying, setCopying] = useState(false);
  const [copyResult, setCopyResult] = useState<any>(null);
  const [copyError, setCopyError] = useState('');

  // Read-only
  const [roPath, setRoPath] = useState('');
  const [roBusy, setRoBusy] = useState(false);
  const [roMsg, setRoMsg] = useState('');

  async function doHash() {
    if (!hashPath.trim()) return;
    setHashing(true); setHashError(''); setHashResult(null);
    try {
      const r = await hashLocalFile(hashPath.trim());
      setHashResult(r);
    } catch (e: any) { setHashError(e.message); }
    finally { setHashing(false); }
  }

  async function doCopy() {
    if (!srcPath.trim() || !dstPath.trim()) return;
    setCopying(true); setCopyError(''); setCopyResult(null);
    try {
      const r = await copyEvidence(srcPath.trim(), dstPath.trim());
      setCopyResult(r);
    } catch (e: any) { setCopyError(e.message); }
    finally { setCopying(false); }
  }

  async function doReadonly() {
    if (!roPath.trim()) return;
    setRoBusy(true); setRoMsg('');
    try {
      await setReadOnly(roPath.trim());
      setRoMsg(`✓ Successfully set read-only: ${roPath}`);
    } catch (e: any) { setRoMsg(`✗ Error: ${e.message}`); }
    finally { setRoBusy(false); }
  }

  const hashMatch = hashResult && verifyAgainst
    ? hashResult.sha256.toLowerCase() === verifyAgainst.trim().toLowerCase()
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Hash Evidence File */}
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.Hash size={16} /> Hash Evidence File
          <span className="badge info" style={{ fontSize: 10, marginLeft: 4 }}>SHA-256</span>
        </h3>
        <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
          <input className="input" style={{ flex: 1 }} value={hashPath}
            onChange={(e) => setHashPath(e.target.value)}
            placeholder="Full path to evidence file (e.g. D:\evidence\image.E01)" />
          <Btn primary onClick={doHash} disabled={hashing || !hashPath.trim()}>
            {hashing ? <><I.Loader size={14} /> Computing…</> : <><I.Hash size={14} /> Hash File</>}
          </Btn>
        </div>
        {hashError && <div className="badge danger" style={{ marginBottom: 10 }}>{hashError}</div>}
        {hashResult && (
          <div style={{ background: 'var(--bg-subtle)', borderRadius: 8, padding: 14, marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ fontSize: 12, fontWeight: 600 }}>SHA-256</span>
              <span className="badge ok">Computed</span>
            </div>
            <div className="mono" style={{ fontSize: 12, wordBreak: 'break-all', color: 'var(--ink)' }}>{hashResult.sha256}</div>
            <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>{(hashResult.bytes / 1e9).toFixed(3)} GB · Algorithm: {hashResult.algorithm}</div>
          </div>
        )}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <input className="input" style={{ flex: 1 }} value={verifyAgainst}
            onChange={(e) => setVerifyAgainst(e.target.value)}
            placeholder="Paste expected SHA-256 to verify" />
          {hashMatch !== null && (
            <span className={hashMatch ? 'badge ok' : 'badge danger'}>
              {hashMatch ? '✓ VERIFIED' : '✗ MISMATCH'}
            </span>
          )}
        </div>
      </Card>

      {/* Copy / Preserve Evidence */}
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.Copy size={16} /> Copy &amp; Preserve Evidence
          <span className="badge info" style={{ fontSize: 10, marginLeft: 4 }}>READ-ONLY DESTINATION</span>
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 10, marginBottom: 10 }}>
          <input className="input" value={srcPath} onChange={(e) => setSrcPath(e.target.value)}
            placeholder="Source evidence path" />
          <input className="input" value={dstPath} onChange={(e) => setDstPath(e.target.value)}
            placeholder="Destination path (must not exist)" />
          <Btn primary onClick={doCopy} disabled={copying || !srcPath.trim() || !dstPath.trim()}>
            {copying ? <><I.Loader size={14} /> Copying…</> : <><I.Copy size={14} /> Copy</>}
          </Btn>
        </div>
        <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
          Evidence copy is streamed with SHA-256 verification. Destination is automatically set read-only. Original is never modified.
        </div>
        {copyError && <div className="badge danger">{copyError}</div>}
        {copyResult && (
          <div style={{ background: 'var(--bg-subtle)', borderRadius: 8, padding: 12, marginTop: 10 }}>
            <div className="badge ok" style={{ marginBottom: 8 }}>✓ Evidence Preserved</div>
            <div className="mono" style={{ fontSize: 11 }}>SHA-256: {copyResult.sha256}</div>
            <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>Destination: {copyResult.destination} · {(copyResult.bytes / 1e9).toFixed(3)} GB · Read-only: {copyResult.readonly ? 'Yes' : 'No'}</div>
          </div>
        )}
      </Card>

      {/* Set Read-Only */}
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.Lock size={16} /> Set Evidence Read-Only
        </h3>
        <div style={{ display: 'flex', gap: 10 }}>
          <input className="input" style={{ flex: 1 }} value={roPath}
            onChange={(e) => setRoPath(e.target.value)}
            placeholder="Path to evidence file or directory" />
          <Btn primary onClick={doReadonly} disabled={roBusy || !roPath.trim()}>
            {roBusy ? <><I.Loader size={14} /> Setting…</> : <><I.Lock size={14} /> Set Read-Only</>}
          </Btn>
        </div>
        {roMsg && <div className={`badge ${roMsg.startsWith('✓') ? 'ok' : 'danger'}`} style={{ marginTop: 10, display: 'block' }}>{roMsg}</div>}
      </Card>
    </div>
  );
}

// ─── ANALYSIS TAB ─────────────────────────────────────────────────────────────
function AnalysisTab() {
  const [tools, setTools] = useState<any[]>([]);
  const [selectedTool, setSelectedTool] = useState('fls');
  const [toolArgs, setToolArgs] = useState('-r -p');
  const [timeout, setTimeout_] = useState('60');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const outputRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    toolInventory().then(setTools).catch(() => {});
  }, []);

  useEffect(() => {
    const presets = TOOL_PRESETS[selectedTool];
    if (presets?.[0]) setToolArgs(presets[0].args);
    else setToolArgs('');
  }, [selectedTool]);

  async function run() {
    setRunning(true); setError(''); setResult(null);
    try {
      const argsArr = toolArgs.split(/\s+/).filter(Boolean);
      const r = await runTool(selectedTool, argsArr, parseInt(timeout) || 60);
      setResult(r);
      setTimeout(() => outputRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    } catch (e: any) { setError(e.message); }
    finally { setRunning(false); }
  }

  const currentTool = tools.find((t) => t.name === selectedTool);
  const presets = TOOL_PRESETS[selectedTool] || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 16px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.Terminal size={16} /> Forensic Tool Runner
          <span className="badge info" style={{ fontSize: 10, marginLeft: 4 }}>ALLOW-LISTED</span>
        </h3>

        {/* Tool selector */}
        <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr 120px auto', gap: 10, marginBottom: 12 }}>
          <select className="input" value={selectedTool} onChange={(e) => setSelectedTool(e.target.value)}>
            {[...ALLOWED_TOOLS].sort().map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <input className="input" value={toolArgs} onChange={(e) => setToolArgs(e.target.value)}
            placeholder="Arguments (space-separated)" />
          <input className="input" type="number" value={timeout}
            onChange={(e) => setTimeout_(e.target.value)}
            placeholder="Timeout (s)" min="5" max="900" />
          <Btn primary onClick={run} disabled={running}>
            {running ? <><I.Loader size={14} /> Running…</> : <><I.Play size={14} /> Run</>}
          </Btn>
        </div>

        {/* Tool availability */}
        {currentTool && (
          <div style={{ fontSize: 12, marginBottom: 12 }}>
            Status:{' '}
            {currentTool.available
              ? <span className="badge ok">Available — {currentTool.path}</span>
              : <span className="badge danger">Not installed — install {selectedTool} on this workstation</span>}
          </div>
        )}

        {/* Presets */}
        {presets.length > 0 && (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
            <span className="muted" style={{ fontSize: 12, lineHeight: '26px' }}>Presets:</span>
            {presets.map((p) => (
              <button key={p.label} className="btn sm ghost" onClick={() => setToolArgs(p.args)} title={p.desc}>
                {p.label}
              </button>
            ))}
          </div>
        )}

        {error && <div className="badge danger" style={{ marginBottom: 10 }}>{error}</div>}
      </Card>

      {/* Tool Output */}
      {result && (
        <Card style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontWeight: 600, fontSize: 13 }}>
              <span className="mono">{result.tool}</span>
              {result.success
                ? <span className="badge ok" style={{ marginLeft: 8 }}>Exit 0</span>
                : <span className="badge danger" style={{ marginLeft: 8 }}>Exit {result.code}</span>}
              {result.timed_out && <span className="badge warn" style={{ marginLeft: 8 }}>Timed Out</span>}
            </div>
            <Btn sm ghost onClick={() => { navigator.clipboard.writeText(result.stdout || ''); }}>
              <I.Copy size={12} /> Copy
            </Btn>
          </div>
          <pre ref={outputRef} style={{
            margin: 0, padding: 16, fontSize: 11.5, fontFamily: 'monospace',
            background: 'var(--bg)', color: 'var(--ink)', whiteSpace: 'pre-wrap',
            wordBreak: 'break-all', maxHeight: 480, overflowY: 'auto',
            lineHeight: 1.6,
          }}>
            {result.stdout || '(no output)'}
            {result.stderr && `\n\n[STDERR]\n${result.stderr}`}
          </pre>
        </Card>
      )}

      {/* Tool inventory summary */}
      <Card style={{ padding: 18 }}>
        <h3 style={{ fontSize: 14, fontWeight: 700, margin: '0 0 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
          <I.Wrench size={14} /> Tool Availability
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 8 }}>
          {tools.map((t) => (
            <div key={t.name} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '7px 10px', background: 'var(--bg-subtle)', borderRadius: 6 }}>
              <span style={{ width: 8, height: 8, borderRadius: 999, background: t.available ? 'var(--green)' : 'var(--muted)', flexShrink: 0 }} />
              <span className="mono" style={{ fontSize: 12 }}>{t.name}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ─── WORKSPACE TAB ────────────────────────────────────────────────────────────
function WorkspaceTab() {
  const [localCases, setLocalCases] = useState<any[]>([]);
  const [newCaseName, setNewCaseName] = useState('');
  const [creating, setCreating] = useState(false);
  const [dataDir, setDataDir] = useState('');
  const [queue, setQueue] = useState<any[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState('');
  const [pendingJobs, setPendingJobs] = useState<any[]>([]);

  useEffect(() => {
    listLocalCases().then(setLocalCases).catch(() => {});
    getDataDir().then(setDataDir).catch(() => {});
    setQueue(getOfflineQueue());
    getDesktopJobs().then((r) => setPendingJobs(r.data || [])).catch(() => {});
  }, []);

  async function createCase() {
    if (!newCaseName.trim()) return;
    setCreating(true);
    try {
      await createLocalCase(newCaseName.trim());
      setNewCaseName('');
      const cases = await listLocalCases();
      setLocalCases(cases);
    } catch (e: any) { alert(e.message); }
    finally { setCreating(false); }
  }

  async function doSync() {
    setSyncing(true); setSyncMsg('');
    try {
      const r = await pushOfflineData();
      clearSyncedRecords();
      setQueue(getOfflineQueue());
      setSyncMsg(`Sync complete: ${r.synced} synced, ${r.conflicts} conflicts, ${r.failed} failed.`);
    } catch (e: any) { setSyncMsg(`Sync error: ${e.message}`); }
    finally { setSyncing(false); }
  }

  const statusColors: Record<string, string> = {
    LOCAL_ONLY: 'badge', PENDING_SYNC: 'badge warn', SYNCING: 'badge info',
    SYNCED: 'badge ok', SYNC_CONFLICT: 'badge danger', SYNC_FAILED: 'badge danger',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Local Cases */}
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.FolderOpen size={16} /> Local Cases
          <span className="badge" style={{ fontSize: 10, marginLeft: 4 }}>OFFLINE READY</span>
        </h3>
        <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
          <input className="input" style={{ flex: 1 }} value={newCaseName}
            onChange={(e) => setNewCaseName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && createCase()}
            placeholder="New local case name" />
          <Btn primary onClick={createCase} disabled={creating || !newCaseName.trim()}>
            {creating ? 'Creating…' : '+ Create Offline Case'}
          </Btn>
        </div>
        {localCases.length === 0
          ? <div className="muted" style={{ fontSize: 13, textAlign: 'center', padding: 20 }}>No local offline cases. Create one above or sync from the backend.</div>
          : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {localCases.map((c: any) => (
                <div key={c.case_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8 }}>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{c.name}</div>
                    <div className="muted mono" style={{ fontSize: 11 }}>{c.case_id}</div>
                  </div>
                  <span className="badge info" style={{ fontSize: 11 }}>{c.mode || 'LOCAL'}</span>
                </div>
              ))}
            </div>
          )
        }
        {dataDir && <div className="muted" style={{ fontSize: 11, marginTop: 12 }}>Local workspace: <span className="mono">{dataDir}</span></div>}
      </Card>

      {/* Sync Queue */}
      <Card style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 7 }}>
            <I.RefreshCw size={16} /> Offline Sync Queue
          </h3>
          <Btn sm primary onClick={doSync} disabled={syncing}>
            {syncing ? 'Syncing…' : 'Sync Now'}
          </Btn>
        </div>
        {syncMsg && <div className={`badge ${syncMsg.includes('error') ? 'danger' : 'ok'}`} style={{ marginBottom: 12, display: 'block' }}>{syncMsg}</div>}
        {queue.length === 0
          ? <div className="muted" style={{ fontSize: 13, textAlign: 'center', padding: 16 }}>No pending offline records.</div>
          : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {queue.map((r: any) => (
                <div key={r.record_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', background: 'var(--bg-subtle)', borderRadius: 6 }}>
                  <div>
                    <span className="mono" style={{ fontSize: 12, fontWeight: 600 }}>{r.record_type}</span>
                    <span className="muted" style={{ fontSize: 11, marginLeft: 8 }}>{r.record_id}</span>
                  </div>
                  <span className={statusColors[r.sync_status] || 'badge'} style={{ fontSize: 10.5 }}>{r.sync_status}</span>
                </div>
              ))}
            </div>
          )
        }
      </Card>

      {/* Pending Desktop Jobs */}
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.ListTodo size={16} /> Pending Desktop Jobs
          {pendingJobs.length > 0 && <span className="badge warn" style={{ fontSize: 10 }}>{pendingJobs.length}</span>}
        </h3>
        {pendingJobs.length === 0
          ? <div className="muted" style={{ fontSize: 13, textAlign: 'center', padding: 16 }}>No pending desktop jobs. Jobs created from the web will appear here.</div>
          : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {pendingJobs.map((j: any) => (
                <div key={j.job_id} style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="mono" style={{ fontWeight: 700, fontSize: 13 }}>{j.job_id}</span>
                    <span className="badge warn" style={{ fontSize: 10.5 }}>{j.status}</span>
                  </div>
                  <div className="muted" style={{ fontSize: 12, marginTop: 3 }}>{j.type}</div>
                </div>
              ))}
            </div>
          )
        }
      </Card>
    </div>
  );
}

// ─── STATUS TAB ───────────────────────────────────────────────────────────────
function StatusTab() {
  const [info, setInfo] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [deviceStatus, setDeviceStatus] = useState<any>(null);
  const [registering, setRegistering] = useState(false);
  const [regMsg, setRegMsg] = useState('');

  useEffect(() => {
    nativeSystemInfo().then(setInfo).catch(() => {});
    checkServerHealth().then(setHealth).catch(() => {});
    getDeviceStatus().then(setDeviceStatus).catch(() => {});
  }, []);

  async function doRegister() {
    setRegistering(true); setRegMsg('');
    try {
      await registerDevice();
      const s = await getDeviceStatus();
      setDeviceStatus(s);
      setRegMsg('✓ Device registered successfully.');
    } catch (e: any) { setRegMsg(`✗ ${e.message}`); }
    finally { setRegistering(false); }
  }

  async function doHeartbeat() {
    try { await sendHeartbeat(); setRegMsg('✓ Heartbeat sent.'); }
    catch (e: any) { setRegMsg(`✗ ${e.message}`); }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* System Info */}
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.Info size={16} /> System Information
        </h3>
        {info ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
            {Object.entries(info).map(([k, v]) => (
              <div key={k} style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8 }}>
                <div className="muted" style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>{k}</div>
                <div className="mono" style={{ fontSize: 13 }}>{String(v)}</div>
              </div>
            ))}
          </div>
        ) : <div className="muted">Loading system info…</div>}
      </Card>

      {/* Backend Connection */}
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.Wifi size={16} /> Backend Connection
        </h3>
        {health ? (
          <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className={`badge ${health.ok ? 'ok' : 'danger'}`}>{health.ok ? '● Connected' : '○ Offline'}</span>
            <span className="muted" style={{ fontSize: 13 }}>Latency: {health.latencyMs}ms</span>
            {health.error && <span className="muted" style={{ fontSize: 12 }}>{health.error}</span>}
          </div>
        ) : <div className="muted">Checking connection…</div>}
      </Card>

      {/* Device Registration */}
      <Card style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 7 }}>
          <I.Fingerprint size={16} /> Device Registration
        </h3>
        <div style={{ marginBottom: 12 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>Device ID:</div>
          <div className="mono" style={{ fontSize: 13, fontWeight: 600 }}>{getDeviceId()}</div>
          <div className="muted" style={{ fontSize: 12, marginTop: 8, marginBottom: 4 }}>Device Name:</div>
          <div className="mono" style={{ fontSize: 13 }}>{getDeviceName()}</div>
        </div>
        {deviceStatus && (
          <div style={{ marginBottom: 12 }}>
            <span className={`badge ${deviceStatus.is_online ? 'ok' : 'warn'}`}>
              {deviceStatus.is_online ? '● Registered & Online' : '○ Not Registered / Offline'}
            </span>
            {deviceStatus.pending_desktop_jobs > 0 && (
              <span className="badge warn" style={{ marginLeft: 8 }}>{deviceStatus.pending_desktop_jobs} pending jobs</span>
            )}
          </div>
        )}
        {regMsg && <div className={`badge ${regMsg.startsWith('✓') ? 'ok' : 'danger'}`} style={{ marginBottom: 10, display: 'block' }}>{regMsg}</div>}
        <div style={{ display: 'flex', gap: 8 }}>
          <Btn primary onClick={doRegister} disabled={registering}>
            <I.Fingerprint size={14} /> {registering ? 'Registering…' : 'Register Device'}
          </Btn>
          <Btn onClick={doHeartbeat}>
            <I.Heart size={14} /> Send Heartbeat
          </Btn>
        </div>
      </Card>
    </div>
  );
}

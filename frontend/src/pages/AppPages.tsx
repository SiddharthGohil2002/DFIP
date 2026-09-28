import { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import * as I from 'lucide-react';
import { api, uploadEvidence, downloadReport, downloadArtifact } from '../services/api';
import { isDesktop, canWrite } from '../native';
import DesktopRequired from '../components/DesktopRequired';
import OperationBadge from '../components/OperationBadge';
import DesktopStatus from '../components/DesktopStatus';

const Card = ({ children, style, className = '' }: { children: any; style?: any; className?: string }) => (
  <div className={`card ${className}`} style={{ borderRadius: 'var(--radius)', ...style }}>
    {children}
  </div>
);

const Title = ({
  title,
  sub,
  eyebrow = 'DFIP / FORENSIC WORKSPACE',
  action
}: {
  title: string;
  sub?: string;
  eyebrow?: string;
  action?: any;
}) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 16, marginBottom: 24 }}>
    <div>
      <div className="eyebrow" style={{ marginBottom: 6 }}>{eyebrow}</div>
      <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.02em', margin: 0 }}>{title}</h1>
      {sub && <div className="muted" style={{ fontSize: 13.5, marginTop: 4 }}>{sub}</div>}
    </div>
    {action && <div>{action}</div>}
  </div>
);

const Button = ({
  children,
  onClick,
  primary = false,
  danger = false,
  ghost = false,
  sm = false,
  disabled = false,
  style
}: {
  children: any;
  onClick?: () => void;
  primary?: boolean;
  danger?: boolean;
  ghost?: boolean;
  sm?: boolean;
  disabled?: boolean;
  style?: any;
}) => (
  <button
    className={`btn ${primary ? 'primary' : ''} ${danger ? 'danger' : ''} ${ghost ? 'ghost' : ''} ${sm ? 'sm' : ''}`}
    onClick={onClick}
    disabled={disabled}
    style={style}
  >
    {children}
  </button>
);

function useLoad(path: string | null) {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(path !== null);

  const load = () => {
    if (path === null) return;
    setLoading(true);
    api<any>(path)
      .then((r) => {
        setData(r.data ?? r);
        setError('');
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const handleWs = () => {
      load();
    };
    window.addEventListener('dfip-ws-event', handleWs);
    return () => window.removeEventListener('dfip-ws-event', handleWs);
  }, [path]);

  return { data, error, loading, reload: load };
}

function Stat({
  label,
  value,
  icon: Icon,
  trend,
  color = 'var(--red)'
}: {
  label: string;
  value: any;
  icon: any;
  trend?: string;
  color?: string;
}) {
  return (
    <Card style={{ padding: '20px 22px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <span className="muted" style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{label}</span>
        <div style={{ width: 36, height: 36, borderRadius: 8, background: 'var(--bg-subtle)', display: 'grid', placeItems: 'center', color }}>
          <Icon size={19} />
        </div>
      </div>
      <div style={{ fontSize: 32, fontWeight: 800, letterSpacing: '-0.02em', marginTop: 10, lineHeight: 1 }}>
        {value ?? 0}
      </div>
      {trend && (
        <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 8, display: 'flex', alignItems: 'center', gap: 4 }}>
          {trend}
        </div>
      )}
    </Card>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const p = (priority || 'MEDIUM').toUpperCase();
  const cls = p === 'CRITICAL' ? 'badge danger' : p === 'HIGH' ? 'badge warn' : p === 'LOW' ? 'badge info' : 'badge';
  return <span className={cls}>{p}</span>;
}

function StatusBadge({ status }: { status: string }) {
  const s = (status || 'UNKNOWN').toUpperCase();
  const cls = s === 'VERIFIED' || s === 'COMPLETED' || s === 'ACTIVE' ? 'badge ok' : s === 'FAILED' || s === 'SUSPENDED' ? 'badge danger' : 'badge warn';
  return <span className={cls}>{s}</span>;
}

function Empty({ text }: { text: string }) {
  return (
    <div style={{ padding: '48px 24px', textAlign: 'center' }}>
      <div style={{ width: 44, height: 44, borderRadius: 999, background: 'var(--bg-subtle)', color: 'var(--muted)', display: 'grid', placeItems: 'center', margin: '0 auto 12px' }}>
        <I.Inbox size={20} />
      </div>
      <div className="muted" style={{ fontSize: 13.5 }}>{text}</div>
    </div>
  );
}

/* =========================================================================
   1. DASHBOARD
========================================================================= */
export function Dashboard({ admin = false }: { admin?: boolean }) {
  const nav = useNavigate();
  const c = useLoad('/cases');
  const e = useLoad('/evidence');
  const a = useLoad('/forensics/timeline');
  const stats = useLoad(admin ? '/admin/stats' : null);
  const s = stats.data || {};

  const activeCases = admin ? s.cases ?? 0 : (c.data || []).filter((x: any) => x.status !== 'COMPLETED').length;
  const totalEvidence = admin ? s.evidence ?? (e.data || []).length : (e.data || []).length;
  const verifiedCount = admin ? s.verified ?? 0 : (e.data || []).filter((x: any) => x.verification_status === 'VERIFIED').length;
  const integrityPct = totalEvidence ? Math.round((verifiedCount / totalEvidence) * 100) : 100;

  return (
    <div className="fade">
      <Title
        title={admin ? 'Platform Command Center' : 'Investigation Workspace'}
        sub={admin ? 'Comprehensive operational telemetry and active forensic case overview.' : 'Overview of your assigned investigations, evidence health, and verification telemetry.'}
        action={
          canWrite ? (
            <div style={{ display: 'flex', gap: 10 }}>
              <Button primary onClick={() => nav(admin ? '/admin/cases' : '/investigator/cases')}>
                <I.FolderPlus size={15} /> New Case
              </Button>
              <Button onClick={() => nav(admin ? '/admin/evidence' : '/investigator/evidence')}>
                <I.Upload size={15} /> Ingest Evidence
              </Button>
            </div>
          ) : (
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <span className="badge" style={{ fontSize: 11, padding: '5px 10px' }}>
                <I.Eye size={12} style={{ marginRight: 5, verticalAlign: 'middle' }} />
                Real-Time Monitoring
              </span>
              <a
                href="/downloads/DFIP-Investigator-Windows-x64.exe"
                download="DFIP-Investigator-Windows-x64.exe"
                className="btn primary sm"
                style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 6 }}
                title="Direct download DFIP Investigator Windows Installer (v2.0.0)"
              >
                <I.Download size={13} /> Workstation Client (.exe)
              </a>
            </div>
          )
        }
      />

      {/* Metrics Row */}
      <div className="grid4">
        <Stat label="Active Cases" value={activeCases} icon={I.Folders} trend="Active investigations in flight" />
        <Stat label="Evidence Items" value={totalEvidence} icon={I.Shield} trend="SHA-256 hashed disk/memory objects" />
        <Stat label="Integrity Ratio" value={`${integrityPct}%`} icon={I.BadgeCheck} color="var(--green)" trend={`${verifiedCount} of ${totalEvidence} verified`} />
        <Stat label={admin ? 'Active Users' : 'Timeline Artifacts'} value={admin ? s.active_users ?? 0 : (a.data || []).length} icon={admin ? I.Users : I.Clock3} trend="Indexed forensic events" />
      </div>

      <div className="grid2" style={{ marginTop: 20 }}>
        {/* Recent Cases Card */}
        <Card>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Active Investigations</h3>
            <Link to={admin ? '/admin/cases' : '/investigator/cases'} style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--red)' }}>
              View all →
            </Link>
          </div>

          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Case ID</th>
                  <th>Name</th>
                  <th>Priority</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {(c.data || []).slice(0, 6).map((x: any) => (
                  <tr key={x._id}>
                    <td>
                      <span className="mono" style={{ fontWeight: 700, color: 'var(--ink)' }}>{x.case_id}</span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{x.name}</div>
                    </td>
                    <td><PriorityBadge priority={x.priority} /></td>
                    <td><StatusBadge status={x.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!(c.data || []).length && <Empty text="No cases available yet. Click 'New Case' to start an investigation." />}
          </div>
        </Card>

        {/* Evidence Integrity Card */}
        <Card style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, margin: '0 0 4px' }}>Cryptographic Integrity</h3>
            <div className="muted" style={{ fontSize: 12.5 }}>WORM storage verification posture</div>
          </div>

          <div style={{ padding: '36px 12px', textAlign: 'center' }}>
            <div style={{ fontSize: 62, fontWeight: 800, color: integrityPct === 100 ? 'var(--green)' : 'var(--amber)', lineHeight: 1 }}>
              {integrityPct}<span style={{ fontSize: 24, fontWeight: 600 }}>%</span>
            </div>
            <div style={{ fontWeight: 700, fontSize: 14, marginTop: 8 }}>
              {integrityPct === 100 ? 'Zero Evidence Alteration Detected' : 'Verification Required'}
            </div>
            <div className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>
              All registered images match their original intake SHA-256 manifest.
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
            <div style={{ background: 'var(--bg-subtle)', padding: 10, borderRadius: 8, textAlign: 'center' }}>
              <div className="muted" style={{ fontSize: 11, fontWeight: 600 }}>ALGORITHM</div>
              <div style={{ fontWeight: 700, fontSize: 13 }}>SHA-256 (256-bit)</div>
            </div>
            <div style={{ background: 'var(--bg-subtle)', padding: 10, borderRadius: 8, textAlign: 'center' }}>
              <div className="muted" style={{ fontSize: 11, fontWeight: 600 }}>CHAIN STATUS</div>
              <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--green-dark)' }}>Tamper-Evident</div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

/* =========================================================================
   2. CASES
========================================================================= */
export function Cases() {
  const { data, error, reload } = useLoad('/cases');
  const [name, setName] = useState('');
  const [priority, setPriority] = useState('MEDIUM');
  const [search, setSearch] = useState('');
  const [busy, setBusy] = useState(false);

  async function create() {
    if (!name.trim()) return alert('Please enter a case name.');
    setBusy(true);
    try {
      await api('/cases', { method: 'POST', body: JSON.stringify({ name: name.trim(), priority }) });
      setName('');
      reload();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  const filtered = (data || []).filter((x: any) =>
    (x.name || '').toLowerCase().includes(search.toLowerCase()) ||
    (x.case_id || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="fade">
      <Title
        title="Case Management"
        sub="Authorized investigation containers with evidence isolation and access control."
        action={
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <input
              className="input"
              style={{ width: 220 }}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter cases…"
            />
          </div>
        }
      />

      {/* Case Creation Toolbar */}
      {canWrite ? (
        <Card style={{ marginBottom: 20, padding: 18 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <input
              className="input"
              style={{ flex: 1, minWidth: 240 }}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="New case title (e.g. Unauthorized Cloud Data Exfiltration)"
            />
            <select className="input" style={{ width: 140 }} value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="LOW">Priority: LOW</option>
              <option value="MEDIUM">Priority: MEDIUM</option>
              <option value="HIGH">Priority: HIGH</option>
              <option value="CRITICAL">Priority: CRITICAL</option>
            </select>
            <Button primary onClick={create} disabled={busy}>
              {busy ? 'Registering…' : '+ Create Case'}
            </Button>
          </div>
        </Card>
      ) : (
        <div style={{ padding: '14px 18px', background: 'var(--bg-subtle)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', marginBottom: 20, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <I.Info size={16} className="muted" />
            <span style={{ fontSize: 13, color: 'var(--ink-light)' }}>
              Case creation & evidence intake are restricted to the <b>DFIP Desktop Workstation</b>. This web portal provides real-time oversight and monitoring.
            </span>
          </div>
          <span className="badge" style={{ fontSize: 11 }}>Read-Only Mode</span>
        </div>
      )}

      <Card style={{ padding: 0 }}>
        {error && <div className="badge danger" style={{ margin: 16 }}>{error}</div>}
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Case Reference</th>
                <th>Investigation Title</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Opened Timestamp</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((x: any) => (
                <tr key={x._id}>
                  <td>
                    <span className="mono" style={{ fontWeight: 700, color: 'var(--red)' }}>{x.case_id}</span>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600 }}>{x.name}</div>
                    {x.description && <div className="muted" style={{ fontSize: 12 }}>{x.description}</div>}
                  </td>
                  <td><PriorityBadge priority={x.priority} /></td>
                  <td><StatusBadge status={x.status} /></td>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(x.created_at).toLocaleString()}</td>
                  <td>
                    <Link to="../evidence" relative="path" className="btn sm">
                      Evidence Register →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!filtered.length && <Empty text="No matching cases found." />}
        </div>
      </Card>
    </div>
  );
}

/* =========================================================================
   3. EVIDENCE REGISTER & VERIFY
========================================================================= */
export function Evidence() {
  const { data, reload } = useLoad('/evidence');
  const [file, setFile] = useState<File | null>(null);
  const [caseId, setCaseId] = useState('CASE-2026-001');
  const [busy, setBusy] = useState(false);
  // Desktop native acquisition state
  const [nativePath, setNativePath] = useState('');
  const [nativeBusy, setNativeBusy] = useState(false);
  const [nativeMsg, setNativeMsg] = useState('');

  async function upload() {
    if (!file || !caseId.trim()) return alert('Please enter a case ID and choose a forensic image.');
    setBusy(true);
    try {
      const f = new FormData();
      f.append('file', file);
      f.append('case_id', caseId.trim());
      await uploadEvidence(f);
      setFile(null);
      reload();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function acquireNative() {
    if (!nativePath.trim() || !caseId.trim()) return;
    setNativeBusy(true); setNativeMsg('');
    try {
      const { hashLocalFile } = await import('../services/desktop/evidence');
      const { getDeviceId } = await import('../services/desktop/device');
      const hashRes = await hashLocalFile(nativePath.trim());
      const { registerEvidenceWithBackend } = await import('../services/desktop/evidence');
      await registerEvidenceWithBackend({
        case_id: caseId.trim(),
        filename: nativePath.trim().split(/[\\/]/).pop() || 'evidence',
        format: (nativePath.trim().split('.').pop() || 'BIN').toUpperCase(),
        size: hashRes.bytes,
        sha256: hashRes.sha256,
        local_path: nativePath.trim(),
        device_id: getDeviceId(),
        acquisition_timestamp: new Date().toISOString(),
      });
      setNativeMsg(`✓ Evidence acquired and registered. SHA-256: ${hashRes.sha256.slice(0, 16)}…`);
      setNativePath('');
      reload();
    } catch (e: any) { setNativeMsg(`✗ ${e.message}`); }
    finally { setNativeBusy(false); }
  }

  return (
    <div className="fade">
      <Title
        title="Evidence Register"
        sub="All acquired evidence objects are preserved read-only and sealed with a SHA-256 acquisition manifest."
      />

      {/* Acquisition Section — Desktop vs Web */}
      {isDesktop ? (
        <Card style={{ marginBottom: 20, padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0 }}>Acquire Evidence from Local Workstation</h3>
            <OperationBadge type="DESKTOP" />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr auto', gap: 10, marginBottom: 10 }}>
            <input className="input" value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="Assign to Case ID" />
            <input className="input" value={nativePath} onChange={(e) => setNativePath(e.target.value)} placeholder="Full local path to evidence file (e.g. D:\evidence\image.E01)" />
            <Button primary onClick={acquireNative} disabled={nativeBusy || !nativePath.trim() || !caseId.trim()}>
              {nativeBusy ? 'Computing SHA-256…' : 'Acquire & Hash'}
            </Button>
          </div>
          {nativeMsg && <div className={`badge ${nativeMsg.startsWith('✓') ? 'ok' : 'danger'}`} style={{ display: 'block', marginBottom: 8 }}>{nativeMsg}</div>}
          <div className="muted" style={{ fontSize: 12 }}>Evidence is hashed locally using the native SHA-256 engine. The file itself is not uploaded — only the metadata and hash are sent to the backend.</div>
          <div style={{ borderTop: '1px solid var(--border)', marginTop: 16, paddingTop: 14 }}>
            <h4 style={{ fontSize: 13, fontWeight: 700, margin: '0 0 8px' }}>Upload Evidence Image to Server Storage</h4>
            <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr auto', gap: 10 }}>
              <input className="input" value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="Case ID" />
              <input className="input" type="file" accept=".E01,.e01,.RAW,.raw,.DD,.dd,.AFF,.aff,.AFF4,.aff4" onChange={(e) => setFile(e.target.files?.[0] || null)} />
              <Button primary onClick={upload} disabled={busy}>{busy ? 'Uploading…' : 'Upload to Server'}</Button>
            </div>
            <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>Server upload is for evidence stored on network-attached storage accessible to the backend. For local evidence, use the native acquisition above.</div>
          </div>
        </Card>
      ) : canWrite ? (
        <Card style={{ marginBottom: 20, padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0 }}>Upload Evidence Image</h3>
            <OperationBadge type="WEB" />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr auto', gap: 10 }}>
            <input className="input" value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="Case ID" />
            <input className="input" type="file" accept=".E01,.e01,.RAW,.raw,.DD,.dd,.AFF,.aff,.AFF4,.aff4" onChange={(e) => setFile(e.target.files?.[0] || null)} />
            <Button primary onClick={upload} disabled={busy}>{busy ? 'Uploading…' : 'Upload to Server'}</Button>
          </div>
          <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>The server computes SHA-256 and SHA-512 on receipt, marks the original read-only and records the chain-of-custody entry.</div>
        </Card>
      ) : (
        <div style={{ marginBottom: 20 }}>
          <DesktopRequired
            operation="Evidence Acquisition"
            description="Acquiring evidence requires direct access to the local forensic workstation to compute cryptographic hashes without transferring the evidence file."
            jobType="DESKTOP_ACQUIRE_EVIDENCE"
            jobPayload={{ case_id: caseId }}
          />
        </div>
      )}

      <Card style={{ padding: 0 }}>
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Evidence ID</th>
                <th>Assigned Case</th>
                <th>Format</th>
                <th>Acquisition SHA-256</th>
                <th>Integrity</th>
                <th>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {(data || []).map((x: any) => (
                <tr key={x._id}>
                  <td>
                    <div style={{ fontWeight: 700, color: 'var(--ink)' }}>{x.evidence_id}</div>
                    <div className="muted" style={{ fontSize: 11 }}>{x.filename}</div>
                  </td>
                  <td>
                    <span className="mono" style={{ fontWeight: 600 }}>{x.case_id}</span>
                  </td>
                  <td>
                    <span className="badge info">{x.format}</span>
                  </td>
                  <td>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--ink-light)' }}>
                      {x.sha256 ? `${x.sha256.slice(0, 24)}…` : '—'}
                    </div>
                  </td>
                  <td>
                    <StatusBadge status={x.verification_status} />
                  </td>
                  <td>
                    <Link to={x.evidence_id} className="btn sm">
                      <I.Microscope size={14} /> Open
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!(data || []).length && <Empty text="No evidence registered. Use the ingest toolbar above to add an image." />}
        </div>
      </Card>
    </div>
  );
}

export function EvidenceVerify() {
  const { id } = useParams();
  const { data, error, reload } = useLoad(`/evidence/${id}`);
  const [busy, setBusy] = useState(false);

  async function verify() {
    setBusy(true);
    try {
      await api(`/evidence/${id}/verify`, { method: 'POST' });
      reload();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fade">
      <Title
        title="Evidence Verification Audit"
        sub="Recalculate the on-disk cryptographic digest and compare against the intake manifest."
        action={
          <Link to=".." relative="path" className="btn sm">
            ← Back to Register
          </Link>
        }
      />

      <Card style={{ maxWidth: 800, padding: 28 }}>
        {error ? (
          <div className="badge danger">{error}</div>
        ) : data ? (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
              <div>
                <div className="eyebrow" style={{ marginBottom: 6 }}>OBJECT MANIFEST</div>
                <h2 style={{ fontSize: 24, fontWeight: 800, margin: 0 }}>{data.evidence_id}</h2>
                <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>
                  {data.filename} · Format: {data.format} · Size: {Math.round(data.size / 1024 / 1024)} MB
                </div>
              </div>
              <StatusBadge status={data.verification_status} />
            </div>

            <div style={{ background: 'var(--bg-subtle)', padding: 18, borderRadius: 10, marginBottom: 24 }}>
              <div className="muted" style={{ fontSize: 11, fontWeight: 700, marginBottom: 6 }}>ACQUISITION HASH (SHA-256)</div>
              <div className="mono" style={{ fontSize: 13, color: 'var(--red)', wordBreak: 'break-all', fontWeight: 600 }}>
                {data.sha256}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 28 }}>
              <div style={{ padding: 12, border: '1px solid var(--border)', borderRadius: 8 }}>
                <div className="muted" style={{ fontSize: 11, fontWeight: 600 }}>IMMUTABILITY</div>
                <div style={{ fontWeight: 700, color: 'var(--green-dark)' }}>Read-Only Locked</div>
              </div>
              <div style={{ padding: 12, border: '1px solid var(--border)', borderRadius: 8 }}>
                <div className="muted" style={{ fontSize: 11, fontWeight: 600 }}>STORAGE LAYER</div>
                <div style={{ fontWeight: 700 }}>Filesystem (WORM)</div>
              </div>
              <div style={{ padding: 12, border: '1px solid var(--border)', borderRadius: 8 }}>
                <div className="muted" style={{ fontSize: 11, fontWeight: 600 }}>PRESERVATION</div>
                <div style={{ fontWeight: 700 }}>Chain Logged</div>
              </div>
            </div>

            {canWrite ? (
              <Button primary onClick={verify} disabled={busy} style={{ width: '100%', padding: '12px 18px', fontSize: 14 }}>
                {busy ? 'Computing Bitstream Checksum…' : 'Run Live Cryptographic Verification'}
              </Button>
            ) : (
              <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border)', padding: 14, borderRadius: 8, textAlign: 'center', fontSize: 13, color: 'var(--ink-light)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                <I.Monitor size={16} className="muted" />
                <span>Bitstream re-verification must be executed on the physical forensic workstation holding the original image.</span>
              </div>
            )}
          </div>
        ) : null}
      </Card>

      {data && <AnalysisPanel evidence={data} onChange={reload} />}
    </div>
  );
}

/* =========================================================================
   3b. DISK IMAGE ANALYSIS — pickers, full analysis job, files / USB / browser
========================================================================= */
const fmtTime = (v: any) => (v ? new Date(v).toLocaleString() : '—');
const fmtSize = (n: any) => (n === null || n === undefined ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const TERMINAL_JOB = ['COMPLETED', 'FAILED', 'CANCELLED'];

function CasePicker({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { data } = useLoad('/cases');
  const cases = data || [];
  useEffect(() => {
    if (cases.length && !cases.find((c: any) => c.case_id === value)) onChange(cases[0].case_id);
  }, [data]);
  return (
    <select className="input" style={{ maxWidth: 320 }} value={value} onChange={(e) => onChange(e.target.value)}>
      {!cases.length && <option value="">No accessible cases</option>}
      {cases.map((c: any) => <option key={c.case_id} value={c.case_id}>{c.case_id} — {c.name}</option>)}
    </select>
  );
}

function EvidencePicker({ caseId, value, onChange }: { caseId: string; value: string; onChange: (v: string) => void }) {
  const { data } = useLoad('/evidence');
  const items = (data || []).filter((e: any) => e.case_id === caseId && !e.demo);
  useEffect(() => {
    if (items.length && !items.find((e: any) => e.evidence_id === value)) onChange(items[0].evidence_id);
    if (!items.length && value) onChange('');
  }, [data, caseId]);
  return (
    <select className="input" style={{ maxWidth: 320 }} value={value} onChange={(e) => onChange(e.target.value)}>
      {!items.length && <option value="">No evidence in this case</option>}
      {items.map((e: any) => <option key={e.evidence_id} value={e.evidence_id}>{e.evidence_id} — {e.filename}</option>)}
    </select>
  );
}

function ProgressBar({ value }: { value: number }) {
  return (
    <div style={{ flex: 1, height: 8, background: 'var(--bg-subtle)', borderRadius: 999, overflow: 'hidden' }}>
      <div style={{ width: `${value || 0}%`, height: '100%', background: 'var(--red)', borderRadius: 999, transition: 'width .4s' }} />
    </div>
  );
}

function AnalysisPanel({ evidence, onChange }: { evidence: any; onChange: () => void }) {
  const [job, setJob] = useState<any>(null);
  const [tab, setTab] = useState<'deleted' | 'files' | 'usb' | 'browser'>('deleted');
  const [err, setErr] = useState('');
  const summary = evidence.analysis_summary || {};

  // Resume progress display for an analysis that is already running.
  useEffect(() => {
    if (evidence.analysis_status === 'RUNNING' && evidence.last_analysis_job) setJob({ job_id: evidence.last_analysis_job, status: 'RUNNING' });
  }, [evidence.evidence_id]);

  useEffect(() => {
    if (!job || TERMINAL_JOB.includes(job.status)) return;
    const t = setInterval(async () => {
      try {
        const j = await api<any>(`/jobs/${job.job_id}`);
        setJob(j);
        if (TERMINAL_JOB.includes(j.status)) onChange();
      } catch (e: any) {
        setErr(e.message);
      }
    }, 1500);
    return () => clearInterval(t);
  }, [job?.job_id, job?.status]);

  async function start() {
    setErr('');
    try {
      const r = await api<any>(`/jobs/analysis/${encodeURIComponent(evidence.evidence_id)}`, { method: 'POST' });
      setJob({ job_id: r.job_id, status: 'QUEUED', progress: 0, stage: 'queued' });
    } catch (e: any) {
      setErr(e.message);
    }
  }

  const running = job && !TERMINAL_JOB.includes(job.status);
  const analyzed = evidence.analysis_status === 'COMPLETED';

  return (
    <Card style={{ marginTop: 20, padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
        <div>
          <div className="eyebrow" style={{ marginBottom: 4 }}>DISK IMAGE ANALYSIS</div>
          <h3 style={{ fontSize: 18, fontWeight: 800, margin: 0 }}>Sleuth Kit examination</h3>
          <div className="muted" style={{ fontSize: 12.5, marginTop: 4 }}>
            Re-verifies the SHA-256, indexes every file (including deleted), builds the MACB timeline, and extracts browser history and USB device history.
          </div>
        </div>
        {canWrite && !evidence.demo && (
          <Button primary onClick={start} disabled={!!running}>
            <I.Play size={15} /> {running ? 'Analysis running…' : analyzed ? 'Re-run Full Analysis' : 'Run Full Analysis'}
          </Button>
        )}
      </div>

      {err && <div className="badge danger" style={{ display: 'block', marginBottom: 12 }}>{err}</div>}
      {job && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
          <span className="mono" style={{ fontSize: 12, fontWeight: 700 }}>{job.job_id}</span>
          <ProgressBar value={job.progress} />
          <span className="mono" style={{ fontSize: 11, minWidth: 190 }}>{job.status} · {job.stage} · {job.progress || 0}%</span>
        </div>
      )}
      {job?.status === 'FAILED' && <div className="badge danger" style={{ display: 'block', marginBottom: 12 }}>{job.error}</div>}

      {analyzed ? (
        <>
          <div className="grid4" style={{ marginBottom: 18 }}>
            <Stat label="Files indexed" value={summary.files} icon={I.Files} trend={`${summary.deleted_files ?? 0} deleted`} />
            <Stat label="Timeline events" value={summary.timeline_events} icon={I.Clock} trend={`Analyzed ${fmtTime(evidence.analyzed_at)}`} />
            <Stat label="Browser records" value={(summary.browser_history ?? 0) + (summary.browser_downloads ?? 0)} icon={I.Globe} trend={`${summary.browser_downloads ?? 0} downloads`} />
            <Stat label="USB devices" value={summary.usb_devices} icon={I.Usb} trend={`${summary.yara_matches ?? 0} YARA matches`} />
          </div>
          <div style={{ display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' }}>
            {([['deleted', 'Deleted files'], ['files', 'All files'], ['usb', 'USB devices'], ['browser', 'Browser']] as const).map(([k, label]) => (
              <button key={k} className={`feature-tab ${tab === k ? 'active' : ''}`} onClick={() => setTab(k)}>{label}</button>
            ))}
          </div>
          {tab === 'deleted' && <FilesTable evidenceId={evidence.evidence_id} deletedOnly />}
          {tab === 'files' && <FilesTable evidenceId={evidence.evidence_id} />}
          {tab === 'usb' && <UsbTable caseId={evidence.case_id} evidenceId={evidence.evidence_id} />}
          {tab === 'browser' && <BrowserTables caseId={evidence.case_id} evidenceId={evidence.evidence_id} />}
        </>
      ) : (
        !running && <Empty text={evidence.demo ? 'Demo evidence is synthetic and cannot be analyzed.' : 'This image has not been analyzed yet.'} />
      )}
    </Card>
  );
}

function FilesTable({ evidenceId, deletedOnly = false }: { evidenceId: string; deletedOnly?: boolean }) {
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [skip, setSkip] = useState(0);
  const [recovered, setRecovered] = useState<Record<string, any>>({});
  const [busy, setBusy] = useState('');
  const limit = 100;
  const path = `/forensics/evidence/${encodeURIComponent(evidenceId)}/files?limit=${limit}&skip=${skip}${deletedOnly ? '&deleted=true' : ''}${search ? `&q=${encodeURIComponent(search)}` : ''}`;
  const [res, setRes] = useState<any>(null);
  useEffect(() => {
    api<any>(path).then(setRes).catch((e) => setRes({ data: [], error: e.message }));
  }, [path]);
  useEffect(() => setSkip(0), [search, deletedOnly]);

  async function recover(f: any) {
    const key = `${f.partition_offset}:${f.inode}`;
    setBusy(key);
    try {
      const r = await api<any>(`/forensics/evidence/${encodeURIComponent(evidenceId)}/recover?inode=${encodeURIComponent(f.inode)}&offset=${f.partition_offset}`, { method: 'POST' });
      if (r.status !== 'COMPLETED') throw new Error(r.stderr || r.status);
      setRecovered({ ...recovered, [key]: r });
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy('');
    }
  }

  const rows = res?.data || [];
  return (
    <div>
      <div style={{ display: 'flex', gap: 10, marginBottom: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <input className="input" style={{ maxWidth: 320 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q)} placeholder="Filter by path (Enter)…" />
        <Button sm onClick={() => setSearch(q)}><I.Search size={13} /> Filter</Button>
        <span className="muted" style={{ fontSize: 12 }}>{res ? `${res.total ?? 0} ${deletedOnly ? 'deleted ' : ''}entries` : 'Loading…'}</span>
        {res?.error && <span className="badge danger">{res.error}</span>}
      </div>
      <div className="table-container">
        <table className="table">
          <thead>
            <tr><th>Path</th><th>Inode</th><th>Size</th><th>Modified</th><th>Created</th><th>Accessed</th><th></th></tr>
          </thead>
          <tbody>
            {rows.map((f: any) => {
              const key = `${f.partition_offset}:${f.inode}`;
              const rec = recovered[key];
              return (
                <tr key={f._id}>
                  <td style={{ maxWidth: 420, wordBreak: 'break-all' }}>
                    {f.is_dir ? <I.Folder size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} /> : <I.File size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />}
                    <span style={{ fontWeight: f.deleted ? 700 : 500 }}>{f.path}</span>
                    {f.deleted && <span className="badge danger" style={{ marginLeft: 8, fontSize: 10 }}>{f.deleted_status?.toUpperCase()}</span>}
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>{f.inode}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{fmtSize(f.size)}</td>
                  <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{fmtTime(f.mtime)}</td>
                  <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{fmtTime(f.crtime)}</td>
                  <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{fmtTime(f.atime)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {rec ? (
                      <Button sm onClick={() => downloadArtifact(rec.artifact_id, rec.filename).catch((e) => alert(e.message))}>
                        <I.Download size={13} /> Download
                      </Button>
                    ) : (
                      canWrite && !f.is_dir && (
                        <Button sm onClick={() => recover(f)} disabled={busy === key}>
                          <I.RotateCcw size={13} /> {busy === key ? 'Recovering…' : 'Recover'}
                        </Button>
                      )
                    )}
                    {rec && <div className="mono muted" style={{ fontSize: 10, marginTop: 4 }} title={rec.sha256}>SHA-256 {rec.sha256.slice(0, 16)}…</div>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {res && !rows.length && <Empty text={deletedOnly ? 'No deleted file entries found.' : 'No files match.'} />}
      </div>
      {res && res.total > limit && (
        <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center' }}>
          <Button sm disabled={skip === 0} onClick={() => setSkip(Math.max(0, skip - limit))}>← Prev</Button>
          <span className="muted" style={{ fontSize: 12 }}>{skip + 1}–{Math.min(skip + limit, res.total)} of {res.total}</span>
          <Button sm disabled={skip + limit >= res.total} onClick={() => setSkip(skip + limit)}>Next →</Button>
        </div>
      )}
    </div>
  );
}

function UsbTable({ caseId, evidenceId }: { caseId: string; evidenceId?: string }) {
  const { data, error } = useLoad(caseId ? `/forensics/usb?case_id=${encodeURIComponent(caseId)}${evidenceId ? `&evidence_id=${encodeURIComponent(evidenceId)}` : ''}` : null);
  return (
    <div className="table-container">
      {error && <div className="badge danger">{error}</div>}
      <table className="table">
        <thead>
          <tr><th>Device</th><th>Serial</th><th>VID:PID</th><th>Drive</th><th>First install</th><th>Last connected</th><th>Last removed</th><th>Source</th></tr>
        </thead>
        <tbody>
          {(data || []).map((d: any) => (
            <tr key={d._id}>
              <td>
                <div style={{ fontWeight: 700 }}>{d.friendly_name || `${d.vendor || ''} ${d.product || ''}`}</div>
                <div className="muted" style={{ fontSize: 11 }}>{d.vendor} · {d.product} · rev {d.revision || '—'}</div>
              </td>
              <td className="mono" style={{ fontSize: 11 }}>
                {d.serial}
                {d.serial_is_unique === false && <div className="badge warn" style={{ fontSize: 9 }}>OS-GENERATED</div>}
              </td>
              <td className="mono" style={{ fontSize: 11 }}>{d.vid ? `${d.vid}:${d.pid}` : '—'}</td>
              <td>{(d.drive_letters || []).join(', ') || '—'}</td>
              <td className="mono" style={{ fontSize: 11 }}>
                {fmtTime(d.first_install)}
                {d.setupapi_first_install && <div className="muted" title="setupapi.dev.log">setupapi: {fmtTime(d.setupapi_first_install)}</div>}
              </td>
              <td className="mono" style={{ fontSize: 11 }}>{fmtTime(d.last_arrival)}</td>
              <td className="mono" style={{ fontSize: 11 }}>{fmtTime(d.last_removal)}</td>
              <td><span className="badge info" style={{ fontSize: 10 }}>{d.source}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      {data && !data.length && <Empty text="No USB storage devices found in the SYSTEM hive or setupapi.dev.log (run Full Analysis on a Windows image)." />}
    </div>
  );
}

function BrowserTables({ caseId, evidenceId }: { caseId: string; evidenceId?: string }) {
  const [kind, setKind] = useState<'BROWSER_HISTORY' | 'BROWSER_DOWNLOAD'>('BROWSER_HISTORY');
  const { data, error } = useLoad(caseId ? `/forensics/browser?case_id=${encodeURIComponent(caseId)}&kind=${kind}${evidenceId ? `&evidence_id=${encodeURIComponent(evidenceId)}` : ''}` : null);
  return (
    <div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
        <button className={`feature-tab ${kind === 'BROWSER_HISTORY' ? 'active' : ''}`} onClick={() => setKind('BROWSER_HISTORY')}>History</button>
        <button className={`feature-tab ${kind === 'BROWSER_DOWNLOAD' ? 'active' : ''}`} onClick={() => setKind('BROWSER_DOWNLOAD')}>Downloads</button>
      </div>
      {error && <div className="badge danger">{error}</div>}
      <div className="table-container">
        <table className="table">
          <thead>
            {kind === 'BROWSER_HISTORY'
              ? <tr><th>Browser</th><th>Last visit</th><th>Visits</th><th>URL / title</th><th>Source database</th></tr>
              : <tr><th>Browser</th><th>Started</th><th>Saved to</th><th>From</th><th>Source database</th></tr>}
          </thead>
          <tbody>
            {(data || []).map((r: any) => (
              <tr key={r._id}>
                <td><span className="badge">{r.browser}</span></td>
                <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{fmtTime(kind === 'BROWSER_HISTORY' ? r.last_visit_time : r.start_time)}</td>
                {kind === 'BROWSER_HISTORY' ? (
                  <>
                    <td>{r.visit_count}</td>
                    <td style={{ maxWidth: 460, wordBreak: 'break-all' }}>
                      <div style={{ fontWeight: 600 }}>{r.title || '—'}</div>
                      <div className="mono muted" style={{ fontSize: 11 }}>{r.url}</div>
                    </td>
                  </>
                ) : (
                  <>
                    <td className="mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{r.target_path}</td>
                    <td className="mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{r.tab_url}</td>
                  </>
                )}
                <td className="mono muted" style={{ fontSize: 10, maxWidth: 220, wordBreak: 'break-all' }}>{r.source_path}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && !data.length && <Empty text="No browser records found (Chrome/Edge/Brave History, Firefox places.sqlite)." />}
      </div>
    </div>
  );
}

function CaseArtifactPage({ title, sub, children }: { title: string; sub: string; children: (caseId: string) => any }) {
  const [caseId, setCaseId] = useState('');
  return (
    <div className="fade">
      <Title title={title} sub={sub} action={<CasePicker value={caseId} onChange={setCaseId} />} />
      <Card style={{ padding: 20 }}>{caseId ? children(caseId) : <Empty text="Select a case." />}</Card>
    </div>
  );
}

export function BrowserForensics() {
  return (
    <CaseArtifactPage title="Browser Forensics" sub="History and downloads parsed from Chrome, Edge, Brave and Firefox databases extracted from analyzed images.">
      {(caseId) => <BrowserTables caseId={caseId} />}
    </CaseArtifactPage>
  );
}

export function UsbForensics() {
  return (
    <CaseArtifactPage title="USB Forensics" sub="Removable storage history from the SYSTEM registry hive (USBSTOR, USB, MountedDevices) and setupapi.dev.log.">
      {(caseId) => <UsbTable caseId={caseId} />}
    </CaseArtifactPage>
  );
}

export function FileRecovery() {
  const [caseId, setCaseId] = useState('');
  const [evidenceId, setEvidenceId] = useState('');
  const [deletedOnly, setDeletedOnly] = useState(true);
  return (
    <div className="fade">
      <Title
        title="Deleted File Recovery"
        sub="Browse the Sleuth Kit file index of an analyzed image and recover files with icat. Recovered copies are hashed and logged to the chain of custody."
        action={
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <CasePicker value={caseId} onChange={setCaseId} />
            <EvidencePicker caseId={caseId} value={evidenceId} onChange={setEvidenceId} />
          </div>
        }
      />
      <Card style={{ padding: 20 }}>
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13, marginBottom: 12 }}>
          <input type="checkbox" checked={deletedOnly} onChange={(e) => setDeletedOnly(e.target.checked)} /> Deleted entries only
        </label>
        {evidenceId ? <FilesTable key={`${evidenceId}-${deletedOnly}`} evidenceId={evidenceId} deletedOnly={deletedOnly} /> : <Empty text="Select evidence that has been analyzed." />}
      </Card>
    </div>
  );
}

/* =========================================================================
   4. TIMELINE ANALYSIS
========================================================================= */
const TIMELINE_TYPES: Record<string, string> = {
  ALL: '',
  NOTABLE: 'BROWSER_VISIT,BROWSER_DOWNLOAD,USB_ACTIVITY',
  FILE: 'FILE_MACB',
  BROWSER: 'BROWSER_VISIT,BROWSER_DOWNLOAD',
  USB: 'USB_ACTIVITY',
};

export function Timeline() {
  const [caseId, setCaseId] = useState('');
  const [filter, setFilter] = useState('ALL');
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState('');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [order, setOrder] = useState<'asc' | 'desc'>('asc');
  const [skip, setSkip] = useState(0);
  const limit = 200;
  const params = new URLSearchParams({ limit: String(limit), skip: String(skip), order });
  if (caseId) params.set('case_id', caseId);
  if (TIMELINE_TYPES[filter]) params.set('type', TIMELINE_TYPES[filter]);
  if (search) params.set('q', search);
  if (start) params.set('start', new Date(start).toISOString());
  if (end) params.set('end', new Date(end).toISOString());
  const [res, setRes] = useState<any>(null);
  useEffect(() => {
    if (!caseId) return;
    api<any>('/forensics/timeline?' + params.toString()).then(setRes).catch((e) => setRes({ data: [], error: e.message }));
  }, [params.toString()]);
  useEffect(() => setSkip(0), [caseId, filter, search, start, end, order]);
  const events = res?.data || [];

  return (
    <div className="fade">
      <Title
        title="Unified Timeline Analysis"
        sub="Filesystem MACB times (Sleuth Kit), browser visits and downloads, and USB device events in one chronology. Times shown in your local time zone."
        action={<CasePicker value={caseId} onChange={setCaseId} />}
      />

      <Card style={{ padding: 16, marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <select className="input" style={{ width: 190 }} value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="ALL">All event types</option>
            <option value="NOTABLE">Browser + USB only</option>
            <option value="FILE">Filesystem (MACB)</option>
            <option value="BROWSER">Browser activity</option>
            <option value="USB">USB activity</option>
          </select>
          <input className="input" style={{ width: 240 }} value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(query)} placeholder="Search descriptions (Enter)…" />
          <label className="muted" style={{ fontSize: 12 }}>From <input className="input" type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} style={{ width: 200 }} /></label>
          <label className="muted" style={{ fontSize: 12 }}>To <input className="input" type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} style={{ width: 200 }} /></label>
          <Button sm onClick={() => setOrder(order === 'asc' ? 'desc' : 'asc')}>{order === 'asc' ? 'Oldest first' : 'Newest first'}</Button>
          <span className="muted" style={{ fontSize: 12 }}>{res ? `${res.total ?? 0} events` : ''}</span>
          {res?.error && <span className="badge danger">{res.error}</span>}
        </div>
      </Card>

      <Card style={{ padding: 0 }}>
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Event Timestamp</th>
                <th>Category</th>
                <th>Forensic Observation / Evidence Source</th>
                <th>Artifact Source</th>
              </tr>
            </thead>
            <tbody>
              {events.map((x: any) => (
                <tr key={x._id}>
                  <td className="mono" style={{ fontSize: 12, whiteSpace: 'nowrap', color: 'var(--ink-light)' }}>
                    {new Date(x.timestamp).toLocaleString()}
                  </td>
                  <td>
                    <span className="badge">{x.type || 'SYSTEM'}</span>
                  </td>
                  <td>
                    <div style={{ fontWeight: 500, fontSize: 13.5 }}>{x.description}</div>
                  </td>
                  <td>
                    <span className="badge ok" style={{ fontSize: 10 }}>{x.source || 'ARTIFACT_PARSER'}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!events.length && <Empty text={caseId ? 'No matching events. Run Full Analysis on the case evidence to build its timeline.' : 'Select a case.'} />}
        </div>
      </Card>
      {res && res.total > limit && (
        <div style={{ display: 'flex', gap: 8, marginTop: 12, alignItems: 'center' }}>
          <Button sm disabled={skip === 0} onClick={() => setSkip(Math.max(0, skip - limit))}>← Prev</Button>
          <span className="muted" style={{ fontSize: 12 }}>{skip + 1}–{Math.min(skip + limit, res.total)} of {res.total}</span>
          <Button sm disabled={skip + limit >= res.total} onClick={() => setSkip(skip + limit)}>Next →</Button>
        </div>
      )}
    </div>
  );
}

/* =========================================================================
   5. SPECIALIST MODULES (Browser, USB, Email, Network, Malware, AI Assistant)
========================================================================= */
export function Module({
  name,
  icon: Icon = I.Activity,
  description
}: {
  name: string;
  icon?: any;
  description: string;
}) {
  const [caseId, setCaseId] = useState('CASE-2026-001');
  const [evidenceId, setEvidenceId] = useState('');
  const [inode, setInode] = useState('');
  const [offset, setOffset] = useState('0');
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  const typeMap: any = {
    'Browser Forensics': 'BROWSER_ACTIVITY',
    'USB Forensics': 'USB_ACTIVITY',
    'Email Forensics': 'EMAIL_ACTIVITY',
    'Network Forensics': 'NETWORK_ACTIVITY',
    'Malware Analysis': 'MALWARE_INDICATOR',
    'File Recovery': 'RECOVERED_FILE'
  };

  const artifactType = typeMap[name];
  const endpoint = artifactType
    ? `/forensics/artifacts?case_id=${encodeURIComponent(caseId)}&artifact_type=${encodeURIComponent(artifactType)}`
    : name === 'Timeline'
    ? `/forensics/timeline?case_id=${encodeURIComponent(caseId)}`
    : `/forensics/artifacts?case_id=${encodeURIComponent(caseId)}`;

  const { data, error, reload } = useLoad(endpoint);

  async function run() {
    setBusy(true);
    setResult(null);
    try {
      if (name === 'Patterns') {
        setResult(await api(`/forensics/patterns?case_id=${encodeURIComponent(caseId)}`, { method: 'POST' }));
      } else if (name === 'Anomalies') {
        setResult(await api(`/forensics/anomalies?case_id=${encodeURIComponent(caseId)}`, { method: 'POST' }));
      } else if (name === 'Acquisition') {
        const es = await api<any>('/evidence');
        const first = (es.data || []).find((x: any) => !evidenceId || x.evidence_id === evidenceId);
        if (!first) return alert('Select or upload an evidence image first.');
        setEvidenceId(first.evidence_id);
        setResult(await api(`/jobs/analysis/${encodeURIComponent(first.evidence_id)}`, { method: 'POST' }));
      } else if (name === 'File Recovery') {
        if (!evidenceId || !inode) return alert('Please enter Evidence ID and Inode.');
        setResult(await api(`/forensics/evidence/${encodeURIComponent(evidenceId)}/recover?inode=${encodeURIComponent(inode)}&offset=${encodeURIComponent(offset)}`, { method: 'POST' }));
      }
      reload();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function examine() {
    if (!evidenceId) return alert('Enter Evidence ID.');
    setBusy(true);
    try {
      setResult(await api(`/forensics/evidence/${encodeURIComponent(evidenceId)}/examine?offset=${encodeURIComponent(offset)}`, { method: 'POST' }));
      reload();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function ask() {
    if (!question.trim()) return;
    setBusy(true);
    try {
      setAnswer(await api(`/forensics/ai?case_id=${encodeURIComponent(caseId)}&question=${encodeURIComponent(question)}`, { method: 'POST' }));
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  // Determine if this module's primary action is desktop-only
  const desktopOnlyModules = ['Acquisition', 'File Recovery'];
  const isDesktopOnly = desktopOnlyModules.includes(name);

  return (
    <div className="fade">
      <Title title={name} sub={description} />

      {/* Desktop-only guard for acquisition and file recovery */}
      {isDesktopOnly && !canWrite ? (
        <DesktopRequired
          operation={name}
          description={
            name === 'Acquisition'
              ? 'Evidence acquisition requires the DFIP Desktop to access local forensic images and compute cryptographic hashes without transferring evidence files.'
              : 'File recovery (icat/inode extraction) requires the DFIP Desktop to access local forensic images directly.'
          }
          jobType={name === 'Acquisition' ? 'DESKTOP_ACQUIRE_EVIDENCE' : 'DESKTOP_RUN_TOOL'}
          jobPayload={name === 'Acquisition' ? { case_id: caseId } : { tool: 'icat', args: [] }}
        />
      ) : (
        /* Action Toolbar */
        <Card style={{ marginBottom: 20, padding: 20 }}>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
            {/* Operation badge */}
            <OperationBadge type={
              isDesktopOnly ? 'DESKTOP' :
              ['Patterns', 'Anomalies', 'AI Assistant'].includes(name) ? 'WEB' : 'WEB+SYNC'
            } />

            <input
              className="input"
              style={{ maxWidth: 220 }}
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              placeholder="Case ID (e.g. CASE-2026-001)"
            />

            {(name === 'Acquisition' || name === 'File Recovery') && (
              <input
                className="input"
                style={{ maxWidth: 220 }}
                value={evidenceId}
                onChange={(e) => setEvidenceId(e.target.value)}
                placeholder="Evidence ID (e.g. EVID-001)"
              />
            )}

            {name === 'File Recovery' && (
              <>
                <input className="input" style={{ maxWidth: 130 }} value={inode} onChange={(e) => setInode(e.target.value)} placeholder="Inode #" />
                <input className="input" style={{ maxWidth: 120 }} value={offset} onChange={(e) => setOffset(e.target.value)} placeholder="Sector Offset" />
              </>
            )}

            {canWrite && ['Patterns', 'Anomalies', 'Acquisition', 'File Recovery'].includes(name) && (
              <Button primary onClick={run} disabled={busy}>
                {busy ? 'Executing Parser…' : name === 'Acquisition' ? 'Queue Background Triage' : name === 'File Recovery' ? 'Recover Inode' : 'Run Pattern Detection'}
              </Button>
            )}

            {!canWrite && ['Patterns', 'Anomalies'].includes(name) && (
              <span className="badge" style={{ fontSize: 11, padding: '6px 10px' }}>
                Analysis Engine Restricted to Desktop Workstation
              </span>
            )}

            {canWrite && name === 'Acquisition' && (
              <Button onClick={examine} disabled={busy}>
                {busy ? 'Inspecting…' : 'Inspect Partition Table'}
              </Button>
            )}

            {name === 'AI Assistant' && (
              <>
                <input
                  className="input"
                  style={{ flex: 1, minWidth: 260 }}
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  placeholder="Ask about extracted evidence (e.g., Which USB devices were inserted?)"
                />
                <Button primary onClick={ask} disabled={busy}>
                  {busy ? 'Analyzing Evidence…' : 'Interrogate Case'}
                </Button>
              </>
            )}
          </div>
        </Card>
      )}

      {/* Execution Result */}
      {result && (
        <Card style={{ marginBottom: 20, borderLeft: '4px solid var(--green)' }}>
          <div className="badge ok" style={{ marginBottom: 10 }}>PARSER OUTPUT</div>
          <pre className="mono" style={{ margin: 0, fontSize: 12, lineHeight: 1.6, overflowX: 'auto', background: 'var(--bg-subtle)', padding: 14, borderRadius: 8 }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </Card>
      )}

      {/* AI Assistant Output */}
      {answer && (
        <Card style={{ marginBottom: 20, borderLeft: '4px solid var(--red)' }}>
          <div className="badge warn" style={{ marginBottom: 12 }}>EVIDENCE-GROUNDED REASONING</div>
          <div style={{ fontSize: 14, lineHeight: 1.7, whiteSpace: 'pre-wrap', color: 'var(--ink)' }}>
            {answer.answer}
          </div>
          {answer.disclaimer && (
            <div className="muted" style={{ fontSize: 11, marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
              {answer.disclaimer}
            </div>
          )}
        </Card>
      )}

      {/* Extracted Artifacts Table */}
      {name !== 'AI Assistant' && (
        <Card style={{ padding: 0 }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
            <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0 }}>Extracted Forensic Records</h3>
          </div>
          {error && <div className="badge danger" style={{ margin: 16 }}>{error}</div>}
          <div className="table-container" style={{ border: 'none' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Artifact Class</th>
                  <th>Source Evidence</th>
                  <th>Extracted Metadata / Value</th>
                  <th>Recorded Time</th>
                </tr>
              </thead>
              <tbody>
                {(data || []).map((x: any) => (
                  <tr key={x._id}>
                    <td><span className="badge">{x.type || 'ARTIFACT'}</span></td>
                    <td className="mono">{x.evidence_id || '—'}</td>
                    <td>
                      <div style={{ fontWeight: 500, fontSize: 13 }}>
                        {x.description || x.source || JSON.stringify(x.data || {})}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {x.timestamp ? new Date(x.timestamp).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!(data || []).length && (
              <Empty text={`No ${name.toLowerCase()} records extracted for this case yet.`} />
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

/* =========================================================================
   6. THREAT INTEL
========================================================================= */
export function ThreatIntel() {
  const [caseId, setCaseId] = useState('CASE-2026-001');
  const [indicator, setIndicator] = useState('');
  const [kind, setKind] = useState<'hash' | 'ip' | 'domain'>('hash');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const { data: providers } = useLoad('/threat-intel/providers');

  async function lookup() {
    if (!indicator.trim()) return alert('Enter an indicator value.');
    setBusy(true);
    setResult(null);
    try {
      const path = `/threat-intel/${kind === 'hash' ? 'hash' : kind}/${encodeURIComponent(indicator.trim())}?case_id=${encodeURIComponent(caseId)}`;
      setResult(await api(path, { method: 'POST' }));
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fade">
      <Title
        title="Live Threat Intelligence"
        sub="Multi-provider reputation lookups against VirusTotal, AbuseIPDB, AlienVault OTX, and URLhaus."
      />

      <Card style={{ marginBottom: 20, padding: 22 }}>
        {/* Provider Badges */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 16 }}>
          <span className="muted" style={{ fontSize: 11.5, fontWeight: 700 }}>FEEDS:</span>
          {providers ? (
            Object.entries(providers).map(([k, v]: any) => (
              <span key={k} className={v ? 'badge ok' : 'badge'} style={{ fontSize: 11 }}>
                {k}: {v ? 'ONLINE' : 'NOT CONFIGURED'}
              </span>
            ))
          ) : (
            <span className="muted" style={{ fontSize: 11 }}>Loading feeds…</span>
          )}
        </div>

        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            className="input"
            style={{ maxWidth: 200 }}
            value={caseId}
            onChange={(e) => setCaseId(e.target.value)}
            placeholder="Case ID"
          />
          <select className="input" style={{ maxWidth: 160 }} value={kind} onChange={(e) => setKind(e.target.value as any)}>
            <option value="hash">File Hash (MD5/SHA)</option>
            <option value="ip">IPv4 / IPv6 Address</option>
            <option value="domain">Domain / Hostname</option>
          </select>
          <input
            className="input"
            style={{ flex: 1, minWidth: 240 }}
            value={indicator}
            onChange={(e) => setIndicator(e.target.value)}
            placeholder={kind === 'hash' ? 'Enter SHA-256 or MD5 hash…' : kind === 'ip' ? 'Enter IP address (e.g. 198.51.100.1)…' : 'Enter domain (e.g. malformed-domain.xyz)…'}
          />
          <Button primary onClick={lookup} disabled={busy}>
            {busy ? 'Querying Feeds…' : 'Query Threat Feeds'}
          </Button>
        </div>
      </Card>

      {result && (
        <Card style={{ borderLeft: '4px solid var(--red)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <span className="badge ok">FEED RESPONSE VERDICT</span>
            <span className="mono" style={{ fontSize: 12 }}>Indicator: {indicator}</span>
          </div>
          <pre className="mono" style={{ margin: 0, fontSize: 12, lineHeight: 1.6, overflowX: 'auto', background: 'var(--bg-subtle)', padding: 14, borderRadius: 8 }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  );
}

/* =========================================================================
   7. FILE CARVING
========================================================================= */
export function Carving() {
  const [evidenceId, setEvidenceId] = useState('');
  const [engine, setEngine] = useState('photorec');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);

  async function run() {
    if (!evidenceId.trim()) return alert('Enter Evidence ID.');
    setBusy(true);
    setResult(null);
    try {
      setResult(await api(`/forensics/evidence/${encodeURIComponent(evidenceId.trim())}/carve?engine=${engine}`, { method: 'POST' }));
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fade">
      <Title
        title="Signature File Carving"
        sub="Perform raw block-level header/footer signature recovery for deleted or unallocated file fragments."
      />

      {!canWrite ? (
        <div style={{ marginBottom: 20 }}>
          <DesktopRequired
            operation="Signature File Carving"
            description="Direct block-level file carving requires access to the raw forensic image stored on the physical workstation."
            jobType="DESKTOP_RUN_TOOL"
            jobPayload={{ tool: engine, evidence_id: evidenceId }}
          />
        </div>
      ) : (
        <Card style={{ marginBottom: 20, padding: 22 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              className="input"
              style={{ maxWidth: 260 }}
              value={evidenceId}
              onChange={(e) => setEvidenceId(e.target.value)}
              placeholder="Target Evidence ID (e.g. EVID-001)"
            />
            <select className="input" style={{ maxWidth: 180 }} value={engine} onChange={(e) => setEngine(e.target.value)}>
              <option value="photorec">PhotoRec Carver</option>
              <option value="scalpel">Scalpel Carver</option>
            </select>
            <Button primary onClick={run} disabled={busy}>
              {busy ? 'Scanning File Headers…' : 'Execute Carving Job'}
            </Button>
          </div>
        </Card>
      )}

      {result && (
        <Card>
          {result.status === 'TOOL_UNAVAILABLE' ? (
            <div className="badge warn">Carving binary not installed on host adapter layer.</div>
          ) : (
            <pre className="mono" style={{ margin: 0, fontSize: 12, lineHeight: 1.6, overflowX: 'auto', background: 'var(--bg-subtle)', padding: 14, borderRadius: 8 }}>
              {JSON.stringify(result, null, 2)}
            </pre>
          )}
        </Card>
      )}
    </div>
  );
}

/* =========================================================================
   8. FINDINGS & REPORTS
========================================================================= */
export function Findings() {
  const { data, reload } = useLoad('/findings');
  const [caseId, setCaseId] = useState('CASE-2026-001');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('HIGH');
  const [busy, setBusy] = useState(false);

  async function create() {
    if (!title.trim() || !description.trim()) return alert('Please enter finding title and description.');
    setBusy(true);
    try {
      await api('/findings', {
        method: 'POST',
        body: JSON.stringify({
          case_id: caseId,
          title: title.trim(),
          description: description.trim(),
          severity,
          evidence_ids: [],
          timeline_ids: []
        })
      });
      setTitle('');
      setDescription('');
      reload();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fade">
      <Title
        title="Investigator Findings"
        sub="Formally document forensic observations linked directly to verified evidence and timeline events."
      />

      {canWrite ? (
        <Card style={{ marginBottom: 20, padding: 22 }}>
          <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 14px' }}>Document New Observation</h3>
          <div style={{ display: 'grid', gap: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr 160px', gap: 10 }}>
              <input className="input" value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="Case ID" />
              <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Finding Headline (e.g. Tor Browser Activity Detected)" />
              <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="LOW">Severity: LOW</option>
                <option value="MEDIUM">Severity: MEDIUM</option>
                <option value="HIGH">Severity: HIGH</option>
                <option value="CRITICAL">Severity: CRITICAL</option>
              </select>
            </div>
            <textarea
              className="input"
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Detailed investigative notes, artifacts observed, and legal significance..."
            />
            <Button primary onClick={create} disabled={busy} style={{ justifySelf: 'flex-start' }}>
              {busy ? 'Recording…' : '+ Record Formal Finding'}
            </Button>
          </div>
        </Card>
      ) : (
        <div style={{ padding: '14px 18px', background: 'var(--bg-subtle)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', marginBottom: 20, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <I.FileCheck size={16} className="muted" />
            <span style={{ fontSize: 13, color: 'var(--ink-light)' }}>
              Case findings are recorded via the <b>DFIP Desktop Workstation</b> to maintain chain of custody with raw evidence. Review documented findings below.
            </span>
          </div>
          <span className="badge" style={{ fontSize: 11 }}>Read-Only Records</span>
        </div>
      )}

      <div style={{ display: 'grid', gap: 12 }}>
        {(data || []).map((x: any) => (
          <Card key={x._id} style={{ padding: 20, borderLeft: `4px solid ${x.severity === 'CRITICAL' ? 'var(--danger)' : x.severity === 'HIGH' ? 'var(--amber)' : 'var(--info)'}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <PriorityBadge priority={x.severity} />
              <span className="mono" style={{ fontSize: 11, color: 'var(--muted)' }}>Case: {x.case_id}</span>
            </div>
            <h3 style={{ fontSize: 16, fontWeight: 700, margin: '0 0 8px' }}>{x.title}</h3>
            <p className="muted" style={{ fontSize: 13.5, lineHeight: 1.6, margin: 0 }}>{x.description}</p>
          </Card>
        ))}
        {!(data || []).length && <Empty text="No findings documented yet." />}
      </div>
    </div>
  );
}

export function Reports() {
  const { data, reload } = useLoad('/reports');
  const [caseId, setCaseId] = useState('CASE-2026-001');
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true);
    try {
      await api(`/reports?case_id=${encodeURIComponent(caseId)}`, { method: 'POST' });
      reload();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fade">
      <Title
        title="Forensic Reports & Documentation"
        sub="Generate court-admissible PDF investigation reports with cryptographic report hashes and custody metadata."
        action={
          canWrite ? (
            <div style={{ display: 'flex', gap: 10 }}>
              <input className="input" style={{ width: 200 }} value={caseId} onChange={(e) => setCaseId(e.target.value)} />
              <Button primary onClick={create} disabled={busy}>
                {busy ? 'Generating PDF…' : '+ Generate Versioned Report'}
              </Button>
            </div>
          ) : (
            <div className="badge ok" style={{ fontSize: 11.5, padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
              <I.FileText size={14} />
              <span>PDF Export Active</span>
            </div>
          )
        }
      />

      <Card style={{ padding: 0 }}>
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Report ID</th>
                <th>Target Case</th>
                <th>Document Version</th>
                <th>Compiled At</th>
                <th>Export</th>
              </tr>
            </thead>
            <tbody>
              {(data || []).map((x: any) => (
                <tr key={x._id}>
                  <td>
                    <span className="mono" style={{ fontWeight: 700, color: 'var(--red)' }}>{x.report_id}</span>
                  </td>
                  <td className="mono">{x.case_id}</td>
                  <td><span className="badge">v{x.version}</span></td>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(x.created_at).toLocaleString()}</td>
                  <td>
                    <Button sm onClick={() => downloadReport(x.report_id)}>
                      <I.Download size={13} /> Download PDF
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!(data || []).length && <Empty text="No reports compiled yet. Click 'Generate Versioned Report' above." />}
        </div>
      </Card>
    </div>
  );
}

/* =========================================================================
   9. CHAIN OF CUSTODY & AUDIT
========================================================================= */
export function Chain() {
  const { data } = useLoad('/chain');
  const rows = (data || []).filter((x: any) => String(x.action).includes('EVIDENCE'));

  return (
    <div className="fade">
      <Title
        title="Chain of Custody Ledger"
        sub="Legally traceable, append-only custody events for evidence handling, examination, and transfer."
      />

      <Card style={{ padding: 0 }}>
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Logged Timestamp</th>
                <th>Investigator / Handler</th>
                <th>Custody Action</th>
                <th>Target Evidence Object</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((x: any) => (
                <tr key={x._id}>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(x.timestamp).toLocaleString()}</td>
                  <td><div style={{ fontWeight: 600 }}>{x.user_name}</div></td>
                  <td><span className="badge ok">{x.action}</span></td>
                  <td className="mono">{x.resource_type} / {x.resource_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && <Empty text="No custody transfer events recorded yet." />}
        </div>
      </Card>
    </div>
  );
}

export function Audit() {
  const { data } = useLoad('/admin/audit');

  return (
    <div className="fade">
      <Title
        title="Tamper-Evident Audit Trail"
        sub="Cryptographically chained audit records guaranteeing unalterable accountability across all operations."
      />

      <Card style={{ padding: 0 }}>
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Seq #</th>
                <th>Timestamp</th>
                <th>Operator</th>
                <th>Action</th>
                <th>Resource</th>
              </tr>
            </thead>
            <tbody>
              {(data || []).map((x: any) => (
                <tr key={x._id}>
                  <td className="mono" style={{ fontWeight: 700, color: 'var(--red)' }}>#{x.sequence ?? '—'}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(x.timestamp).toLocaleString()}</td>
                  <td><div style={{ fontWeight: 600 }}>{x.user_name}</div></td>
                  <td><span className="badge">{x.action}</span></td>
                  <td className="mono">{x.resource_type} / {x.resource_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!(data || []).length && <Empty text="No audit records available." />}
        </div>
      </Card>
    </div>
  );
}

export function Notifications() {
  const { data, reload } = useLoad('/notifications');

  async function markRead(id: string) {
    await api(`/notifications/${id}/read`, { method: 'PATCH' });
    reload();
  }

  return (
    <div className="fade">
      <Title
        title="Investigation Alert Center"
        sub="Real-time alerts for completed background tasks, integrity audits, and case updates."
      />

      <div style={{ display: 'grid', gap: 12 }}>
        {(data || []).map((x: any) => (
          <Card key={x._id} style={{ padding: 18, opacity: x.read ? 0.65 : 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{x.title}</div>
                <div className="muted" style={{ fontSize: 13.5 }}>{x.message}</div>
              </div>
              {!x.read && (
                <Button sm onClick={() => markRead(x._id)}>
                  Mark as Read
                </Button>
              )}
            </div>
          </Card>
        ))}
        {!(data || []).length && <Empty text="No notifications in your alert center." />}
      </div>
    </div>
  );
}

/* =========================================================================
   10. ADMIN CONSOLE (Users, Roles, Security, Settings, Jobs, Tooling)
========================================================================= */
export function AdminUsers() {
  const { data, reload } = useLoad('/admin/users');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('INVESTIGATOR');
  const [busy, setBusy] = useState(false);

  async function create() {
    if (!name || !email || !password) return alert('Fill in all user fields.');
    setBusy(true);
    try {
      await api('/admin/users', {
        method: 'POST',
        body: JSON.stringify({ name, email, role, password })
      });
      setName('');
      setEmail('');
      setPassword('');
      reload();
    } catch (e: any) {
      alert(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function toggle(u: any) {
    await api(`/admin/users/${u._id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: u.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE' })
    });
    reload();
  }

  return (
    <div className="fade">
      <Title title="User Provisioning" sub="Create investigator accounts and manage authentication states." />

      <Card style={{ marginBottom: 20, padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 12px' }}>Provision Investigator Identity</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr 160px 150px auto', gap: 10 }}>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Full Name" />
          <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="user@agency.local" />
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Temp Pass (12+)" />
          <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="INVESTIGATOR">INVESTIGATOR</option>
            <option value="ANALYST">ANALYST</option>
            <option value="VIEWER">VIEWER</option>
            <option value="ADMIN">ADMIN</option>
          </select>
          <Button primary onClick={create} disabled={busy}>
            {busy ? 'Provisioning…' : '+ Add User'}
          </Button>
        </div>
      </Card>

      <Card style={{ padding: 0 }}>
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Identity</th>
                <th>Email Address</th>
                <th>Role</th>
                <th>Account Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(data || []).map((u: any) => (
                <tr key={u._id}>
                  <td><div style={{ fontWeight: 700 }}>{u.name}</div></td>
                  <td className="mono" style={{ fontSize: 12 }}>{u.email}</td>
                  <td><span className="badge">{u.role}</span></td>
                  <td><StatusBadge status={u.status} /></td>
                  <td>
                    <Button sm danger={u.status === 'ACTIVE'} onClick={() => toggle(u)}>
                      {u.status === 'ACTIVE' ? 'Suspend' : 'Activate'}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

export function AdminRoles() {
  const { data, reload } = useLoad('/admin/roles');
  const perms = [
    'USER_MANAGE', 'ROLE_MANAGE', 'CASE_CREATE', 'CASE_READ', 'CASE_UPDATE',
    'CASE_ARCHIVE', 'EVIDENCE_UPLOAD', 'EVIDENCE_READ', 'EVIDENCE_VERIFY',
    'ANALYSIS_RUN', 'FINDING_CREATE', 'REPORT_CREATE', 'REPORT_READ',
    'REPORT_EXPORT', 'AUDIT_READ', 'SYSTEM_MANAGE'
  ];

  async function save(name: string, p: any[]) {
    await api(`/admin/roles/${name}`, {
      method: 'PATCH',
      body: JSON.stringify({ permissions: p })
    });
    reload();
  }

  return (
    <div className="fade">
      <Title title="Roles & Permission Matrix" sub="Granular backend-enforced access control policies." />

      <div className="grid2">
        {(data || []).map((r: any) => (
          <Card key={r.name} style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <h3 style={{ fontSize: 17, fontWeight: 800, margin: 0 }}>{r.name}</h3>
              <span className="badge">{r.permissions?.length || 0} PERMISSIONS</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
              {perms.map((p) => (
                <label key={p} style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, color: 'var(--ink-light)' }}>
                  <input
                    type="checkbox"
                    checked={r.permissions?.includes(p)}
                    onChange={(e) =>
                      save(r.name, e.target.checked ? [...(r.permissions || []), p] : (r.permissions || []).filter((x: string) => x !== p))
                    }
                  />
                  {p}
                </label>
              ))}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

export function AdminSecurity() {
  const { data } = useLoad('/admin/security');

  return (
    <div className="fade">
      <Title title="Security & Authentication Telemetry" sub="Audit events for logins, verification checks, and administrative updates." />

      <Card style={{ padding: 0 }}>
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Event Type</th>
                <th>Investigator Identity</th>
                <th>Recorded Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {(data || []).map((x: any) => (
                <tr key={x._id}>
                  <td><span className="badge ok">{x.action}</span></td>
                  <td><b>{x.user_name}</b></td>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(x.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

export function AdminSettings() {
  return (
    <div className="fade">
      <Title title="System Infrastructure Settings" sub="Runtime configuration health and backend service discovery." />

      <div className="grid2">
        {[
          ['MongoDB System of Record', 'MongoDB 8 engine storing cases, users, and audit hash chains.', 'ONLINE'],
          ['Filesystem Evidence Vault', 'WORM storage for immutable disk images and recovered files.', 'CONFIGURED'],
          ['FastAPI Execution Layer', 'Asynchronous API with strict Pydantic model validation.', 'ACTIVE'],
          ['Celery Task Broker', 'Distributed worker queue for long-running forensic analysis.', 'CONFIGURED'],
          ['Threat Intel Adapters', 'Live integrations for VirusTotal, AbuseIPDB, and AlienVault OTX.', 'READY'],
          ['WebSocket Realtime Sync', 'Authenticated real-time investigator notifications.', 'ONLINE']
        ].map(([a, b, status]) => (
          <Card key={a} style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>{a}</h3>
              <span className="badge ok">{status}</span>
            </div>
            <p className="muted" style={{ fontSize: 13, margin: 0 }}>{b}</p>
          </Card>
        ))}
      </div>
    </div>
  );
}

export function Jobs() {
  const { data, reload } = useLoad('/jobs');

  async function cancel(id: string) {
    try {
      await api(`/jobs/${id}/cancel`, { method: 'POST' });
      reload();
    } catch (e: any) {
      alert(e.message);
    }
  }

  return (
    <div className="fade">
      <Title title="Background Job Center" sub="Monitor long-running disk parsing and analysis jobs." />

      <Card style={{ padding: 0 }}>
        <div className="table-container" style={{ border: 'none' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Job Identifier</th>
                <th>Operation Type</th>
                <th>Progress</th>
                <th>Status</th>
                <th>Submitted Timestamp</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {(data || []).map((x: any) => (
                <tr key={x._id}>
                  <td className="mono" style={{ fontWeight: 700, color: 'var(--red)' }}>{x.job_id}</td>
                  <td><b>{x.type}</b></td>
                  <td style={{ width: 140 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ flex: 1, height: 6, background: 'var(--bg-subtle)', borderRadius: 999, overflow: 'hidden' }}>
                        <div style={{ width: `${x.progress || 0}%`, height: '100%', background: 'var(--red)', borderRadius: 999 }} />
                      </div>
                      <span className="mono" style={{ fontSize: 11 }}>{x.progress || 0}%</span>
                    </div>
                  </td>
                  <td><StatusBadge status={x.status} /></td>
                  <td className="mono" style={{ fontSize: 12 }}>{new Date(x.created_at).toLocaleString()}</td>
                  <td>
                    {['QUEUED', 'RUNNING'].includes(x.status) && (
                      <Button sm danger onClick={() => cancel(x.job_id)}>
                        Cancel Job
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!(data || []).length && <Empty text="No active or past background jobs in queue." />}
        </div>
      </Card>
    </div>
  );
}

export function Tooling() {
  const { data, error } = useLoad('/forensics/tooling');

  return (
    <div className="fade">
      <Title title="Forensic Adapter Inventory" sub="Binary availability report for integrated forensic tools and system adapters." />

      {error && <div className="badge danger" style={{ marginBottom: 16 }}>{error}</div>}

      <div className="grid3">
        {Object.entries(data || {}).map(([name, x]: any) => (
          <Card key={name} style={{ padding: 22, borderTop: '4px solid var(--red)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--ink)' }}>{name}</h3>
                <span className={x.available ? 'badge ok' : 'badge'}>
                  {x.available ? 'AVAILABLE' : 'NOT INSTALLED'}
                </span>
              </div>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--muted)', background: 'var(--bg-subtle)', padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)' }}>
                Binary: {x.binary}
              </div>
            </div>
            <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid var(--border)', fontSize: 11.5, color: 'var(--muted)', display: 'flex', justifyContent: 'space-between' }}>
              <span>Adapter Status</span>
              <span style={{ fontWeight: 600, color: x.available ? 'var(--green-dark)' : 'var(--muted)' }}>
                {x.available ? '● Operational' : '○ Standby'}
              </span>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

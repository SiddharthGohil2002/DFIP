import { useContext, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  ShieldCheck,
  Download,
  LockKeyhole,
  Monitor,
  Activity,
  Cpu,
  Layers,
  FileCheck2,
  HardDrive,
  FileSearch,
  CheckCircle2,
  Key,
  Database,
  ExternalLink,
  Copy,
  Check,
  AlertTriangle,
  Scale
} from 'lucide-react';
import { api } from '../services/api';
import { AuthContext } from '../main';
import Card3D from '../components/Card3D';

/* =========================================================================
   REUSABLE ENTERPRISE PUBLIC HEADER
========================================================================= */
export function PublicHeader({ activeNav }: { activeNav?: string }) {
  return (
    <header className="glass" style={{ position: 'sticky', top: 0, zIndex: 40, borderBottom: '1px solid var(--border)', background: 'rgba(255, 255, 255, 0.95)' }}>
      <div style={{ maxWidth: 1300, margin: '0 auto', padding: '14px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <img
            src="/dfip-logo.svg"
            alt="DFIP Logo"
            style={{ width: 36, height: 36, filter: 'drop-shadow(0 2px 6px rgba(200, 16, 46, 0.3))' }}
          />
          <div>
            <div style={{ fontWeight: 800, fontSize: 16, letterSpacing: '-0.02em', color: 'var(--ink)' }}>DFIP</div>
            <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--muted)', letterSpacing: '0.06em' }}>DIGITAL FORENSICS PLATFORM</div>
          </div>
        </Link>

        <nav style={{ display: 'flex', alignItems: 'center', gap: 24, fontSize: 13.5, fontWeight: 600 }}>
          <Link to="/" className={activeNav === 'home' ? '' : 'muted'} style={{ color: activeNav === 'home' ? 'var(--red)' : undefined }}>
            Overview
          </Link>
          <Link to="/functions" className={activeNav === 'functions' ? '' : 'muted'} style={{ color: activeNav === 'functions' ? 'var(--red)' : undefined }}>
            Forensic Capabilities
          </Link>
          <Link to="/technology" className={activeNav === 'technology' ? '' : 'muted'} style={{ color: activeNav === 'technology' ? 'var(--red)' : undefined }}>
            Architecture
          </Link>
          <Link to="/security" className={activeNav === 'security' ? '' : 'muted'} style={{ color: activeNav === 'security' ? 'var(--red)' : undefined }}>
            Compliance
          </Link>
          <Link to="/download" className={`btn sm ${activeNav === 'download' ? 'primary' : ''}`} style={{ gap: 6, height: 36 }}>
            <Download size={14} /> Desktop Workstation
          </Link>
          <Link to="/login" className={`btn primary sm ${activeNav === 'login' ? 'active' : ''}`} style={{ gap: 6, height: 36 }}>
            Admin Portal <ArrowRight size={14} />
          </Link>
        </nav>
      </div>
    </header>
  );
}

/* =========================================================================
   REUSABLE ENTERPRISE PUBLIC FOOTER
========================================================================= */
export function PublicFooter() {
  return (
    <footer style={{ background: '#0B0F17', color: '#94A3B8', padding: '60px 24px 28px', borderTop: '1px solid #1E293B' }}>
      <div style={{ maxWidth: 1300, margin: '0 auto', display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: 40, marginBottom: 44 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#FFF', fontWeight: 800, fontSize: 17, marginBottom: 12 }}>
            <span style={{ width: 28, height: 28, borderRadius: 6, background: 'var(--red)', display: 'grid', placeItems: 'center' }}>
              <ShieldCheck size={16} color="#FFF" />
            </span>
            DFIP — DIGITAL FORENSICS INVESTIGATION PLATFORM
          </div>
          <p style={{ fontSize: 13, lineHeight: 1.6, maxWidth: 360, color: '#64748B', margin: 0 }}>
            Enterprise forensic case management, bitstream preservation, real-time investigation telemetry, and tamper-evident audit verification.
          </p>
        </div>

        <div>
          <div style={{ color: '#FFF', fontWeight: 700, fontSize: 12, letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 14 }}>Core Capabilities</div>
          <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
            <Link to="/functions" style={{ color: '#94A3B8' }}>Disk Forensics (E01 / RAW)</Link>
            <Link to="/functions" style={{ color: '#94A3B8' }}>Volatility RAM Triage</Link>
            <Link to="/functions" style={{ color: '#94A3B8' }}>YARA Malware Scans</Link>
            <Link to="/functions" style={{ color: '#94A3B8' }}>File Signature Carving</Link>
          </div>
        </div>

        <div>
          <div style={{ color: '#FFF', fontWeight: 700, fontSize: 12, letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 14 }}>Architecture</div>
          <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
            <Link to="/technology" style={{ color: '#94A3B8' }}>FastAPI & MongoDB 8</Link>
            <Link to="/security" style={{ color: '#94A3B8' }}>Audit Hash Chains</Link>
            <Link to="/download" style={{ color: '#94A3B8' }}>Tauri 2 Windows Client</Link>
            <Link to="/functions" style={{ color: '#94A3B8' }}>Tool Adapters</Link>
          </div>
        </div>

        <div>
          <div style={{ color: '#FFF', fontWeight: 700, fontSize: 12, letterSpacing: '0.05em', textTransform: 'uppercase', marginBottom: 14 }}>System Access</div>
          <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
            <Link to="/login" style={{ color: '#94A3B8' }}>Admin Web Portal</Link>
            <Link to="/download" style={{ color: '#94A3B8' }}>Investigator Workstation</Link>
            <span style={{ color: '#475569' }}>Version 2.0.0 Production</span>
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 1300, margin: '0 auto', paddingTop: 20, borderTop: '1px solid #1E293B', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12, color: '#64748B', flexWrap: 'wrap', gap: 12 }}>
        <div>© 2026 DFIP Digital Forensics Platform. All original evidence objects preserved read-only.</div>
        <div>Engineered to ISO/IEC 27037 and Federal Rules of Evidence Standards.</div>
      </div>
    </footer>
  );
}

/* =========================================================================
   1. LANDING PAGE — CLEAN, SIMPLE & VERY PROFESSIONAL
========================================================================= */
export function Landing() {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg)' }}>
      <PublicHeader activeNav="home" />

      {/* Hero Section */}
      <section style={{ padding: '80px 24px 70px', background: 'radial-gradient(ellipse at 50% 20%, rgba(200, 16, 46, 0.05) 0%, transparent 70%)' }}>
        <div style={{ maxWidth: 1100, margin: '0 auto', textAlign: 'center' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 999, background: 'var(--red-light)', border: '1px solid rgba(200,16,46,0.18)', marginBottom: 20 }}>
            <span className="beacon active" />
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--red)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              DFIP Enterprise Digital Forensics Suite
            </span>
          </div>

          <h1 style={{ fontSize: 'clamp(32px, 5vw, 54px)', fontWeight: 800, lineHeight: 1.15, letterSpacing: '-0.03em', color: 'var(--ink)', margin: '0 0 20px' }}>
            Forensic Integrity & <br />
            <span style={{ color: 'var(--red)' }}>Real-Time Investigation Telemetry</span>
          </h1>

          <p style={{ fontSize: 17, lineHeight: 1.6, color: 'var(--muted)', maxWidth: 740, margin: '0 auto 36px' }}>
            Production-grade digital forensics platform engineered for complete evidence admissibility. Features bitstream preservation with dual SHA-256 and SHA-512 cryptographic verification, tamper-evident audit hash chains, and real-time operational telemetry.
          </p>

          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
            <Link to="/download" className="btn primary" style={{ height: 46, padding: '0 24px', fontSize: 15, gap: 8, fontWeight: 700 }}>
              <Download size={17} /> Download Desktop Workstation
            </Link>
            <Link to="/login" className="btn" style={{ height: 46, padding: '0 24px', fontSize: 15, gap: 8, fontWeight: 700, background: 'var(--surface)', border: '1px solid var(--border)' }}>
              <LockKeyhole size={17} /> Admin Web Console <ArrowRight size={15} />
            </Link>
          </div>
        </div>
      </section>

      {/* Two-Client Product Architecture Section */}
      <section style={{ padding: '40px 24px 60px' }}>
        <div style={{ maxWidth: 1200, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 40 }}>
            <div className="eyebrow" style={{ justifyContent: 'center', marginBottom: 8 }}>DUAL CLIENT TOPOLOGY</div>
            <h2 style={{ fontSize: 28, fontWeight: 800, margin: 0 }}>Purpose-Built Operational Architecture</h2>
            <p className="muted" style={{ fontSize: 14, margin: '8px auto 0', maxWidth: 600 }}>
              DFIP provides two complementary clients connected to a single high-integrity backend.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 24 }}>
            {/* Client A: Web Portal */}
            <Card3D>
              <div style={{ padding: 32 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                  <div style={{ width: 44, height: 44, borderRadius: 10, background: 'var(--red-light)', display: 'grid', placeItems: 'center', color: 'var(--red)' }}>
                    <Monitor size={22} />
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800 }}>Read-Only Web Portal</h3>
                    <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--red)' }}>CENTRALIZED MONITORING & AUDITING</span>
                  </div>
                </div>
                <p className="muted" style={{ fontSize: 14, lineHeight: 1.6, marginBottom: 20 }}>
                  A zero-mutation web console for administrators, lead investigators, and auditors. Provides real-time visibility into active cases, cryptographic verification statuses, and report compilation.
                </p>
                <div style={{ display: 'grid', gap: 10, fontSize: 13 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="var(--green)" /> Real-time WebSocket timeline & telemetry stream
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="var(--green)" /> Sequential SHA-256 audit chain verification
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="var(--green)" /> Court-admissible PDF forensic report exports
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="var(--green)" /> Complete read-only security model (zero write risk)
                  </div>
                </div>
                <div style={{ marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--border)' }}>
                  <Link to="/login" className="btn sm" style={{ width: '100%', justifyContent: 'center' }}>
                    Access Web Portal →
                  </Link>
                </div>
              </div>
            </Card3D>

            {/* Client B: Desktop Workstation */}
            <Card3D>
              <div style={{ padding: 32 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                  <div style={{ width: 44, height: 44, borderRadius: 10, background: '#EFF6FF', display: 'grid', placeItems: 'center', color: '#2563EB' }}>
                    <HardDrive size={22} />
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800 }}>Desktop Workstation</h3>
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#2563EB' }}>OPERATIONAL CLIENT (TAURI 2)</span>
                  </div>
                </div>
                <p className="muted" style={{ fontSize: 14, lineHeight: 1.6, marginBottom: 20 }}>
                  The primary investigative workstation client for physical evidence ingestion, native command execution, offline cases, and hardware write-protection enforcement.
                </p>
                <div style={{ display: 'grid', gap: 10, fontSize: 13 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="#2563EB" /> Real hardware bitstream acquisition (E01, RAW, DD)
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="#2563EB" /> Streaming dual SHA-256 and SHA-512 computation
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="#2563EB" /> Native forensic tools (TSK, YARA, ExifTool, Volatility)
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} color="#2563EB" /> Local workspace management with offline synchronization
                  </div>
                </div>
                <div style={{ marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--border)' }}>
                  <Link to="/download" className="btn primary sm" style={{ width: '100%', justifyContent: 'center' }}>
                    Download Desktop Client →
                  </Link>
                </div>
              </div>
            </Card3D>
          </div>
        </div>
      </section>

      {/* Forensic Capabilities Grid */}
      <section style={{ padding: '60px 24px', background: 'var(--surface)', borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)' }}>
        <div style={{ maxWidth: 1200, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 44 }}>
            <div className="eyebrow" style={{ justifyContent: 'center', marginBottom: 8 }}>TECHNICAL SPECIFICATIONS</div>
            <h2 style={{ fontSize: 28, fontWeight: 800, margin: 0 }}>Enterprise Forensic Capabilities</h2>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 24 }}>
            {[
              {
                icon: HardDrive,
                title: 'Evidence Ingestion & Sealing',
                desc: 'Acquire disk images (E01, RAW/DD, AFF4). Original files are locked read-only (chmod 0444) and preserved immutably.'
              },
              {
                icon: FileCheck2,
                title: 'Dual Cryptographic Verification',
                desc: 'Streaming calculation of SHA-256 and SHA-512 hashes. Checksums are bound to chain of custody records at intake.'
              },
              {
                icon: Layers,
                title: 'Filesystem & Partition Analysis',
                desc: 'TSK integration for mmls partition layout extraction, fls recursive file listings, and icat deleted file recovery.'
              },
              {
                icon: Cpu,
                title: 'Volatile Memory & YARA Scans',
                desc: 'Volatility 3 memory triage alongside automated YARA signature scans against recovered artifacts and executables.'
              },
              {
                icon: Activity,
                title: 'Real-Time Event Architecture',
                desc: 'Unified WebSocket event bus updates dashboard, timeline, jobs, and case records synchronously across clients.'
              },
              {
                icon: Scale,
                title: 'Tamper-Evident Audit Logging',
                desc: 'Chronologically sequenced, hash-chained audit logging guaranteeing mathematical proof of log continuity.'
              }
            ].map((f, i) => {
              const Icon = f.icon;
              return (
                <div key={i} className="card-static-wrapper" style={{ padding: 24, border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--bg)' }}>
                  <div style={{ width: 40, height: 40, borderRadius: 8, background: 'var(--red-light)', color: 'var(--red)', display: 'grid', placeItems: 'center', marginBottom: 16 }}>
                    <Icon size={20} />
                  </div>
                  <h3 style={{ fontSize: 16, fontWeight: 700, margin: '0 0 8px' }}>{f.title}</h3>
                  <p className="muted" style={{ fontSize: 13.5, lineHeight: 1.6, margin: 0 }}>{f.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Compliance & Standards */}
      <section style={{ padding: '60px 24px' }}>
        <div style={{ maxWidth: 1200, margin: '0 auto', textAlign: 'center' }}>
          <div className="eyebrow" style={{ justifyContent: 'center', marginBottom: 8 }}>LEGAL ADMISSIBILITY</div>
          <h2 style={{ fontSize: 26, fontWeight: 800, margin: '0 0 12px' }}>Forensic Standards Compliance</h2>
          <p className="muted" style={{ fontSize: 14, maxWidth: 640, margin: '0 auto 36px' }}>
            Built strictly in accordance with recognized international forensic standards to ensure evidence is admissible in formal legal proceedings.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 20 }}>
            {[
              { code: 'ISO/IEC 27037', title: 'Digital Evidence Handling', detail: 'Standards for identification, collection, acquisition, and preservation of electronic evidence.' },
              { code: 'NIST SP 800-86', title: 'Forensic Techniques', detail: 'National Institute of Standards guide for integrating forensic techniques into incident response.' },
              { code: 'RFC 3161', title: 'Cryptographic Timestamps', detail: 'Trusted third-party and hash-linked sequential timestamp verification for audit records.' },
              { code: 'FRE 902(14)', title: 'Federal Evidence Rules', detail: 'Certification of digital records copied from electronic devices via cryptographic hash values.' }
            ].map((s, i) => (
              <div key={i} style={{ padding: 22, border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--surface)', textAlign: 'left' }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--red)', marginBottom: 4 }}>{s.code}</div>
                <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 8 }}>{s.title}</div>
                <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.5 }}>{s.detail}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <PublicFooter />
    </div>
  );
}

/* =========================================================================
   2. LOGIN PAGE — SIMPLE, CLEAN & ADMINISTRATOR ONLY
========================================================================= */
export function Login() {
  const { setUser } = useContext(AuthContext);
  const nav = useNavigate();
  const [email, setEmail] = useState('admin@dfip.local');
  const [password, setPassword] = useState('DemoPassword!2026');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr('');
    try {
      const r = await api<any>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password, client: 'web' })
      });
      localStorage.setItem('dfip_token', r.access_token);
      localStorage.setItem('dfip_refresh', r.refresh_token);
      setUser(r.user);
      nav('/admin/dashboard');
    } catch (e: any) {
      setErr(e.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg)' }}>
      <PublicHeader activeNav="login" />

      <main style={{ flex: 1, display: 'grid', placeItems: 'center', padding: '40px 20px', background: 'radial-gradient(ellipse at 50% 20%, rgba(200, 16, 46, 0.04) 0%, transparent 70%)' }}>
        <div className="login-card" style={{ width: 'min(460px, 100%)', padding: '36px 32px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div className="eyebrow"><Key size={13} /> SECURE ACCESS</div>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 700, color: 'var(--green-dark)' }}>
              <span className="beacon active" /> MONGODB ONLINE
            </span>
          </div>

          <h1 style={{ fontSize: 24, fontWeight: 800, margin: '0 0 6px', letterSpacing: '-0.02em', color: 'var(--ink)' }}>
            Admin Web Portal
          </h1>
          <p className="muted" style={{ fontSize: 13.5, lineHeight: 1.5, margin: '0 0 20px' }}>
            Centralized monitoring and audit verification console. Access is strictly restricted to administrator accounts.
          </p>

          <div style={{ padding: '12px 14px', background: 'var(--bg-subtle)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12.5, lineHeight: 1.5, color: 'var(--ink-light)', marginBottom: 22 }}>
            <strong>Read-Only Notice:</strong> This web portal provides monitoring and compliance export. Field evidence acquisition and tool execution must be performed using the <strong>DFIP Desktop Workstation</strong>.
          </div>

          {err && (
            <div style={{ padding: '12px 14px', background: '#FEF2F2', border: '1px solid #FCA5A5', borderRadius: 8, color: '#DC2626', fontSize: 13, marginBottom: 18 }}>
              {err}
            </div>
          )}

          <form onSubmit={submit} style={{ display: 'grid', gap: 16 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--muted)', marginBottom: 6 }}>
                Administrator Email
              </label>
              <input
                type="email"
                required
                className="input"
                style={{ width: '100%', height: 42 }}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@dfip.local"
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--muted)', marginBottom: 6 }}>
                Password
              </label>
              <input
                type="password"
                required
                className="input"
                style={{ width: '100%', height: 42 }}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
              />
            </div>

            <button type="submit" className="btn primary" disabled={busy} style={{ width: '100%', height: 44, marginTop: 6, fontWeight: 700, fontSize: 14 }}>
              {busy ? 'Authenticating…' : 'Sign in to Web Portal'}
            </button>
          </form>

          <div style={{ marginTop: 24, paddingTop: 18, borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12 }}>
            <span className="muted">Performing acquisition?</span>
            <Link to="/download" style={{ fontWeight: 700, color: 'var(--red)', display: 'flex', alignItems: 'center', gap: 4 }}>
              Get Desktop Workstation <ArrowRight size={13} />
            </Link>
          </div>
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}

/* =========================================================================
   3. FUNCTIONS & TOOLING CATALOG PAGE
========================================================================= */
export function FunctionsPage() {
  const tools = [
    { name: 'fls', type: 'TSK Filesystem', desc: 'Recursive extraction of allocated and deleted file names from forensic disk partitions.' },
    { name: 'mmls', type: 'Partition Discovery', desc: 'Displays partition layout of volume systems (DOS, GPT, Sun, MAC).' },
    { name: 'fsstat', type: 'Filesystem Statistics', desc: 'Detailed file system metadata, block cluster allocation, and OS attributes.' },
    { name: 'istat', type: 'Inode Details', desc: 'Inspects specific inode or MFT record structures, timestamps, and data runs.' },
    { name: 'icat', type: 'Bitstream File Recovery', desc: 'Extracts file contents by inode number without mounting the filesystem.' },
    { name: 'exiftool', type: 'Metadata Engine', desc: 'Deep metadata extraction across documents, images, and system artifacts.' },
    { name: 'tshark', type: 'Network Packet Triage', desc: 'PCAP analysis, DNS resolutions, HTTP requests, and TLS SNI extraction.' },
    { name: 'yara', type: 'Signature Scanner', desc: 'High-speed pattern matching engine for malware detection and triage.' },
    { name: 'vol', type: 'Volatility 3', desc: 'Volatile memory analysis for malicious code injection, process trees, and hooks.' },
    { name: 'strings', type: 'Printable Extraction', desc: 'Carves ASCII and Unicode strings from binary forensic artifacts.' },
    { name: 'file', type: 'MIME Detection', desc: 'Magic byte inspection to determine true file type independent of extension.' }
  ];

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg)' }}>
      <PublicHeader activeNav="functions" />

      <main style={{ flex: 1, padding: '50px 24px', maxWidth: 1200, margin: '0 auto', width: '100%' }}>
        <div style={{ marginBottom: 36, textAlign: 'center' }}>
          <div className="eyebrow" style={{ justifyContent: 'center', marginBottom: 8 }}>TOOL INTEGRATION MATRIX</div>
          <h1 style={{ fontSize: 32, fontWeight: 800, margin: '0 0 10px', color: 'var(--ink)' }}>Specialist Forensic Tools</h1>
          <p className="muted" style={{ fontSize: 15, maxWidth: 680, margin: '0 auto' }}>
            Allow-listed forensic binaries executed non-destructively through the DFIP Desktop Workstation execution bridge.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 20 }}>
          {tools.map((t, i) => (
            <div key={i} className="card-static-wrapper" style={{ padding: 22, border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--surface)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <span className="mono" style={{ fontWeight: 800, fontSize: 18, color: 'var(--red)' }}>{t.name}</span>
                <span className="badge" style={{ fontSize: 11, fontWeight: 700 }}>{t.type}</span>
              </div>
              <p className="muted" style={{ fontSize: 13, lineHeight: 1.55, margin: 0 }}>{t.desc}</p>
            </div>
          ))}
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}

/* =========================================================================
   4. DOWNLOAD PAGE — DESKTOP WORKSTATION DISTRIBUTION
========================================================================= */
export function DownloadPage() {
  const [copied, setCopied] = useState(false);
  const sha = '42DCF7204532CD213FA12B432A20FA2A860F822BA1C075C5649E61200667ADC9';

  function copyHash() {
    navigator.clipboard.writeText(sha);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg)' }}>
      <PublicHeader activeNav="download" />

      <main style={{ flex: 1, padding: '50px 24px', maxWidth: 1100, margin: '0 auto', width: '100%' }}>
        <div style={{ marginBottom: 36, textAlign: 'center' }}>
          <div className="eyebrow" style={{ justifyContent: 'center', marginBottom: 8 }}>DESKTOP CLIENT</div>
          <h1 style={{ fontSize: 32, fontWeight: 800, margin: '0 0 10px', color: 'var(--ink)' }}>DFIP Investigator Workstation</h1>
          <p className="muted" style={{ fontSize: 15, maxWidth: 640, margin: '0 auto' }}>
            The primary operational desktop client for local evidence acquisition, dual SHA-256 / SHA-512 calculation, and native forensic tool execution.
          </p>
        </div>

        {/* Release Box */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 32, marginBottom: 30 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 24, paddingBottom: 20, borderBottom: '1px solid var(--border)' }}>
            <div>
              <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--ink)' }}>Version 2.0.0 — Windows x64</div>
              <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>Official Release • Tauri 2 Engine • Hardware Write-Blocking Support</div>
            </div>
            <a
              href="/downloads/DFIP-Investigator-Windows-x64.exe"
              download
              className="btn primary"
              style={{ height: 44, padding: '0 22px', gap: 8, fontSize: 14, fontWeight: 700 }}
            >
              <Download size={16} /> Download Windows Installer (.exe)
            </a>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20, marginBottom: 24 }}>
            <div style={{ padding: 16, background: 'var(--bg)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase' }}>Format</div>
              <div style={{ fontSize: 15, fontWeight: 700, marginTop: 4 }}>Windows Installer (x64)</div>
              <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>Installs to %LOCALAPPDATA%\Programs\DFIP</div>
            </div>
            <div style={{ padding: 16, background: 'var(--bg)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase' }}>Portable Archive</div>
              <div style={{ fontSize: 15, fontWeight: 700, marginTop: 4 }}>
                <a href="/downloads/DFIP-Investigator-v1.0.0-Windows-x64.zip" download style={{ color: 'var(--red)', textDecoration: 'underline' }}>
                  Download Portable (.zip)
                </a>
              </div>
              <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>Zero installation, run directly from USB</div>
            </div>
          </div>

          {/* SHA-256 Checksum Verification */}
          <div style={{ background: '#0F172A', color: '#F8FAFC', borderRadius: 8, padding: 18, fontFamily: 'monospace', fontSize: 13 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ color: '#94A3B8', fontSize: 11, fontWeight: 700, letterSpacing: '0.05em' }}>OFFICIAL RELEASE SHA-256 DIGEST</span>
              <button onClick={copyHash} className="btn sm ghost" style={{ color: '#FFF', gap: 4, height: 26, padding: '0 8px' }}>
                {copied ? <Check size={13} color="#4ADE80" /> : <Copy size={13} />} {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div style={{ wordBreak: 'break-all', color: '#38BDF8' }}>{sha}</div>
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #334155', color: '#94A3B8', fontSize: 11.5 }}>
              Verification: <span style={{ color: '#F1F5F9' }}>Get-FileHash .\DFIP-Investigator-Windows-x64.exe -Algorithm SHA256</span>
            </div>
          </div>
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}

/* =========================================================================
   5. ARCHITECTURE & COMPLIANCE PAGES
========================================================================= */
export function InfoPage({ page }: { page: 'about' | 'technology' | 'security' }) {
  const titles = {
    about: 'About DFIP Forensics Platform',
    technology: 'System Architecture & Infrastructure',
    security: 'Evidence Immutability & Audit Security'
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg)' }}>
      <PublicHeader activeNav={page} />

      <main style={{ flex: 1, padding: '50px 24px', maxWidth: 960, margin: '0 auto', width: '100%' }}>
        <h1 style={{ fontSize: 32, fontWeight: 800, margin: '0 0 16px', color: 'var(--ink)' }}>{titles[page]}</h1>
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 32, lineHeight: 1.7, fontSize: 15, color: 'var(--ink-light)' }}>
          {page === 'about' && (
            <div>
              <p>The Digital Forensics Investigation Platform (DFIP) is a specialized software environment designed to support legal, corporate, and law enforcement digital investigations.</p>
              <p>DFIP enforces strict separation of concerns: mutating operations (evidence acquisition, inode recovery, forensic tool execution) are isolated to the physical desktop workstation, while review, case timeline auditing, and reporting are served to leadership via the read-only web portal.</p>
            </div>
          )}
          {page === 'technology' && (
            <div>
              <p>DFIP is built upon a resilient modern forensic stack:</p>
              <ul>
                <li><strong>Backend:</strong> FastAPI with asynchronous ASGI execution and PyMongo persistence.</li>
                <li><strong>Database:</strong> MongoDB 8 system of record with indexed case and evidence manifests.</li>
                <li><strong>Desktop Engine:</strong> Tauri 2 Rust native shell with zero shell execution and sandboxed forensic tool adapters.</li>
                <li><strong>Real-Time Transport:</strong> WebSockets with full pub/sub event broadcasting.</li>
              </ul>
            </div>
          )}
          {page === 'security' && (
            <div>
              <p>Cryptographic evidence integrity and audit trail continuity are enforced mathematically:</p>
              <ul>
                <li><strong>Evidence Immutability:</strong> Ingested files are stored read-only (chmod 0444). Original media is never mounted read-write.</li>
                <li><strong>Dual Cryptographic Hashes:</strong> Continuous verification with simultaneous SHA-256 and SHA-512 digests.</li>
                <li><strong>Audit Hash Chains:</strong> Each audit entry links to its predecessor via canonical JSON SHA-256 digest, guaranteeing tamper detection.</li>
              </ul>
            </div>
          )}
        </div>
      </main>

      <PublicFooter />
    </div>
  );
}

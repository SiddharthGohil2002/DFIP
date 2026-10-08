import { Link } from 'react-router-dom';
import {
  ArrowRight, Clock, Download, FileLock2, FileText, FileX, Fingerprint, Globe, KeyRound, Link2, ListChecks, Monitor, ShieldCheck, Usb,
} from 'lucide-react';
import { installerHref, installerVersion, primaryInstaller, useInstallers } from '../lib/installers';
import { formatBytes } from '../lib/format';
import { Logo } from '../app/Logo';
import { Badge, Hash } from '../ui';

const FEATURES = [
  {
    icon: FileX, title: 'Deleted file recovery',
    text: 'Sleuth Kit indexes every file in every partition, including deleted entries the filesystem still describes, and recovers them with icat.',
    points: ['NTFS, FAT, exFAT, ext and more', 'Recovered copies hashed and logged', 'PhotoRec and Scalpel carving of unallocated space'],
  },
  {
    icon: Clock, title: 'Timeline analysis',
    text: 'File modified, accessed, changed and created times merged with browser and USB events into one chronology.',
    points: ['mactime-style MACB events', 'Zoomable activity chart', 'Filter by type, text and time range'],
  },
  {
    icon: Globe, title: 'Browser history analysis',
    text: 'Browser databases are found inside the image automatically and parsed read-only.',
    points: ['Chrome, Edge, Brave, Firefox', 'Visits and downloads', 'Every row traced to its source database'],
  },
  {
    icon: Usb, title: 'USB activity detection',
    text: 'Removable storage history from the Windows SYSTEM registry hive and setupapi.dev.log.',
    points: ['Vendor, product, serial, VID:PID', 'Drive letters and volume GUIDs', 'Install, arrival and removal times'],
  },
  {
    icon: FileText, title: 'Evidence reporting',
    text: 'Versioned PDF reports covering evidence, custody, findings and every analysis result.',
    points: ['SHA-256 recorded per report version', 'Notable-event timeline', 'Audit chain status at report time'],
  },
];

const STEPS = [
  { title: 'Acquire', text: 'Upload an E01, RAW/DD or AFF image of the seized device.' },
  { title: 'Preserve', text: 'SHA-256 and SHA-512 computed on arrival; the original is sealed read-only.' },
  { title: 'Examine', text: 'Integrity re-verified, then partitions and filesystems indexed with Sleuth Kit.' },
  { title: 'Analyze', text: 'Deleted files, timeline, browser history, USB devices, YARA indicators.' },
  { title: 'Document', text: 'Findings recorded against evidence; every action enters the audit chain.' },
  { title: 'Report', text: 'Generate a hash-sealed PDF for the case file or the court.' },
];

const SAFEGUARDS = [
  { icon: Fingerprint, title: 'Hash on acquisition', text: 'SHA-256 and SHA-512 of every image, re-checked before each analysis run.' },
  { icon: FileLock2, title: 'Originals never modified', text: 'Evidence is stored read-only; tools only read it and write to a separate analysis area.' },
  { icon: Link2, title: 'Chain of custody', text: 'Registration, verification, analysis and recovery recorded with handler and hash.' },
  { icon: ListChecks, title: 'Tamper-evident audit log', text: 'Each audit record carries the hash of the previous one; any edit breaks the chain.' },
  { icon: KeyRound, title: 'Role-based access', text: 'Administrator, investigator, analyst and viewer roles, enforced by the server.' },
  { icon: ShieldCheck, title: 'Leads, not verdicts', text: 'Missing data is reported as missing; patterns and anomalies are marked for review.' },
];

export function Landing() {
  const installers = useInstallers();
  const main = primaryInstaller(installers);

  return (
    <div className="site">
      <nav className="site-nav">
        <div className="site-nav-inner">
          <Logo />
          <div className="site-links">
            <a href="#features">Features</a>
            <a href="#workflow">How it works</a>
            <a href="#integrity">Evidence integrity</a>
            <a href="#desktop">Desktop app</a>
          </div>
          {main && (
            <a href={installerHref(main)} className="btn" download>
              <Download size={15} /> Download for Windows
            </a>
          )}
          <Link to="/login" className="btn primary">Sign in</Link>
        </div>
      </nav>

      <header className="site-hero">
        <div className="site-section-inner">
          <Badge tone="info">Digital forensics · incident response · cybercrime investigation</Badge>
          <h1 style={{ marginTop: 18 }}>Analyze disk images and investigate cybercrime evidence.</h1>
          <p>
            DFIP turns a forensic image into answers an investigator can defend: what was deleted, what happened when, which websites were visited, which USB drives were connected, all with the evidence hashed, preserved and accounted for.
          </p>
          <div className="row">
            <Link to="/login" className="btn primary lg">Sign in to the workspace <ArrowRight size={17} /></Link>
            {main ? (
              <a href={installerHref(main)} className="btn lg" style={{ background: 'transparent', color: '#dbe5f5', borderColor: '#33476e' }} download>
                <Download size={17} /> Download for Windows{installerVersion(main) && ` · v${installerVersion(main)}`}
              </a>
            ) : (
              <a href="#desktop" className="btn lg" style={{ background: 'transparent', color: '#dbe5f5', borderColor: '#33476e' }}><Monitor size={17} /> Desktop app</a>
            )}
          </div>
        </div>
      </header>

      <section className="site-section" id="features">
        <div className="site-section-inner">
          <h2>What DFIP finds in a disk image</h2>
          <p className="lead">One analysis run produces all five results. Each is traceable to the exact file, inode or registry key it came from.</p>
          <div className="grid cols-3">
            {FEATURES.map((f) => {
              const Icon = f.icon;
              return (
                <div className="card feature" key={f.title}>
                  <div className="tile-icon"><Icon size={20} /></div>
                  <h3>{f.title}</h3>
                  <p>{f.text}</p>
                  <ul>{f.points.map((p) => <li key={p}>{p}</li>)}</ul>
                </div>
              );
            })}
            <div className="card feature">
              <div className="tile-icon"><ShieldCheck size={20} /></div>
              <h3>Built on proven tools</h3>
              <p>The Sleuth Kit (mmls, fsstat, fls, icat), PhotoRec, Scalpel, YARA and the regipy registry parser, orchestrated in Python. Sleuth Kit bodyfiles are kept for cross-checking with mactime or Autopsy.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="site-section alt" id="workflow">
        <div className="site-section-inner">
          <h2>How an investigation runs</h2>
          <p className="lead">The platform follows the standard forensic process, from acquisition to the report.</p>
          <div className="steps">
            {STEPS.map((s) => (
              <div className="step" key={s.title}>
                <h4>{s.title}</h4>
                <p>{s.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="site-section" id="integrity">
        <div className="site-section-inner">
          <h2>Evidence that stands up</h2>
          <p className="lead">Integrity and accountability are built into every step, not added at the end.</p>
          <div className="grid cols-3">
            {SAFEGUARDS.map((s) => {
              const Icon = s.icon;
              return (
                <div className="card feature" key={s.title}>
                  <div className="tile-icon green"><Icon size={20} /></div>
                  <h3>{s.title}</h3>
                  <p>{s.text}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="site-section alt" id="desktop">
        <div className="site-section-inner">
          <h2>DFIP Investigator for Windows</h2>
          <p className="lead">
            The desktop app is the same workspace in a native window: one sign-in, then every case function. It adds workstation-side checks, such as hashing a local copy of an image to confirm it matches the registered evidence without uploading it again.
          </p>
          {installers === null ? null : installers.length ? (
            <div className="card" style={{ padding: 0 }}>
              <table className="table">
                <thead><tr><th>Installer</th><th>Size</th><th>SHA-256</th><th /></tr></thead>
                <tbody>
                  {installers.map((f) => (
                    <tr key={f.filename}>
                      <td className="strong">{f.filename} <Badge>{f.format}</Badge></td>
                      <td className="small">{formatBytes(f.size)}</td>
                      <td><Hash value={f.sha256} short={24} /></td>
                      <td className="right"><a className="btn primary sm" href={installerHref(f)} download><Download size={14} /> Download</a></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="small muted" style={{ padding: '10px 14px', margin: 0 }}>
                Verify before installing: <code>Get-FileHash &lt;file&gt; -Algorithm SHA256</code> must equal the SHA-256 shown.
              </p>
            </div>
          ) : (
            <div className="card" style={{ padding: 18 }}>
              <div className="strong">No installer has been published on this server yet.</div>
              <p className="small muted" style={{ margin: '6px 0 0' }}>
                Administrators build it with <code>desktop/scripts/build-windows.ps1</code> (see <code>desktop/INSTALL.md</code>) and place the output in the server's <code>storage/downloads</code> folder; it then appears here with its SHA-256. Until then, use the web workspace.
              </p>
            </div>
          )}
        </div>
      </section>

      <footer className="site-foot">
        <div className="site-section-inner row between">
          <span>DFIP — Digital Forensics Investigation Platform</span>
          <Link to="/login">Investigator sign-in</Link>
        </div>
      </footer>
    </div>
  );
}

import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowRight, Check, ChevronDown, Clock, Download, FileLock2, FileText, FileX, Fingerprint, Globe, HardDrive, KeyRound,
  Layers, Link2, ListChecks, Menu, Monitor, NotebookPen, ScanSearch, ShieldCheck, Usb, X, type LucideIcon,
} from 'lucide-react';
import { formatBytes } from '../lib/format';
import { installerHref, installerVersion, primaryInstaller, useInstallers } from '../lib/installers';
import { Logo } from '../app/Logo';
import { Hash } from '../ui';
import homeShot from './assets/home.webp';
import filesShot from './assets/files.webp';
import timelineShot from './assets/timeline.webp';
import browserShot from './assets/browser.webp';
import usbShot from './assets/usb.webp';
import reportShot from './assets/report.webp';
import './site.css';

const TOOLS = ['The Sleuth Kit', 'PhotoRec', 'Scalpel', 'YARA', 'libewf', 'regipy', 'ExifTool'];

const FACTS = [
  { value: '28', label: 'analysis modules in a single run' },
  { value: 'SHA-256', label: 'and SHA-512 on every image' },
  { value: '38', label: 'report sections to choose from' },
  { value: '0', label: 'writes to original evidence' },
];

const FEATURES: { icon: LucideIcon; eyebrow: string; title: string; text: string; points: string[]; image: string; alt: string }[] = [
  {
    icon: FileX, eyebrow: 'Deleted file recovery', image: filesShot,
    alt: 'DFIP file index listing every file in the image, with the deleted payroll export highlighted',
    title: 'Every file in every partition, including the deleted ones',
    text: 'DFIP indexes the whole image with The Sleuth Kit and lists the files a suspect deleted, with their original names, sizes and timestamps. Recover any of them in one click.',
    points: ['NTFS, FAT, exFAT, ext and more', 'Recovered copies are hashed and logged to the chain of custody', 'PhotoRec and Scalpel carving for data with no filesystem record'],
  },
  {
    icon: Clock, eyebrow: 'Timeline analysis', image: timelineShot,
    alt: 'DFIP timeline with an hourly activity chart and events from the filesystem, browsers and USB devices',
    title: 'One timeline for files, web activity and USB devices',
    text: 'File modified, accessed, changed and created times are merged with browser visits, downloads and USB connections into a single chronology you can zoom, filter and search.',
    points: ['mactime-style MACB events from the filesystem', 'Zoomable activity chart: click any period to drill in', 'UTC by default, local time on demand'],
  },
  {
    icon: Globe, eyebrow: 'Browser history analysis', image: browserShot,
    alt: 'DFIP browser history table with visits from Chrome and Firefox',
    title: 'Browser history found and parsed automatically',
    text: 'There is no need to hunt for profile folders. DFIP locates the browser databases inside the image, reads copies of them and shows every visit and download with exact times.',
    points: ['Chrome, Edge, Brave and Firefox', 'Visits, titles, visit counts and downloads', 'Every record traced to the database it came from'],
  },
  {
    icon: Usb, eyebrow: 'USB activity detection', image: usbShot,
    alt: 'DFIP USB device cards with serial numbers, vendor and product IDs and install times',
    title: 'Who plugged in what, and when',
    text: 'Removable storage history comes straight from the Windows registry and setupapi.dev.log: device names, serial numbers, drive letters and the times each device was installed, connected and removed.',
    points: ['Vendor, product, revision, serial and VID:PID', 'Drive letters and volume GUIDs from MountedDevices', 'Missing times are shown as missing, never estimated'],
  },
  {
    icon: FileText, eyebrow: 'Evidence reporting', image: reportShot,
    alt: 'First page of a DFIP investigation report with the evidence register and chain of custody',
    title: 'Hash-sealed reports, ready for the case file',
    text: 'Generate a versioned PDF covering the evidence register, chain of custody, findings and every analysis result. Each version is fingerprinted with SHA-256 so any later change shows.',
    points: ['Evidence, custody, deleted files, browser, USB, YARA and findings', 'A new numbered version every time you generate', 'Audit-chain integrity status printed in the report'],
  },
];

const STEPS: { icon: LucideIcon; title: string; text: string }[] = [
  { icon: HardDrive, title: 'Acquire', text: 'Upload a disk image (E01, RAW/DD, VHD, VMDK, QCOW2, AFF), a collection of files, a network capture or a memory image.' },
  { icon: Fingerprint, title: 'Preserve', text: 'Hashed on arrival and sealed read-only.' },
  { icon: ScanSearch, title: 'Examine', text: 'Integrity re-checked, then every partition indexed.' },
  { icon: Layers, title: 'Analyze', text: 'Deleted files, timeline, browser, USB, YARA.' },
  { icon: NotebookPen, title: 'Document', text: 'Findings linked to evidence; every action audited.' },
  { icon: FileText, title: 'Report', text: 'A hash-sealed PDF for the case file.' },
];

const SAFEGUARDS: { icon: LucideIcon; title: string; text: string }[] = [
  { icon: Fingerprint, title: 'Hashed on acquisition', text: 'SHA-256 and SHA-512 for every image, re-verified before each analysis run. A mismatch stops the analysis.' },
  { icon: FileLock2, title: 'Originals never modified', text: 'Evidence is stored read-only. Analysis tools only read it and write to a separate analysis area.' },
  { icon: Link2, title: 'Chain of custody', text: 'Registration, verification, analysis and every recovery are recorded with handler, time and hash.' },
  { icon: ListChecks, title: 'Tamper-evident audit log', text: 'Each audit record carries the hash of the previous one, so editing or deleting any record breaks the chain.' },
  { icon: KeyRound, title: 'Role-based access', text: 'Administrator, investigator, analyst and viewer roles, enforced by the server on every request.' },
  { icon: ShieldCheck, title: 'Leads, not verdicts', text: 'Patterns and anomalies are flagged for review, and missing data is reported as missing, never filled in.' },
];

const FAQ = [
  { q: 'Does DFIP modify the original evidence?', a: 'No. Images are stored read-only, the analysis tools only read them, and the SHA-256 is re-verified before every analysis run. Recovered files are written to a separate analysis area and hashed.' },
  { q: 'Which image formats and filesystems are supported?', a: 'Disk images: E01/Ex01 (EnCase, with their segments), raw/dd and split raw, VHD, VHDX, VMDK, QCOW2 and AFF/AFF4. Collections of files as ZIP or TAR (KAPE, Velociraptor, phone extractions), network captures (pcap, pcapng) and memory images (raw, crash dump, LiME, VMware .vmem). Filesystems are read by The Sleuth Kit, which covers NTFS, FAT, exFAT, ext2/3/4, HFS+ and APFS; BitLocker and LUKS volumes are unlocked with their key.' },
  { q: 'Where is the evidence stored?', a: 'On the DFIP server your organisation runs. Evidence, analysis results and reports stay on that infrastructure. Nothing is sent to a third party unless an administrator turns on an optional online lookup (VirusTotal, threat intelligence, Claude mode), and then only hashes, addresses or the facts you select.' },
  { q: 'Do I need the desktop app?', a: 'No. The web portal has every function. The Windows app gives you the same workspace in a native window and adds workstation features, such as checking a local copy of an image against the registered evidence without uploading it again.' },
  { q: 'How does DFIP relate to Autopsy?', a: 'DFIP uses the same Sleuth Kit engine and keeps the Sleuth Kit bodyfile for every analysis, so results can be cross-checked in Autopsy or with mactime.' },
  { q: 'Who can see a case?', a: 'The investigators assigned to it, the person who created it, and administrators. Roles decide what each user can do, and every action is written to the tamper-evident audit log.' },
  { q: 'How do I get an account?', a: 'Choose Create account on the sign-in page. Depending on your organisation\'s settings, an administrator approves new accounts and assigns a role before the first sign-in.' },
];

export function Landing() {
  const installer = primaryInstaller(useInstallers());
  const [menu, setMenu] = useState(false);
  const version = installer ? installerVersion(installer) : '';

  return (
    <div className="lp">
      <nav className="lp-nav" aria-label="Main">
        <div className="lp-wrap lp-nav-inner">
          <Logo />
          <div className="lp-links">
            <a href="#features">Features</a>
            <a href="#how-it-works">How it works</a>
            <a href="#security">Security</a>
            <a href="#download">Download</a>
            <a href="#faq">FAQ</a>
          </div>
          <div className="lp-nav-actions">
            <Link to="/login" className="btn lp-btn-ghost">Sign in</Link>
            <Link to="/login?mode=register" className="btn primary">Create account</Link>
          </div>
          <button className="lp-menu-toggle" onClick={() => setMenu((m) => !m)} aria-label={menu ? 'Close menu' : 'Open menu'} aria-expanded={menu}>
            {menu ? <X size={22} /> : <Menu size={22} />}
          </button>
        </div>
        <div className={`lp-mobile-menu ${menu ? 'open' : ''}`} onClick={() => setMenu(false)}>
          <a href="#features">Features</a>
          <a href="#how-it-works">How it works</a>
          <a href="#security">Security</a>
          <a href="#download">Download</a>
          <a href="#faq">FAQ</a>
          <Link to="/login" className="btn lp-btn-ghost">Sign in</Link>
          <Link to="/login?mode=register" className="btn primary">Create account</Link>
        </div>
      </nav>

      <header className="lp-hero">
        <div className="lp-wrap lp-hero-copy">
          <span className="lp-pill"><ShieldCheck size={15} /> Digital forensics · incident response<span className="lp-pill-more">&nbsp;· cybercrime investigation</span></span>
          <h1>
            Turn disk images into <span className="lp-grad">evidence you can defend</span>
          </h1>
          <p className="lp-hero-lead">
            DFIP recovers deleted files, rebuilds the timeline and extracts browser history and USB activity from a disk image, with every image hashed, preserved read-only and accounted for.
          </p>
          <div className="lp-cta">
            <Link to="/login?mode=register" className="btn primary lg">Get started <ArrowRight size={17} /></Link>
            {installer ? (
              <a href={installerHref(installer)} className="btn lg lp-btn-light" download>
                <Download size={17} /> Download for Windows{version && ` · v${version}`}
              </a>
            ) : (
              <Link to="/login" className="btn lg lp-btn-ghost">Sign in</Link>
            )}
          </div>
          <div className="lp-checks">
            <span><Check size={16} /> Built on The Sleuth Kit</span>
            <span><Check size={16} /> Originals never modified</span>
            <span><Check size={16} /> Chain of custody built in</span>
          </div>
        </div>
        <div className="lp-shot-wrap">
          <div className="lp-window">
            <div className="lp-window-bar"><i /><i /><i /><span>DFIP — Case desktop</span></div>
            <img src={homeShot} width={2880} height={1800} alt="The DFIP case desktop: evidence status and a tile for each investigation function with live counts" />
          </div>
        </div>
        <div className="lp-hero-fade" />
      </header>

      <section className="lp-strip" aria-label="Forensic tools">
        <div className="lp-wrap">
          <p>Powered by proven open-source forensic tools</p>
          <div className="lp-tools">{TOOLS.map((t) => <span key={t}>{t}</span>)}</div>
        </div>
      </section>

      <section className="lp-section" id="features" style={{ paddingTop: 0 }}>
        <div className="lp-wrap">
          <div className="lp-facts">
            {FACTS.map((f) => (
              <div className="lp-fact" key={f.label}><b>{f.value}</b><span>{f.label}</span></div>
            ))}
          </div>
          <div className="lp-head" style={{ marginTop: 96 }}>
            <div className="lp-eyebrow">Features</div>
            <h2>Everything an investigation needs, from one analysis run</h2>
            <p>Upload an image, click Analyze, and DFIP produces these results and many more, each traceable to the exact file, inode or registry key it came from.</p>
          </div>
          {FEATURES.map((f, i) => {
            const Icon = f.icon;
            return (
              <div className={`lp-feature ${i % 2 ? 'flip' : ''}`} key={f.eyebrow}>
                <div className="lp-feature-copy">
                  <div className="lp-feature-icon"><Icon size={22} /></div>
                  <div className="lp-eyebrow">{f.eyebrow}</div>
                  <h3>{f.title}</h3>
                  <p>{f.text}</p>
                  <ul>{f.points.map((p) => <li key={p}><Check size={17} /> {p}</li>)}</ul>
                </div>
                <div className="lp-frame">
                  <img src={f.image} alt={f.alt} loading="lazy" />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="lp-section alt" id="how-it-works">
        <div className="lp-wrap">
          <div className="lp-head">
            <div className="lp-eyebrow">How it works</div>
            <h2>A forensic process you can explain in court</h2>
            <p>DFIP follows the standard investigation process, from acquisition to the report, and records each step as it happens.</p>
          </div>
          <div className="lp-steps">
            {STEPS.map((s, i) => {
              const Icon = s.icon;
              return (
                <div className="lp-step" key={s.title}>
                  <div className="lp-step-icon"><Icon size={23} /><em>{i + 1}</em></div>
                  <h4>{s.title}</h4>
                  <p>{s.text}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="lp-section lp-dark" id="security">
        <div className="lp-wrap">
          <div className="lp-head">
            <div className="lp-eyebrow">Evidence integrity</div>
            <h2>Built so the evidence holds up</h2>
            <p>Integrity and accountability are part of every step, not a checkbox at the end.</p>
          </div>
          <div className="lp-safeguards">
            {SAFEGUARDS.map((s) => {
              const Icon = s.icon;
              return (
                <div className="lp-safeguard" key={s.title}>
                  <Icon size={22} />
                  <h4>{s.title}</h4>
                  <p>{s.text}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="lp-section" id="download">
        <div className="lp-wrap">
          <div className="lp-head">
            <div className="lp-eyebrow">Platforms</div>
            <h2>In the browser or on your Windows workstation</h2>
            <p>The same workspace and the same cases, wherever you work.</p>
          </div>
          <div className="lp-platforms">
            <div className="lp-platform">
              <div className="lp-feature-icon" style={{ marginBottom: 0 }}><Globe size={22} /></div>
              <h3>Web portal</h3>
              <p>Nothing to install. Sign in from any modern browser and work on your cases.</p>
              <ul>
                <li><Check size={16} /> Every investigation function</li>
                <li><Check size={16} /> Large image uploads with progress</li>
                <li><Check size={16} /> Runs on your organisation's own server</li>
              </ul>
              <div className="actions">
                <Link to="/login" className="btn primary">Sign in</Link>
                <Link to="/login?mode=register" className="btn">Create account</Link>
              </div>
            </div>
            <div className="lp-platform featured">
              <div className="lp-feature-icon" style={{ marginBottom: 0 }}><Monitor size={22} /></div>
              <h3>DFIP Investigator for Windows</h3>
              <p>The same workspace in a native window, plus checks that run on the workstation itself.</p>
              <ul>
                <li><Check size={16} /> Verify a local image copy against the registered hash</li>
                <li><Check size={16} /> Connects to your DFIP server; sign-in on every launch</li>
                <li><Check size={16} /> Windows 10 and 11 (64-bit)</li>
              </ul>
              {installer ? (
                <>
                  <div className="meta">
                    <span>{installer.filename} · {formatBytes(installer.size)}</span>
                    <span>SHA-256 <Hash value={installer.sha256} short={24} /></span>
                  </div>
                  <div className="actions">
                    <a href={installerHref(installer)} className="btn primary" download><Download size={16} /> Download{version && ` v${version}`}</a>
                  </div>
                </>
              ) : (
                <div className="meta"><span>No installer has been published on this server yet. Use the web portal meanwhile.</span></div>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="lp-section alt" id="faq">
        <div className="lp-wrap">
          <div className="lp-head">
            <div className="lp-eyebrow">FAQ</div>
            <h2>Questions investigators ask</h2>
          </div>
          <div className="lp-faq">
            {FAQ.map((f) => (
              <details key={f.q}>
                <summary>{f.q} <ChevronDown size={18} /></summary>
                <p>{f.a}</p>
              </details>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-cta-band">
            <h2>Start your first investigation</h2>
            <p>Create an account, upload a disk image and have deleted files, a timeline, browser history and USB activity in minutes.</p>
            <div className="lp-cta">
              <Link to="/login?mode=register" className="btn lg lp-btn-light">Create account <ArrowRight size={17} /></Link>
              <Link to="/login" className="btn lg lp-btn-ghost">Sign in</Link>
            </div>
          </div>
        </div>
      </section>

      <footer className="lp-foot">
        <div className="lp-wrap">
          <div className="lp-foot-grid">
            <div>
              <Logo />
              <p style={{ maxWidth: 340, marginTop: 14, lineHeight: 1.6 }}>
                Digital Forensics Investigation Platform: disk image analysis with evidence integrity and chain of custody built in.
              </p>
            </div>
            <div>
              <h5>Product</h5>
              <ul>
                <li><a href="#features">Features</a></li>
                <li><a href="#how-it-works">How it works</a></li>
                <li><a href="#security">Evidence integrity</a></li>
              </ul>
            </div>
            <div>
              <h5>Get DFIP</h5>
              <ul>
                <li><a href="#download">Desktop app</a></li>
                <li><Link to="/login">Sign in</Link></li>
                <li><Link to="/login?mode=register">Create account</Link></li>
              </ul>
            </div>
            <div>
              <h5>Help</h5>
              <ul>
                <li><a href="#faq">FAQ</a></li>
              </ul>
            </div>
          </div>
          <div className="lp-foot-bottom">
            <span>© {new Date().getFullYear()} DFIP — Digital Forensics Investigation Platform</span>
            <span>Screenshots show a sample case.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

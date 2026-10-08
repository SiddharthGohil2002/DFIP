import { Download, Monitor } from 'lucide-react';
import { formatBytes } from '../lib/format';
import { installerHref, installerVersion, primaryInstaller, useInstallers } from '../lib/installers';
import { IS_DESKTOP } from '../lib/platform';

/** Web only: a download link for the published Windows installer; renders nothing when none is published. */
export function DesktopDownload({ variant }: { variant: 'login' | 'sidebar' }) {
  const main = primaryInstaller(useInstallers());
  if (IS_DESKTOP || !main) return null;
  const version = installerVersion(main);

  if (variant === 'sidebar') {
    return (
      <div className="nav-download">
        <div className="row" style={{ gap: 7 }}>
          <Monitor size={15} />
          <b>Desktop app</b>
          {version && <span className="tiny">v{version}</span>}
        </div>
        <a className="btn sm block" href={installerHref(main)} download>
          <Download size={14} /> Download for Windows
        </a>
      </div>
    );
  }
  return (
    <div className="card" style={{ padding: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
      <Monitor size={20} color="var(--accent)" style={{ flex: 'none' }} />
      <div className="grow small">
        <b>Prefer a desktop app?</b>
        <div className="muted">DFIP Investigator for Windows{version ? ` v${version}` : ''} · {formatBytes(main.size)}</div>
      </div>
      <a className="btn sm" href={installerHref(main)} download>
        <Download size={14} /> Download
      </a>
    </div>
  );
}

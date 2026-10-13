import { useEffect, useState } from 'react';
import { CheckCircle2, XCircle } from 'lucide-react';
import { health, serverUrl, type Health } from '../../lib/api';
import { IS_DESKTOP } from '../../lib/platform';
import { useApi } from '../../lib/useApi';
import { Badge, Card, Loading, PageHeader } from '../../ui';
import { WorkstationCard } from '../../app/Workstation';
import { MemorySymbolsCard } from './MemorySymbols';

const TOOL_PURPOSE: Record<string, string> = {
  sleuthkit_mmls: 'Partition tables',
  sleuthkit_fsstat: 'Filesystem details',
  sleuthkit_fls: 'File listing incl. deleted entries',
  sleuthkit_istat: 'Inode metadata',
  sleuthkit_icat: 'File recovery by inode',
  exiftool: 'File metadata',
  yara: 'Malware signatures',
  strings: 'Printable strings',
  file: 'File type identification',
  tshark: 'Packet captures',
  volatility: 'Memory images',
  carving_photorec: 'Signature carving',
  carving_scalpel: 'Signature carving',
};

export function SystemPage() {
  const tools = useApi<{ data: Record<string, { binary: string; available: boolean }> }>('/forensics/tooling');
  const [h, setH] = useState<Health | null>(null);
  const [hError, setHError] = useState('');
  useEffect(() => {
    health().then(setH).catch((e) => setHError(e.message));
  }, []);

  return (
    <div className="stack">
      <PageHeader title="System & tools" subtitle="Server status and the forensic tools available to the analysis engine." />
      <div className="grid cols-2">
        <Card title="DFIP server">
          {!h && !hError ? <Loading /> : (
            <dl className="kv">
              <dt>Address</dt><dd className="mono">{serverUrl() || window.location.origin}</dd>
              <dt>Status</dt><dd>{h?.status === 'ok' ? <Badge tone="ok">Online</Badge> : <Badge tone="danger">{hError || h?.status}</Badge>}</dd>
              <dt>Database</dt><dd>{h?.database}</dd>
              <dt>Version</dt><dd>{h?.version || '—'}</dd>
              <dt>Demo mode</dt><dd>{h?.demo_mode ? <Badge tone="warn">On: demo accounts and data enabled</Badge> : <Badge tone="ok">Off</Badge>}</dd>
              <dt>Client</dt><dd>{IS_DESKTOP ? 'DFIP desktop app' : 'Web portal'}</dd>
            </dl>
          )}
        </Card>
        {IS_DESKTOP && <WorkstationCard showTools />}
      </div>
      <Card title="Server forensic tools" flush>
        {tools.loading && !tools.data ? <Loading /> : (
          <table className="table">
            <thead><tr><th>Tool</th><th>Binary</th><th>Used for</th><th>Status</th></tr></thead>
            <tbody>
              {Object.entries(tools.data?.data || {}).map(([name, t]) => (
                <tr key={name}>
                  <td className="strong">{name.replace(/^(sleuthkit|carving)_/, '')}</td>
                  <td className="mono small">{t.binary}</td>
                  <td className="small">{TOOL_PURPOSE[name] || ''}</td>
                  <td>{t.available ? <span className="row small" style={{ color: 'var(--ok)' }}><CheckCircle2 size={14} /> Installed</span> : <span className="row small muted"><XCircle size={14} /> Not installed</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <MemorySymbolsCard />
    </div>
  );
}

import { useEffect, useState } from 'react';
import { CloudDownload, Trash2, Upload } from 'lucide-react';
import { api, del, post } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import { formatBytes, shortHash, useTime } from '../../lib/format';
import { useApi } from '../../lib/useApi';
import { Badge, Banner, Button, Card, ErrorBanner, Loading, ProgressBar, useToast } from '../../ui';

interface Pack {
  name: string;
  size: number;
  sha256?: string | null;
  symbols?: Record<string, number> | null;
  source: string;
  added_by?: string | null;
  added_at?: string | null;
}
interface MemoryStatus {
  volatility: string | null;
  packs: Pack[];
  symbol_server: boolean;
  pack_url: string;
  download: { job_id: string; status: string; progress: number; stage: string; error?: string | null; finished_at?: string } | null;
}

/** The symbol packs Volatility reads memory images with: listed for everyone, added, downloaded and removed by administrators. */
export function MemorySymbolsCard() {
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const manage = can('SYSTEM_MANAGE');
  const [busy, setBusy] = useState('');
  const downloading = (s?: MemoryStatus | null) => !!s?.download && ['QUEUED', 'RUNNING'].includes(s.download.status);
  const [watch, setWatch] = useState(false);
  const status = useApi<MemoryStatus>('/forensics/memory/status', { pollMs: watch ? 3000 : undefined });  // polled while a download runs
  const s = status.data;
  useEffect(() => setWatch(downloading(s)), [s]);

  async function act(label: string, fn: () => Promise<any>, done: (r: any) => string) {
    setBusy(label);
    try {
      toast(done(await fn()), 'ok');
      setWatch(true);
      status.reload();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy('');
    }
  }
  const add = (file: File) => act('add', () => {
    const form = new FormData();
    form.append('file', file);
    return api('/forensics/memory/symbols', { method: 'POST', body: form });
  }, (r) => `${r.name} added: ${Object.values(r.symbols as Record<string, number>).reduce((a, b) => a + b, 0).toLocaleString()} symbol tables`);
  const counts = (p: Pack) => Object.entries(p.symbols || {}).filter(([, n]) => n).map(([k, n]) => `${n.toLocaleString()} ${k}`).join(', ') || '—';

  return (
    <Card title="Memory analysis symbols" flush
      subtitle={`Volatility ${s?.volatility || ''} needs the symbols of the exact Windows kernel in a memory image. They come from symbol packs (such as the Volatility Foundation's windows.zip)${s?.symbol_server ? ', or are downloaded from Microsoft\'s symbol server (MEMORY_SYMBOL_SERVER is on)' : '; Volatility runs offline (MEMORY_SYMBOL_SERVER is off)'}.`}
      actions={manage && (
        <div className="row" style={{ flexWrap: 'nowrap' }}>
          <Button size="sm" variant="ghost" icon={<CloudDownload size={13} />} disabled={!!busy || downloading(s)} title={s?.pack_url}
            onClick={() => act('download', () => post('/forensics/memory/symbols/download'), (r) => `Downloading the Windows symbol pack (${r.job_id})`)}>
            Download the Windows pack</Button>
          <label className={`btn sm${busy === 'add' ? ' disabled' : ''}`}>
            {busy === 'add' ? <span className="spinner" /> : <Upload size={13} />} Add a symbol pack
            <input type="file" accept=".zip,application/zip" hidden aria-label="Symbol pack (ZIP)" disabled={!!busy}
              onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) add(f); }} />
          </label>
        </div>
      )}>
      <ErrorBanner error={status.error} />
      {s?.download && (
        <div className="row" style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)' }}>
          <span className="small strong">Download {s.download.job_id}</span>
          {downloading(s) ? <><ProgressBar value={s.download.progress} /><span className="small muted">{s.download.stage}</span></>
            : s.download.status === 'FAILED' ? <Badge tone="danger" title={s.download.error || ''}>Failed: {(s.download.error || '').slice(0, 120)}</Badge>
              : <Badge tone="ok">{s.download.status.toLowerCase()}{s.download.finished_at ? ` ${time(s.download.finished_at)}` : ''}</Badge>}
        </div>
      )}
      {!s ? <Loading /> : !s.packs.length ? (
        <Banner tone="info">No symbol pack: Windows memory images can be read only when Microsoft's symbol server may be used. Download the Windows pack
          (the server needs internet access) or add one copied from another computer.</Banner>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Pack</th><th>Symbol tables</th><th className="right">Size</th><th>SHA-256</th><th>Added</th><th /></tr></thead>
            <tbody>
              {s.packs.map((p) => (
                <tr key={p.name}>
                  <td className="mono small">{p.name}</td>
                  <td className="small">{counts(p)}</td>
                  <td className="right small">{formatBytes(p.size)}</td>
                  <td className="mono tiny">{p.sha256 ? shortHash(p.sha256) : '—'}</td>
                  <td className="small">{p.source}{p.added_at ? <div className="tiny muted">{time(p.added_at)}{p.added_by ? ` · ${p.added_by}` : ''}</div> : null}</td>
                  <td className="right">{manage && p.name.endsWith('.zip') && <Button size="sm" variant="ghost" icon={<Trash2 size={13} />} aria-label={`Delete ${p.name}`}
                    disabled={!!busy} onClick={() => act(p.name, () => del(`/forensics/memory/symbols/${encodeURIComponent(p.name)}`), () => `${p.name} deleted`)}>Delete</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

import { useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, Eye } from 'lucide-react';
import { api, fetchBlob } from '../lib/api';
import { formatBytes, formatNumber } from '../lib/format';
import { Banner, Button, Loading, Modal, Tabs } from './index';

/** A file inside an evidence image (by inode) or a file DFIP stored (recovered, carved, extracted). */
export type ViewSource =
  | { kind: 'image'; evidenceId: string; inode: string; offset: number; name: string }
  | { kind: 'artifact'; artifactId: string; name: string };

interface Preview {
  path?: string;
  size: number;
  kind: 'text' | 'image' | 'pdf' | 'binary';
  mime: string;
  text?: string;
  encoding?: string;
  truncated?: boolean;
  renderable?: boolean;
}

interface Page {
  start: number;
  length: number;
  size: number;
  eof: boolean;
  data_b64: string;
}

const PAGE = 4096;

function endpoint(src: ViewSource, what: 'content' | 'preview' | 'raw', extra = '') {
  if (src.kind === 'artifact') return `/forensics/artifacts/${encodeURIComponent(src.artifactId)}/${what}${extra ? `?${extra}` : ''}`;
  return `/forensics/evidence/${encodeURIComponent(src.evidenceId)}/${what}?inode=${encodeURIComponent(src.inode)}&offset=${src.offset}${extra ? `&${extra}` : ''}`;
}

const hex2 = (b: number) => b.toString(16).padStart(2, '0');

function hexDump(bytes: Uint8Array, base: number): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.subarray(i, i + 16);
    const hex = Array.from(row, hex2);
    const left = hex.slice(0, 8).join(' ').padEnd(23, ' ');
    const right = hex.slice(8).join(' ').padEnd(23, ' ');
    const ascii = Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${(base + i).toString(16).padStart(8, '0')}  ${left}  ${right}  |${ascii}|`);
  }
  return lines.join('\n');
}

/** "View" button that opens the viewer for one file. */
export function ViewButton({ source }: { source: ViewSource }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" icon={<Eye size={13} />} onClick={() => setOpen(true)}>View</Button>
      {open && <FileViewer source={source} onClose={() => setOpen(false)} />}
    </>
  );
}

/** Preview (text, image or PDF, decided from the file's content) and a paged hex view. Nothing is written or downloaded. */
export function FileViewer({ source, onClose }: { source: ViewSource; onClose: () => void }) {
  const [tab, setTab] = useState<'preview' | 'hex'>('preview');
  return (
    <Modal open title={source.name} onClose={onClose} wide>
      <Tabs<'preview' | 'hex'> value={tab} onChange={setTab} tabs={[{ id: 'preview', label: 'Preview' }, { id: 'hex', label: 'Hex' }]} />
      <div style={{ paddingTop: 12 }}>{tab === 'preview' ? <PreviewPane source={source} onHex={() => setTab('hex')} /> : <HexPane source={source} />}</div>
    </Modal>
  );
}

function PreviewPane({ source, onHex }: { source: ViewSource; onHex: () => void }) {
  const [p, setP] = useState<Preview | null>(null);
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const key = endpoint(source, 'preview');

  useEffect(() => {
    let alive = true;
    let objectUrl = '';
    api<Preview>(endpoint(source, 'preview'))
      .then(async (r) => {
        if (!alive) return;
        setP(r);
        if ((r.kind === 'image' || r.kind === 'pdf') && r.renderable) {
          const blob = await fetchBlob(endpoint(source, 'raw'));
          objectUrl = URL.createObjectURL(new Blob([blob], { type: r.mime }));
          if (alive) setUrl(objectUrl);
        }
      })
      .catch((e) => alive && setError(e.message));
    return () => {
      alive = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  if (error) return <Banner tone="danger">{error}</Banner>;
  if (!p) return <Loading label="Reading the file…" />;
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="small muted">{p.path} · {formatBytes(p.size)} · detected as {p.mime}{p.encoding ? ` (${p.encoding})` : ''}</div>
      {p.kind === 'text' && (
        <>
          {p.truncated && <Banner tone="info">Showing the first 256 KB. Use the Hex tab for the rest of the file.</Banner>}
          <pre className="pre viewer-text">{p.text}</pre>
        </>
      )}
      {p.kind === 'image' && (url
        ? <div className="viewer-media"><img src={url} alt={`Preview of ${p.path}`} /></div>
        : p.renderable === false ? <Banner tone="info">This image is larger than 20 MB; download it to view.</Banner> : <Loading />)}
      {p.kind === 'pdf' && (url
        ? <iframe className="viewer-pdf" src={url} title={`PDF preview of ${p.path}`} />
        : p.renderable === false ? <Banner tone="info">This PDF is larger than 20 MB; download it to view.</Banner> : <Loading />)}
      {p.kind === 'binary' && (
        <Banner tone="info">
          <div>This is not text, an image or a PDF. <Button size="sm" variant="ghost" onClick={onHex}>Open the hex view</Button></div>
        </Banner>
      )}
    </div>
  );
}

function HexPane({ source }: { source: ViewSource }) {
  const [start, setStart] = useState(0);
  const [page, setPage] = useState<Page | null>(null);
  const [error, setError] = useState('');
  const [go, setGo] = useState('');
  const key = endpoint(source, 'content', `start=${start}&length=${PAGE}`);

  useEffect(() => {
    let alive = true;
    setError('');
    api<Page>(endpoint(source, 'content', `start=${start}&length=${PAGE}`))
      .then((r) => alive && setPage(r))
      .catch((e) => alive && setError(e.message));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  function jump() {
    const t = go.trim().toLowerCase();
    const n = t.startsWith('0x') ? parseInt(t.slice(2), 16) : /^[0-9a-f]+h$/.test(t) ? parseInt(t.slice(0, -1), 16) : parseInt(t, 10);
    if (Number.isFinite(n) && n >= 0) setStart(n - (n % 16));
  }

  const bytes = page ? Uint8Array.from(atob(page.data_b64), (c) => c.charCodeAt(0)) : null;
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="row">
        <Button size="sm" icon={<ChevronLeft size={13} />} disabled={start === 0} onClick={() => setStart(Math.max(0, start - PAGE))}>Previous</Button>
        <Button size="sm" disabled={!page || page.eof} onClick={() => setStart(start + PAGE)}>Next <ChevronRight size={13} /></Button>
        <input className="input sm mono" style={{ width: 150 }} value={go} onChange={(e) => setGo(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && jump()}
          placeholder="0x1000 or 4096" aria-label="Go to offset" />
        <Button size="sm" onClick={jump}>Go to offset</Button>
        {page && <span className="small muted">Bytes {formatNumber(page.start)}–{formatNumber(page.start + page.length)} of {formatNumber(page.size)}</span>}
      </div>
      {error && <Banner tone="danger">{error}</Banner>}
      {!page && !error && <Loading />}
      {bytes && (bytes.length ? <pre className="pre hex-dump">{hexDump(bytes, page!.start)}</pre> : <Banner tone="info">No bytes at this offset (past the end of the file).</Banner>)}
    </div>
  );
}

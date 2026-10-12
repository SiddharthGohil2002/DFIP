import { Fragment, useEffect, useState, type ReactNode } from 'react';
import { ChevronLeft, ChevronRight, Eye, LocateFixed } from 'lucide-react';
import { api, fetchBlob } from '../lib/api';
import { formatBytes, formatNumber } from '../lib/format';
import { Banner, Button, Loading, Modal, Tabs } from './index';

/** A file inside an evidence image (by inode), a file DFIP stored (recovered, carved, extracted), a file taken out
 * of an archive or document (by its file-index record), or the raw bytes of a volume (unallocated space). */
export type ViewSource =
  | { kind: 'image'; evidenceId: string; inode: string; offset: number; name: string }
  | { kind: 'artifact'; artifactId: string; name: string }
  | { kind: 'member'; entryId: string; name: string }
  | { kind: 'volume'; evidenceId: string; volumeId: string; name: string }
  | { kind: 'shadow'; evidenceId: string; volumeId: string; inode: string; name: string };

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

/** Where a search hit or found value can be viewed: the file on the disk, the archive member, or the raw volume
 * (unallocated space). Null when it can't be shown (for example a member that was not extracted). */
export function locate(h: { evidence_id: string; path: string; inode: string | null; volume_id: string; partition_offset: number | null;
  member?: boolean; unallocated?: boolean; method?: string; entry_id?: string | null }): ViewSource | null {
  if (h.unallocated || h.method === 'unallocated') return { kind: 'volume', evidenceId: h.evidence_id, volumeId: h.volume_id, name: `Unallocated space (${h.volume_id})` };
  if (h.member) return h.entry_id ? { kind: 'member', entryId: h.entry_id, name: h.path } : null;
  if (h.partition_offset === null || !h.inode) return null;
  return { kind: 'image', evidenceId: h.evidence_id, inode: h.inode, offset: h.partition_offset, name: h.path };
}

/** Bytes to show highlighted when the viewer opens at a search hit. */
export interface ViewAt {
  offset: number;
  length?: number | null;
}

function endpoint(src: ViewSource, what: 'content' | 'preview' | 'raw', extra = '') {
  if (src.kind === 'artifact') return `/forensics/artifacts/${encodeURIComponent(src.artifactId)}/${what}${extra ? `?${extra}` : ''}`;
  if (src.kind === 'member') return `/forensics/members/${encodeURIComponent(src.entryId)}/${what}${extra ? `?${extra}` : ''}`;
  if (src.kind === 'shadow') return `/forensics/shadow-copies/${what}?evidence_id=${encodeURIComponent(src.evidenceId)}&volume_id=${encodeURIComponent(src.volumeId)}&inode=${encodeURIComponent(src.inode)}${extra ? `&${extra}` : ''}`;
  if (src.kind === 'volume') return `/forensics/evidence/${encodeURIComponent(src.evidenceId)}/volume?volume_id=${encodeURIComponent(src.volumeId)}${extra ? `&${extra}` : ''}`;
  return `/forensics/evidence/${encodeURIComponent(src.evidenceId)}/${what}?inode=${encodeURIComponent(src.inode)}&offset=${src.offset}${extra ? `&${extra}` : ''}`;
}

const hex2 = (b: number) => b.toString(16).padStart(2, '0');

const printable = (b: number) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.');

/** A hex dump; bytes in [mark.from, mark.to) are wrapped in <mark> in both the hex and the text columns. */
function hexDump(bytes: Uint8Array, base: number, mark?: { from: number; to: number } | null): ReactNode {
  const lines: ReactNode[] = [];
  const marked = (at: number) => !!mark && at >= mark.from && at < mark.to;
  for (let i = 0; i < bytes.length; i += 16) {
    const row = Array.from(bytes.subarray(i, i + 16));
    const at = base + i;
    if (!row.some((_, k) => marked(at + k))) {
      const hex = row.map(hex2);
      lines.push(`${at.toString(16).padStart(8, '0')}  ${hex.slice(0, 8).join(' ').padEnd(23, ' ')}  ${hex.slice(8).join(' ').padEnd(23, ' ')}  |${row.map(printable).join('')}|\n`);
      continue;
    }
    const cells: ReactNode[] = [];
    for (let k = 0; k < 16; k++) {
      const sep = k === 0 ? '' : k === 8 ? '  ' : ' ';
      const text = k < row.length ? hex2(row[k]) : '  ';
      cells.push(sep, marked(at + k) ? <mark key={`h${k}`}>{text}</mark> : text);
    }
    const chars = row.map((b, k) => (marked(at + k) ? <mark key={`a${k}`}>{printable(b)}</mark> : printable(b)));
    lines.push(<Fragment key={at}>{at.toString(16).padStart(8, '0')}{'  '}{cells}{'  |'}{chars}{'|\n'}</Fragment>);
  }
  return lines;
}

/** "View" button that opens the viewer for one file; with `at`, "View at offset" opens the hex view there. */
export function ViewButton({ source, at }: { source: ViewSource; at?: ViewAt }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      {at ? (
        <Button size="sm" icon={<LocateFixed size={13} />} onClick={() => setOpen(true)} title={`Byte ${at.offset.toLocaleString()} (0x${at.offset.toString(16)})`}>
          View at offset
        </Button>
      ) : (
        <Button size="sm" icon={<Eye size={13} />} onClick={() => setOpen(true)}>View</Button>
      )}
      {open && <FileViewer source={source} at={at} onClose={() => setOpen(false)} />}
    </>
  );
}

/** Preview (text, image or PDF, decided from the file's content) and a paged hex view. Nothing is written or downloaded. */
export function FileViewer({ source, at, onClose }: { source: ViewSource; at?: ViewAt; onClose: () => void }) {
  const hexOnly = source.kind === 'volume';  // raw volume bytes have no file type to preview
  const [tab, setTab] = useState<'preview' | 'hex'>(at || hexOnly ? 'hex' : 'preview');
  return (
    <Modal open title={source.name} onClose={onClose} wide>
      <Tabs<'preview' | 'hex'> value={tab} onChange={setTab} tabs={hexOnly ? [{ id: 'hex', label: 'Hex' }] : [{ id: 'preview', label: 'Preview' }, { id: 'hex', label: 'Hex' }]} />
      <div style={{ paddingTop: 12 }}>{tab === 'preview' ? <PreviewPane source={source} onHex={() => setTab('hex')} /> : <HexPane source={source} at={at} />}</div>
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

function HexPane({ source, at }: { source: ViewSource; at?: ViewAt }) {
  // Opening at a hit: start a few rows before it, on a 16-byte boundary.
  const [start, setStart] = useState(at ? Math.max(0, at.offset - (at.offset % 16) - 64) : 0);
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
      {at && <div className="small">Match at byte {formatNumber(at.offset)} (0x{at.offset.toString(16)}){at.length ? `, ${at.length} bytes long` : ''}, highlighted.</div>}
      {error && <Banner tone="danger">{error}</Banner>}
      {!page && !error && <Loading />}
      {bytes && (bytes.length
        ? <pre className="pre hex-dump">{hexDump(bytes, page!.start, at ? { from: at.offset, to: at.offset + Math.max(1, at.length || 1) } : null)}</pre>
        : <Banner tone="info">No bytes at this offset (past the end of the file).</Banner>)}
    </div>
  );
}

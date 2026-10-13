import { Fragment, useEffect, useMemo, useState } from 'react';
import { Copy, ExternalLink, FileText, ImageOff, MapPin, Search } from 'lucide-react';
import { WORLD_HEIGHT, WORLD_LAND, WORLD_WIDTH } from '../assets/worldMap';
import { fetchBlob } from '../lib/api';
import { useCase } from '../lib/caseContext';
import { formatBytes, shortHash, useTime } from '../lib/format';
import { IS_DESKTOP } from '../lib/platform';
import { TagButton } from '../lib/tags';
import { useApi } from '../lib/useApi';
import { ViewButton, type ViewSource } from '../ui/FileViewer';
import { Badge, Button, Card, Empty, ErrorBanner, Loading, Modal, PageHeader, Pager, Tabs } from '../ui';

type Tab = 'all' | 'picture' | 'video' | 'gps' | 'text';
const LIMIT = 60;
type Item = { _id: string; path: string; name?: string; size?: number; deleted?: boolean; evidence_id: string; inode?: string;
  partition_offset?: number; sha256?: string; hash_status?: string; container?: { kind: string; parent: string }; media?: any;
  ocr?: { text?: string; chars?: number; pages?: number } };
type Point = { _id: string; path: string; lat: number; lon: number; taken?: string | null; camera?: string | null; deleted?: boolean };

const fileName = (p: string) => p.split('!/').pop()!.split('/').pop()!;
const osm = (lat: number, lon: number) => `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`;
const source = (it: Item): ViewSource => (it.container ? { kind: 'member', entryId: it._id, name: it.path }
  : { kind: 'image', evidenceId: it.evidence_id, inode: it.inode!, offset: it.partition_offset || 0, name: it.path, volumeId: (it as any).volume_id });

export function MediaPage() {
  const { caseId, overview } = useCase();
  const time = useTime();
  const [tab, setTab] = useState<Tab>('all');
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [camera, setCamera] = useState('');
  const [origin, setOrigin] = useState('');
  const [deleted, setDeleted] = useState(false);
  const [skip, setSkip] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => setSkip(0), [tab, search, camera, origin, deleted]);

  const qs = new URLSearchParams({ case_id: caseId, limit: String(LIMIT), skip: String(skip) });
  if (tab === 'picture' || tab === 'video') qs.set('kind', tab);
  if (tab === 'gps') qs.set('gps', 'true');
  if (tab === 'text') qs.set('text', 'true');
  if (search) qs.set('search', search);
  if (camera) qs.set('camera', camera);
  if (origin) qs.set('source', origin);
  if (deleted) qs.set('deleted', 'true');
  const { data, error, loading } = useApi<{ data: Item[]; total: number }>(`/forensics/media?${qs}`);
  const cams = useApi<{ data: { camera: string; items: number }[] }>(`/forensics/media/cameras?case_id=${encodeURIComponent(caseId)}`);
  const places = useApi<{ data: Point[] }>(`/forensics/media/locations?case_id=${encodeURIComponent(caseId)}`);
  const c = overview?.counts;

  return (
    <div className="stack">
      <PageHeader
        title="Pictures and videos"
        subtitle="Every picture and video found by its content (renamed and deleted files, archive members and email attachments included), with camera and location metadata, keyframes of videos and text read in pictures and scans. The map is drawn offline."
      />
      {!!places.data?.data.length && (
        <Card title="Where pictures were taken" subtitle={`${places.data.data.length} with a GPS location · drawn without loading anything from the internet`}>
          <WorldMap points={places.data.data} onSelect={setOpen} />
        </Card>
      )}
      <Card flush>
        <Tabs<Tab> value={tab} onChange={setTab} tabs={[
          { id: 'all', label: 'All', count: c ? (c.pictures ?? 0) + (c.videos ?? 0) : undefined },
          { id: 'picture', label: 'Pictures', count: c?.pictures },
          { id: 'video', label: 'Videos', count: c?.videos },
          { id: 'gps', label: 'With a location', count: c?.media_with_gps },
          { id: 'text', label: 'Text in pictures', count: c?.ocr_files },
        ]} />
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
          <input className="input sm" style={{ maxWidth: 260 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
            placeholder="Search file names and folders" aria-label="Search pictures and videos" />
          <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
          <select className="select sm" style={{ width: 190 }} value={camera} onChange={(e) => setCamera(e.target.value)} aria-label="Camera">
            <option value="">All cameras</option>
            {(cams.data?.data || []).map((x) => <option key={x.camera} value={x.camera}>{x.camera} ({x.items})</option>)}
          </select>
          <select className="select sm" style={{ width: 170 }} value={origin} onChange={(e) => setOrigin(e.target.value)} aria-label="Found">
            <option value="">Found anywhere</option><option value="disk">On the disk</option><option value="archive">In archives</option>
            <option value="email">In emails</option>
          </select>
          <label className="check"><input type="checkbox" checked={deleted} onChange={(e) => setDeleted(e.target.checked)} /> Deleted only</label>
          <span className="small muted">{data ? `${data.total.toLocaleString()} items` : ''}</span>
        </div>
        <ErrorBanner error={error} />
        {loading && !data ? <Loading /> : !data?.data.length ? (
          <Empty title="No pictures or videos" text={search || camera || origin || deleted || tab !== 'all' ? 'Nothing matches these filters.'
            : 'Pictures and videos are read by the Standard and Full analysis profiles (module "Pictures and videos"); text in pictures by the Full profile.'} />
        ) : (
          <div className="media-grid">
            {data.data.map((it) => {
              const m = it.media || {};
              return (
                <button key={it._id} className="card media-card" onClick={() => setOpen(it._id)} aria-label={`Open ${fileName(it.path)}`}>
                  {it.media ? <MediaThumb entryId={it._id} label={fileName(it.path)} />
                    : <div className="media-box" title="A scanned document"><FileText size={34} /></div>}
                  <div className="media-meta">
                    <div className="small strong media-name" title={it.path}>{fileName(it.path)}</div>
                    <div className="tiny muted">{m.taken ? time(m.taken) : it.media ? 'no date recorded' : `scanned document, ${it.ocr?.pages ?? 1} page(s)`}</div>
                    <div className="media-badges">
                      {m.kind === 'video' && <Badge tone="info">VIDEO {Math.round(m.video?.duration ?? 0)} S</Badge>}
                      {m.gps && <Badge tone="accent">GPS</Badge>}
                      {it.deleted && <Badge tone="danger">DELETED</Badge>}
                      {it.container && <Badge>{it.container.kind === 'email' ? 'IN EMAIL' : 'IN ARCHIVE'}</Badge>}
                      {it.ocr?.chars ? <Badge tone="warn">TEXT</Badge> : null}
                      {m.error && <Badge tone="warn">UNREADABLE</Badge>}
                    </div>
                    {m.camera && <div className="tiny muted">{m.camera}</div>}
                  </div>
                </button>
              );
            })}
          </div>
        )}
        {data && <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />}
      </Card>
      {open && <Detail id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

/** A thumbnail DFIP made, fetched with the user's session (each view is recorded in the audit log). */
function MediaThumb({ entryId, label, frame, large }: { entryId: string; label: string; frame?: number; large?: boolean }) {
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let objectUrl: string | null = null;
    let live = true;
    setUrl(null);
    setFailed(false);
    fetchBlob(`/forensics/media/${encodeURIComponent(entryId)}/thumb${frame === undefined ? '' : `?frame=${frame}`}`)
      .then((b) => { if (live) { objectUrl = URL.createObjectURL(b); setUrl(objectUrl); } })
      .catch(() => live && setFailed(true));
    return () => { live = false; if (objectUrl) URL.revokeObjectURL(objectUrl); };
  }, [entryId, frame]);
  const cls = large ? 'media-box large' : 'media-box';
  if (failed) return <div className={cls}><ImageOff size={20} /></div>;
  return <div className={cls}>{url ? <img src={url} alt={label} /> : <Loading label="" />}</div>;
}

function Detail({ id, onClose }: { id: string; onClose: () => void }) {
  const time = useTime();
  const { data: it, error } = useApi<Item>(`/forensics/media/${encodeURIComponent(id)}`);
  const m = it?.media || {};
  return (
    <Modal open wide title={it ? fileName(it.path) : 'Picture or video'} onClose={onClose}>
      <ErrorBanner error={error} />
      {!it ? <Loading /> : (
        <div className="stack" style={{ gap: 14 }}>
          <div className="media-detail">
            {it.media ? <MediaThumb entryId={it._id} label={fileName(it.path)} large />
              : <div className="media-box large"><FileText size={48} /></div>}
            <dl className="kv">
              <dt>File</dt><dd className="mono small">{it.path}{it.deleted && <> <Badge tone="danger">DELETED</Badge></>}</dd>
              <dt>Size</dt><dd className="small">{formatBytes(it.size)} · {m.width && m.height ? `${m.width} × ${m.height}` : '—'} · {m.format || m.exif?.FileType || '—'}</dd>
              <dt>{m.kind === 'video' ? 'Recorded' : 'Taken'}</dt>
              <dd className="small"><span className="mono">{m.taken ? time(m.taken) : '—'}</span>
                {m.taken_local && <div className="tiny muted">recorded as {m.taken_local} (local); {m.taken_basis}</div>}
                {!m.taken_local && m.taken_basis && <div className="tiny muted">{m.taken_basis}</div>}</dd>
              {m.camera && (<><dt>Camera</dt><dd className="small">{m.camera}{m.exif?.LensModel ? ` · ${m.exif.LensModel}` : ''}{m.exif?.Software ? ` · ${m.exif.Software}` : ''}</dd></>)}
              {m.gps && (<><dt>Location</dt><dd className="small"><MapPin size={12} /> <span className="mono">{m.gps.lat}, {m.gps.lon}</span>
                {m.gps.alt != null && <span className="muted"> · {m.gps.alt} m</span>}<OsmLink lat={m.gps.lat} lon={m.gps.lon} /></dd></>)}
              {m.kind === 'video' && m.video && (<><dt>Video</dt><dd className="small">{(m.video.duration ?? 0).toFixed(1)} s · {m.video.video_codec}
                {m.video.frame_rate ? ` · ${m.video.frame_rate} fps` : ''}{m.video.audio_codec ? ` · audio ${m.video.audio_codec}` : ' · no audio'}</dd></>)}
              <dt>SHA-256</dt><dd className="mono tiny">{shortHash(it.sha256, 32)}{it.hash_status && <> <Badge tone={it.hash_status === 'KNOWN_BAD' ? 'danger' : 'warn'}>{it.hash_status.replace('_', ' ')}</Badge></>}</dd>
              {m.error && (<><dt>Problem</dt><dd className="small">{m.error}</dd></>)}
            </dl>
          </div>
          {!!m.frames?.length && (
            <div>
              <div className="small strong" style={{ marginBottom: 6 }}>Keyframes ({m.frames[0].method})</div>
              <div className="keyframes">
                {m.frames.map((f: any, i: number) => (
                  <figure key={f.file}>
                    <MediaThumb entryId={it._id} label={`Keyframe ${i + 1}`} frame={i} />
                    <figcaption className="tiny muted mono">{f.time != null ? `${f.time.toFixed(2)} s` : `frame ${i + 1}`}</figcaption>
                  </figure>
                ))}
              </div>
            </div>
          )}
          {it.ocr?.text && (
            <div>
              <div className="small strong" style={{ marginBottom: 6 }}>Text read by OCR{it.ocr.pages && it.ocr.pages > 1 ? ` (${it.ocr.pages} pages)` : ''}</div>
              <pre className="pre viewer-text">{it.ocr.text}</pre>
            </div>
          )}
          {!!Object.keys(m.exif || {}).length && (
            <details>
              <summary className="small">All metadata ({Object.keys(m.exif).length} fields)</summary>
              <dl className="kv" style={{ marginTop: 8 }}>
                {Object.entries(m.exif).map(([k, v]) => (<Fragment key={k}><dt>{k}</dt><dd className="small mono">{String(v)}</dd></Fragment>))}
              </dl>
            </details>
          )}
          <div className="row">
            <ViewButton source={source(it)} />
            <TagButton type="FILE" id={it._id} title={it.path} />
          </div>
        </div>
      )}
    </Modal>
  );
}

/** Opening a map site is the user's choice: a link on the web; on the desktop (no browser to hand it to) the address to copy. */
function OsmLink({ lat, lon }: { lat: number; lon: number }) {
  const url = osm(lat, lon);
  const [copied, setCopied] = useState(false);
  if (IS_DESKTOP) {
    return <Button size="sm" variant="ghost" icon={<Copy size={12} />} onClick={() => navigator.clipboard?.writeText(url).then(() => setCopied(true))}>
      {copied ? 'Address copied' : 'Copy OpenStreetMap address'}</Button>;
  }
  return <a className="small" style={{ marginLeft: 8 }} href={url} target="_blank" rel="noopener noreferrer">Open in OpenStreetMap <ExternalLink size={11} /></a>;
}

/** Locations on Natural Earth's land outlines (bundled), zoomed to the points, with the whole world one click away. */
export function WorldMap({ points, onSelect }: { points: Point[]; onSelect: (id: string) => void }) {
  const [world, setWorld] = useState(false);
  const xy = (p: Point) => [(p.lon + 180) * 2, (90 - p.lat) * 2] as const;
  const box = useMemo(() => {
    if (world || !points.length) return [0, 0, WORLD_WIDTH, WORLD_HEIGHT];
    const xs = points.map((p) => xy(p)[0]);
    const ys = points.map((p) => xy(p)[1]);
    let [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    const w = Math.max(40, (x1 - x0) * 1.4);  // at least 20 degrees across
    const h = Math.max(w / 2, (y1 - y0) * 1.4);
    const cx = (x0 + x1) / 2;
    const cy = (y0 + y1) / 2;
    x0 = Math.max(0, Math.min(WORLD_WIDTH - w, cx - w / 2));
    y0 = Math.max(0, Math.min(WORLD_HEIGHT - h, cy - h / 2));
    return [x0, y0, Math.min(w, WORLD_WIDTH), Math.min(h, WORLD_HEIGHT)];
  }, [points, world]);
  const r = box[2] / 110;
  return (
    <div className="stack" style={{ gap: 8 }}>
      <svg className="world-map" viewBox={box.join(' ')} role="img" aria-label={`Map of ${points.length} picture locations`} preserveAspectRatio="xMidYMid meet">
        <rect x={0} y={0} width={WORLD_WIDTH} height={WORLD_HEIGHT} className="world-sea" />
        <path d={WORLD_LAND} className="world-land" strokeWidth={box[2] / 900} />
        {points.map((p) => {
          const [x, y] = xy(p);
          return (
            <circle key={p._id} cx={x} cy={y} r={r} className="world-point" strokeWidth={r / 3} onClick={() => onSelect(p._id)}
              data-path={p.path}>
              <title>{`${fileName(p.path)}${p.deleted ? ' (deleted)' : ''}\n${p.lat}, ${p.lon}${p.camera ? `\n${p.camera}` : ''}`}</title>
            </circle>
          );
        })}
      </svg>
      <div className="row small muted">
        <span>{points.length} location{points.length === 1 ? '' : 's'} · select a point to open its picture</span>
        <Button size="sm" variant="ghost" onClick={() => setWorld(!world)}>{world ? 'Zoom to the locations' : 'Whole world'}</Button>
      </div>
    </div>
  );
}

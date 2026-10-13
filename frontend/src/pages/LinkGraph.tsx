import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type Simulation, type SimulationLinkDatum, type SimulationNodeDatum } from 'd3-force';
import { Expand, Focus, RotateCcw, Share2 } from 'lucide-react';
import { api } from '../lib/api';
import { useCase } from '../lib/caseContext';
import { useTime } from '../lib/format';
import { Badge, Banner, Button, Card, Empty, Loading, PageHeader } from '../ui';

interface GNode extends SimulationNodeDatum { id: string; type: string; category: string; label: string; detail?: string | null; evidence_ids: string[]; weight: number }
interface Ref { collection: string; id: string; type?: string; evidence_id?: string }
interface GEdge extends SimulationLinkDatum<GNode> { source: string | GNode; target: string | GNode; kind: string; count: number; refs: Ref[]; first?: string; last?: string }
interface Graph { nodes: GNode[]; edges: GEdge[]; omitted: Record<string, number>; totals?: { nodes: number; edges: number }; focus?: string | null }

// Three groups, coloured from the validated categorical slots (all-pairs safe: CVD dE 9.2, normal-vision dE 24.0); the
// letter inside each node and its label tell the types apart, so colour never carries identity alone.
const GROUPS: Record<string, { label: string; color: string }> = {
  people: { label: 'People and accounts', color: '#2a78d6' },
  devices: { label: 'Devices', color: '#eb6834' },
  data: { label: 'Files, programs and internet', color: '#1baf7a' },
};
const TYPES: Record<string, { label: string; group: string; glyph: string }> = {
  person: { label: 'Person', group: 'people', glyph: 'P' }, contact: { label: 'Contact', group: 'people', glyph: '@' }, account: { label: 'Account', group: 'people', glyph: 'A' },
  computer: { label: 'Computer', group: 'devices', glyph: 'C' }, phone: { label: 'Phone', group: 'devices', glyph: 'M' }, usb: { label: 'USB device', group: 'devices', glyph: 'U' },
  volume: { label: 'Removable volume', group: 'devices', glyph: 'V' }, file: { label: 'File', group: 'data', glyph: 'F' }, program: { label: 'Program', group: 'data', glyph: 'X' },
  domain: { label: 'Internet host', group: 'data', glyph: 'W' }, ip: { label: 'IP address', group: 'data', glyph: 'I' },
};
const PAGE: [RegExp, string, string][] = [
  [/^BROWSER_/, '/app/browser', 'browser record'], [/^EMAIL/, '/app/email', 'email'], [/^USB/, '/app/usb', 'USB device'], [/^(CHAT|CLOUD)_/, '/app/chat-cloud', 'chat or cloud record'],
  [/^PHONE_/, '/app/phones', 'phone record'], [/^(HTTP_REQUEST|DNS_QUERY|TLS_HANDSHAKE|NET_CONVERSATION)$/, '/app/network', 'network record'],
  [/^(RECENT_FILE|RECYCLE_BIN_ITEM|PROGRAM_RUN|USERASSIST|RDP_CONNECTION|JUMPLIST_ENTRY)$/, '/app/activity', 'Windows activity'],
  [/^EXECUTABLE$/, '/app/indicators', 'program'], [/^UNIX_EVENT$/, '/app/unix', 'log event'], [/^(USER_ACCOUNT|COMPUTER_INFO)$/, '/app/computer', 'account'],
];
const W = 1000, H = 640;
const radius = (n: GNode) => Math.min(20, 7 + Math.sqrt(n.weight) * 1.8);
const idOf = (x: string | GNode) => (typeof x === 'string' ? x : x.id);

/** The nodes that show their label: all of a small graph, else the 60 busiest (a selected node's neighbours always do). */
function labelSet(nodes: GNode[]): Set<string> {
  return new Set(nodes.length <= 120 ? nodes.map((n) => n.id) : [...nodes].sort((a, b) => b.weight - a.weight).slice(0, 60).map((n) => n.id));
}

function pageOf(ref: Ref): [string, string] {
  for (const [rx, to, label] of PAGE) if (rx.test(ref.type ?? '')) return [to, label];
  return ['/app/timeline', (ref.type ?? 'record').toLowerCase().replace(/_/g, ' ')];
}

export function LinkGraphPage() {
  const { caseId } = useCase();
  const time = useTime();
  const [graph, setGraph] = useState<Graph | null>(null);
  const [error, setError] = useState('');
  const [hidden, setHidden] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [onlyNear, setOnlyNear] = useState(false);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const [, setTick] = useState(0);
  const sim = useRef<Simulation<GNode, GEdge> | null>(null);
  const svg = useRef<SVGSVGElement>(null);
  const drag = useRef<{ kind: 'pan' | 'node'; id?: string; x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null);

  async function load(focus?: string) {
    setError('');
    const qs = new URLSearchParams();
    const types = Object.keys(TYPES).filter((t) => !hidden.includes(t));
    if (hidden.length) qs.set('types', types.join(','));
    if (focus) qs.set('focus', focus);
    try {
      const g = await api<Graph>(`/cases/${encodeURIComponent(caseId)}/graph?${qs}`);
      setGraph((old) => {
        if (!focus || !old) return g;
        // Expanding: add the node's neighbours to what is shown, keeping the positions already laid out.
        const have = new Map(old.nodes.map((n) => [n.id, n]));
        const nodes = [...old.nodes, ...g.nodes.filter((n) => !have.has(n.id)).map((n) => { const f = have.get(focus); return { ...n, x: f?.x, y: f?.y }; })];
        const key = (e: GEdge) => `${idOf(e.source)}|${idOf(e.target)}|${e.kind}`;
        const seen = new Set(old.edges.map(key));
        return { ...old, nodes, edges: [...old.edges.map((e) => ({ ...e, source: idOf(e.source), target: idOf(e.target) })), ...g.edges.filter((e) => !seen.has(key(e)))] };
      });
    } catch (e: any) {
      setError(e.message);
    }
  }
  useEffect(() => { setSelected(null); load(); }, [caseId, hidden.join(',')]); // eslint-disable-line react-hooks/exhaustive-deps

  // The force layout: runs when the graph changes, re-rendering at most once a frame.
  useEffect(() => {
    if (!graph) return;
    sim.current?.stop();
    let frame = 0;
    let fitted = false;
    // Labels sit under their nodes; a labelled node keeps clear a circle as wide as its label so labels don't overlap.
    const labelled = labelSet(graph.nodes);
    const clear = (d: GNode) => labelled.has(d.id) ? Math.max(radius(d) + 10, Math.min(d.label.length, 36) * 2.9 + 6) : radius(d) + 8;
    const s = forceSimulation<GNode, GEdge>(graph.nodes)
      .force('link', forceLink<GNode, GEdge>(graph.edges).id((d) => d.id).distance(110).strength(0.5))
      .force('charge', forceManyBody<GNode>().strength(-380))
      .force('center', forceCenter(W / 2, H / 2))
      .force('collide', forceCollide<GNode>().radius(clear).iterations(2))
      .alphaDecay(0.035)
      .on('tick', () => { if (!frame) frame = requestAnimationFrame(() => { frame = 0; setTick((t) => t + 1); }); })
      .on('end', () => {
        // Once the layout first settles, fit it to the view (leaving room for the labels on the right).
        if (fitted) return;
        fitted = true;
        const xs = graph.nodes.map((n) => n.x ?? 0), ys = graph.nodes.map((n) => n.y ?? 0);
        const x0 = Math.min(...xs) - 90, x1 = Math.max(...xs) + 90, y0 = Math.min(...ys) - 30, y1 = Math.max(...ys) + 40;
        const k = Math.max(0.3, Math.min(2.5, W / (x1 - x0), H / (y1 - y0)));
        setView({ k, x: (W - (x1 - x0) * k) / 2 - x0 * k, y: (H - (y1 - y0) * k) / 2 - y0 * k });
      });
    sim.current = s;
    return () => { s.stop(); cancelAnimationFrame(frame); };
  }, [graph]);

  const neighbours = useMemo(() => {
    const out = new Set<string>();
    if (!graph || !selected) return out;
    out.add(selected);
    for (const e of graph.edges) {
      if (idOf(e.source) === selected) out.add(idOf(e.target));
      if (idOf(e.target) === selected) out.add(idOf(e.source));
    }
    return out;
  }, [graph, selected]);

  const toSvg = (cx: number, cy: number) => {
    const r = svg.current!.getBoundingClientRect();
    const sx = ((cx - r.left) / r.width) * W, sy = ((cy - r.top) / r.height) * H;
    return { x: (sx - view.x) / view.k, y: (sy - view.y) / view.k, sx, sy };
  };
  function onWheel(e: React.WheelEvent) {
    const p = toSvg(e.clientX, e.clientY);
    const k = Math.min(4, Math.max(0.3, view.k * (e.deltaY < 0 ? 1.15 : 1 / 1.15)));
    setView({ k, x: p.sx - p.x * k, y: p.sy - p.y * k });
  }
  function down(e: React.PointerEvent, id?: string) {
    e.stopPropagation();
    (e.target as Element).setPointerCapture?.(e.pointerId);
    drag.current = { kind: id ? 'node' : 'pan', id, x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false };
  }
  function move(e: React.PointerEvent) {
    const d = drag.current;
    if (!d) return;
    if (Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) > 3) d.moved = true;
    if (d.kind === 'pan') {
      const r = svg.current!.getBoundingClientRect();
      setView({ ...view, x: d.vx + ((e.clientX - d.x) / r.width) * W, y: d.vy + ((e.clientY - d.y) / r.height) * H });
    } else if (d.moved && graph) {
      const n = graph.nodes.find((x) => x.id === d.id);
      const p = toSvg(e.clientX, e.clientY);
      if (n) { n.fx = p.x; n.fy = p.y; sim.current?.alphaTarget(0.2).restart(); }
    }
  }
  function up() {
    const d = drag.current;
    drag.current = null;
    sim.current?.alphaTarget(0);
    if (d?.kind === 'node' && !d.moved) setSelected(d.id === selected ? null : d.id ?? null);
    if (d?.kind === 'pan' && !d.moved) setSelected(null);
  }

  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const sel = nodes.find((n) => n.id === selected) ?? null;
  const visible = (id: string) => !onlyNear || !selected || neighbours.has(id);
  const labelled = useMemo(() => labelSet(nodes), [nodes]);
  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const selEdges = sel ? edges.filter((e) => idOf(e.source) === sel.id || idOf(e.target) === sel.id) : [];
  const omitted = Object.entries(graph?.omitted ?? {}).filter(([, n]) => n > 0);

  return (
    <div className="stack">
      <PageHeader title="Link graph"
        subtitle="People, devices, files, programs, internet hosts and accounts in the case, joined by what the records say they did. Every line rests on records you can open." />
      <Card>
        <div className="row between" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div className="legend" aria-label="Legend">
            {Object.entries(GROUPS).map(([g, v]) => <span key={g} className="legend-item small"><span className="legend-swatch" style={{ background: v.color }} />{v.label}</span>)}
          </div>
          <div className="row" style={{ gap: 6 }}>
            <Button size="sm" icon={<RotateCcw size={13} />} onClick={() => { setView({ k: 1, x: 0, y: 0 }); setSelected(null); setOnlyNear(false); load(); }}>Reset</Button>
          </div>
        </div>
        <div className="row" style={{ flexWrap: 'wrap', gap: '4px 14px', marginTop: 10 }}>
          {Object.entries(TYPES).map(([t, v]) => (
            <label key={t} className="check small">
              <input type="checkbox" checked={!hidden.includes(t)} onChange={(e) => setHidden(e.target.checked ? hidden.filter((x) => x !== t) : [...hidden, t])} />
              <b style={{ color: GROUPS[v.group].color, width: 12, display: 'inline-block', textAlign: 'center' }}>{v.glyph}</b> {v.label}
            </label>
          ))}
        </div>
        {omitted.length > 0 && <p className="tiny muted" style={{ margin: '8px 0 0' }}>
          The busiest are shown; left out: {omitted.map(([t, n]) => `${n} ${(TYPES[t]?.label ?? t).toLowerCase()}${n === 1 ? '' : 's'}`).join(', ')}. Open a node and expand it to see all its neighbours.</p>}
      </Card>
      {error && <Banner tone="danger">{error}</Banner>}
      {!graph ? <Loading /> : !nodes.length ? (
        <Card><Empty icon={<Share2 size={20} />} title="Nothing to link yet" text="Analyse the case's evidence: the graph is built from the records the analysis finds." /></Card>
      ) : (
        <Card flush>
          <div className="graph-wrap">
            <svg ref={svg} className={`graph-canvas ${drag.current ? 'dragging' : ''}`} viewBox={`0 0 ${W} ${H}`} role="img"
              aria-label={`Link graph: ${nodes.length} nodes and ${edges.length} connections. The table below lists every connection.`}
              onWheel={onWheel} onPointerDown={(e) => down(e)} onPointerMove={move} onPointerUp={up} onPointerLeave={() => { if (drag.current?.kind === 'pan') drag.current = null; }}>
              <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
                {edges.map((e, i) => {
                  const s = typeof e.source === 'string' ? byId.get(e.source) : e.source, t = typeof e.target === 'string' ? byId.get(e.target) : e.target;
                  if (!s || !t || s.x == null || t.x == null || !visible(s.id) || !visible(t.id)) return null;
                  const hi = !!selected && (s.id === selected || t.id === selected);
                  return <line key={i} className={`graph-edge ${hi ? 'hi' : ''}`} x1={s.x} y1={s.y} x2={t.x} y2={t.y} strokeWidth={Math.min(5, 1 + Math.log2(e.count))}>
                    <title>{`${s.label} ${e.kind} ${t.label} (${e.count})`}</title></line>;
                })}
                {nodes.map((n) => {
                  if (n.x == null || !visible(n.id)) return null;
                  const ty = TYPES[n.type] ?? { glyph: '?', group: 'data', label: n.type };
                  const dim = !!selected && !neighbours.has(n.id);
                  const r = radius(n);
                  return (
                    <g key={n.id} className={`graph-node ${dim ? 'dim' : ''} ${n.id === selected ? 'focus' : ''}`} transform={`translate(${n.x},${n.y})`}
                      onPointerDown={(e) => down(e, n.id)} role="button" tabIndex={0} aria-label={`${ty.label} ${n.label}`}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(n.id === selected ? null : n.id); } }}>
                      <circle r={r} fill={GROUPS[ty.group].color} />
                      <text className="glyph" style={{ fill: '#0f172a' }}>{ty.glyph}</text>
                      {(labelled.has(n.id) || neighbours.has(n.id)) && <text y={r + 11} textAnchor="middle">{n.label.length > 36 ? `${n.label.slice(0, 34)}…` : n.label}</text>}
                      <title>{`${ty.label}: ${n.label}${n.detail ? ` (${n.detail})` : ''}`}</title>
                    </g>
                  );
                })}
              </g>
            </svg>
            <aside className="graph-side" aria-label="Selected node">
              {!sel ? (
                <p className="small muted" style={{ margin: 0 }}>Select a node to see what it is connected to and the records behind each connection. Drag to move a node or the view; scroll to zoom.
                  {graph.totals && <><br /><br />{graph.totals.nodes.toLocaleString()} nodes and {graph.totals.edges.toLocaleString()} connections in the case.</>}</p>
              ) : (
                <>
                  <div className="row" style={{ gap: 6 }}><Badge>{TYPES[sel.type]?.label ?? sel.type}</Badge><span className="tiny muted">{sel.evidence_ids.join(', ')}</span></div>
                  <h3 style={{ fontSize: 15, margin: '6px 0 2px', wordBreak: 'break-word' }}>{sel.label}</h3>
                  {sel.detail && <div className="tiny muted mono break">{sel.detail}</div>}
                  <div className="row" style={{ margin: '10px 0', gap: 6, flexWrap: 'wrap' }}>
                    <Button size="sm" icon={<Expand size={13} />} onClick={() => load(sel.id)}>Expand</Button>
                    <Button size="sm" icon={<Focus size={13} />} onClick={() => setOnlyNear(!onlyNear)} aria-pressed={onlyNear}>{onlyNear ? 'Show all' : 'Only its neighbours'}</Button>
                  </div>
                  <div className="small strong">{selEdges.length} connection{selEdges.length === 1 ? '' : 's'}</div>
                  <ul style={{ listStyle: 'none', padding: 0, margin: '6px 0 0' }}>
                    {selEdges.map((e, i) => {
                      const out = idOf(e.source) === sel.id;
                      const other = byId.get(out ? idOf(e.target) : idOf(e.source));
                      return (
                        <li key={i} className="small" style={{ padding: '6px 0', borderTop: '1px solid var(--border)' }}>
                          {out ? <><i>{e.kind}</i> <button className="link-btn" onClick={() => setSelected(other?.id ?? null)}>{other?.label}</button></>
                            : <><button className="link-btn" onClick={() => setSelected(other?.id ?? null)}>{other?.label}</button> <i>{e.kind}</i> this</>}
                          <span className="tiny muted"> · {e.count}×{e.last ? ` · last ${time(e.last)}` : ''}</span>
                          <div className="tiny">{e.refs.map((r, j) => { const [to, label] = pageOf(r); return <span key={j}>{j > 0 && ', '}<Link to={to}>{label}</Link></span>; })}</div>
                        </li>
                      );
                    })}
                  </ul>
                </>
              )}
            </aside>
          </div>
        </Card>
      )}
      {graph && edges.length > 0 && (
        <Card title="Connections" subtitle="Every connection drawn above, busiest first: the same information as the picture, as a table." flush>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>From</th><th>Connection</th><th>To</th><th>Times</th><th>First</th><th>Last</th></tr></thead>
              <tbody>
                {edges.slice(0, 300).map((e, i) => {
                  const s = byId.get(idOf(e.source)), t = byId.get(idOf(e.target));
                  return <tr key={i}>
                    <td className="small break"><span className="tiny muted">{TYPES[s?.type ?? '']?.label}</span><br />{s?.label}</td><td className="small">{e.kind}</td>
                    <td className="small break"><span className="tiny muted">{TYPES[t?.type ?? '']?.label}</span><br />{t?.label}</td><td className="small">{e.count}</td>
                    <td className="small nowrap">{e.first ? time(e.first) : '—'}</td><td className="small nowrap">{e.last ? time(e.last) : '—'}</td>
                  </tr>;
                })}
              </tbody>
            </table>
          </div>
          {edges.length > 300 && <p className="tiny muted" style={{ padding: '0 14px 10px' }}>Showing 300 of {edges.length}.</p>}
        </Card>
      )}
    </div>
  );
}

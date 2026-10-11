import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';

/** Rounded axis maximum: 1, 1.5, 2, 2.5, 3, 4, 5, 6, 8 x 10^n. */
export function niceMax(v: number): number {
  if (v <= 5) return 5;
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].map((m) => m * p).find((m) => m >= v)!;
}

/** Width of a container, kept up to date (charts redraw at the new size). */
export function useWidth(min = 320) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  useLayoutEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(min, e.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, [min]);
  return [ref, width] as const;
}

export function ChartTooltip({ x, y, width, children }: { x: number; y: number; width: number; children: ReactNode }) {
  return (
    <div
      role="tooltip"
      style={{
        position: 'absolute', left: Math.max(0, Math.min(x + 12, width - 230)), top: Math.max(0, y - 10), pointerEvents: 'none', zIndex: 2,
        background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, boxShadow: 'var(--shadow-lg)', padding: '8px 10px',
        fontSize: 12, minWidth: 160, maxWidth: 260,
      }}
    >
      {children}
    </div>
  );
}

// One-hue sequential ramp (blue 100 -> 700) for magnitude; the lightest steps recede toward the surface.
export const SEQUENTIAL_BLUE = ['#cde2fb', '#b7d3f6', '#9ec5f4', '#86b6ef', '#6da7ec', '#5598e7', '#3987e5', '#2a78d6', '#256abf', '#1c5cab', '#184f95', '#104281', '#0d366b'];
const HEAT_STEPS = [1, 3, 5, 7, 9, 11].map((i) => SEQUENTIAL_BLUE[i]);
const GRID = '#e6eaf0';
const BASELINE = '#c7d0db';

export interface BarRow {
  key: string;
  label: string;
  value: number;
  /** Shown in the tooltip under the value. */
  hint?: string;
}

/** Ranked horizontal bars, one series, value printed at the end of each bar. */
export function HBarChart({ rows, unit, ariaLabel, labelWidth = 170 }: { rows: BarRow[]; unit: string; ariaLabel: string; labelWidth?: number }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState<{ i: number; x: number; y: number } | null>(null);
  const rowH = 26;
  const bar = 14;
  const pad = { top: 4, right: 44, left: labelWidth };
  const plotW = Math.max(40, width - pad.left - pad.right);
  const max = Math.max(1, ...rows.map((r) => r.value));
  const height = pad.top + rows.length * rowH + 4;
  const h = hover ? rows[hover.i] : null;
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <svg className="chart" width={width} height={height} role="img" aria-label={ariaLabel}>
        <line x1={pad.left} x2={pad.left} y1={pad.top} y2={height - 4} stroke={BASELINE} />
        {rows.map((r, i) => {
          const y = pad.top + i * rowH;
          const w = Math.max(r.value > 0 ? 2 : 0, (r.value / max) * plotW);
          const top = y + (rowH - bar) / 2;
          const rad = Math.min(4, w / 2);
          const d = `M${pad.left},${top} H${pad.left + w - rad} Q${pad.left + w},${top} ${pad.left + w},${top + rad} V${top + bar - rad} Q${pad.left + w},${top + bar} ${pad.left + w - rad},${top + bar} H${pad.left} Z`;
          return (
            <g key={r.key}>
              <title>{`${r.label}: ${r.value.toLocaleString()} ${unit}`}</title>
              <text x={pad.left - 8} y={y + rowH / 2 + 4} textAnchor="end" fontSize={12} fill="var(--ink-2)">
                {r.label.length > 26 ? `${r.label.slice(0, 25)}…` : r.label}
              </text>
              {w > 0 && <path d={d} fill="var(--accent)" opacity={hover && hover.i !== i ? 0.55 : 1} />}
              <text x={pad.left + w + 6} y={y + rowH / 2 + 4} fontSize={11.5} fill="var(--muted)">{r.value.toLocaleString()}</text>
              <rect x={0} y={y} width={width} height={rowH} fill="transparent"
                onPointerMove={(e) => setHover({ i, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })} onPointerLeave={() => setHover(null)} />
            </g>
          );
        })}
      </svg>
      {hover && h && (
        <ChartTooltip x={hover.x} y={hover.y} width={width}>
          <div className="strong break">{h.label}</div>
          <div><b style={{ fontSize: 14 }}>{h.value.toLocaleString()}</b> {unit}</div>
          {h.hint && <div className="muted">{h.hint}</div>}
        </ChartTooltip>
      )}
    </div>
  );
}

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

/** Events per weekday x hour: a 7 x 24 grid on a one-hue ramp, darker = more. */
export function Heatmap({ cells, max, zone }: { cells: [number, number, number][]; max: number; zone: string }) {
  const [ref, width] = useWidth(480);
  const [hover, setHover] = useState<{ d: number; h: number; n: number; x: number; y: number } | null>(null);
  const counts = new Map(cells.map(([d, h, n]) => [`${d}:${h}`, n]));
  const left = 40;
  const top = 18;
  const cw = (width - left - 4) / 24;
  const ch = 24;
  const height = top + 7 * ch + 4;
  const color = (n: number) => (n ? HEAT_STEPS[Math.min(HEAT_STEPS.length - 1, Math.ceil((n / Math.max(1, max)) * HEAT_STEPS.length) - 1)] : 'var(--surface-3)');
  const hh = (h: number) => `${String(h).padStart(2, '0')}:00`;
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <svg className="chart" width={width} height={height} role="img" aria-label={`Events by day of week and hour (${zone})`}>
        {Array.from({ length: 24 }, (_, h) => h % 3 === 0 && (
          <text key={h} x={left + h * cw + 1} y={12} fontSize={10.5} fill="var(--muted)">{hh(h).slice(0, 2)}</text>
        ))}
        {DAYS.map((day, di) => (
          <g key={day}>
            <text x={left - 8} y={top + di * ch + ch / 2 + 4} textAnchor="end" fontSize={11} fill="var(--muted)">{day}</text>
            {Array.from({ length: 24 }, (_, h) => {
              const n = counts.get(`${di + 1}:${h}`) || 0;
              return (
                <rect key={h} className="heat-cell" x={left + h * cw + 1} y={top + di * ch + 1} width={Math.max(1, cw - 2)} height={ch - 2} rx={3}
                  fill={color(n)} stroke={hover && hover.d === di && hover.h === h ? 'var(--ink)' : 'none'}
                  onPointerMove={(e) => setHover({ d: di, h, n, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })}
                  onPointerLeave={() => setHover(null)}>
                  <title>{`${day} ${hh(h)}–${hh((h + 1) % 24)}: ${n} events`}</title>
                </rect>
              );
            })}
          </g>
        ))}
      </svg>
      <div className="row small muted" style={{ gap: 6, marginTop: 6 }} aria-hidden="true">
        <span>Fewer</span>
        <span style={{ width: 14, height: 12, borderRadius: 3, background: 'var(--surface-3)', display: 'inline-block' }} />
        {HEAT_STEPS.map((c) => <span key={c} style={{ width: 14, height: 12, borderRadius: 3, background: c, display: 'inline-block' }} />)}
        <span>More (busiest hour: {max.toLocaleString()} events)</span>
      </div>
      {hover && (
        <ChartTooltip x={hover.x} y={hover.y} width={width}>
          <div><b style={{ fontSize: 14 }}>{hover.n.toLocaleString()}</b> events</div>
          <div className="muted">{DAYS[hover.d]} {hh(hover.h)}–{hh((hover.h + 1) % 24)} ({zone})</div>
        </ChartTooltip>
      )}
    </div>
  );
}

export interface UsbSpan {
  serial: string;
  label: string;
  drive_letters: string[];
  first: string | null;
  last: string | null;
  points: { kind: string; t: string }[];
}

const USB_KIND: Record<string, string> = {
  setupapi_first_install: 'First install (setupapi.dev.log)', first_install: 'First installed', last_install: 'Last installed',
  last_arrival: 'Last connected', last_removal: 'Last removed',
};

/** One lane per USB device on a shared time axis: a span from first to last record, a marker per recorded time. */
export function UsbLanes({ spans, format }: { spans: UsbSpan[]; format: (t: string) => string }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState<{ label: string; kind: string; t: string; x: number; y: number } | null>(null);
  const times = spans.flatMap((s) => s.points.map((p) => new Date(p.t).getTime()));
  if (!times.length) return <div ref={ref}><p className="small muted" style={{ margin: 0 }}>No USB connection times were recorded.</p></div>;
  let t0 = Math.min(...times);
  let t1 = Math.max(...times);
  if (t1 - t0 < 86_400_000) { t0 -= 43_200_000; t1 += 43_200_000; }
  const left = 150;
  const right = 16;
  const laneH = 34;
  const height = spans.length * laneH + 22;
  const x = (t: number) => left + ((t - t0) / (t1 - t0)) * (width - left - right);
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <svg className="chart" width={width} height={height} role="img" aria-label="USB device connection times">
        {spans.map((s, i) => {
          const y = i * laneH + laneH / 2;
          const pts = s.points.map((p) => ({ ...p, x: x(new Date(p.t).getTime()) }));
          return (
            <g key={s.serial + i}>
              <text x={left - 10} y={y - 2} textAnchor="end" fontSize={12} fill="var(--ink-2)">{s.label.length > 20 ? `${s.label.slice(0, 19)}…` : s.label}</text>
              <text x={left - 10} y={y + 11} textAnchor="end" fontSize={10} fill="var(--muted)">{s.serial.length > 20 ? `${s.serial.slice(0, 19)}…` : s.serial}</text>
              <line x1={left} x2={width - right} y1={y} y2={y} stroke={GRID} />
              {pts.length > 1 && <line x1={pts[0].x} x2={pts[pts.length - 1].x} y1={y} y2={y} stroke={SEQUENTIAL_BLUE[3]} strokeWidth={4} strokeLinecap="round" />}
              {pts.map((p) => (
                <circle key={p.kind} cx={p.x} cy={y} r={5} fill="var(--accent)" stroke="var(--surface)" strokeWidth={2}
                  onPointerMove={(e) => setHover({ label: s.label, kind: p.kind, t: p.t, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })}
                  onPointerLeave={() => setHover(null)}>
                  <title>{`${s.label}: ${USB_KIND[p.kind] || p.kind} ${format(p.t)}`}</title>
                </circle>
              ))}
            </g>
          );
        })}
        <text x={left} y={height - 4} fontSize={10.5} fill="var(--muted)">{format(new Date(t0).toISOString()).slice(0, 10)}</text>
        <text x={width - right} y={height - 4} textAnchor="end" fontSize={10.5} fill="var(--muted)">{format(new Date(t1).toISOString()).slice(0, 10)}</text>
      </svg>
      {hover && (
        <ChartTooltip x={hover.x} y={hover.y} width={width}>
          <div className="strong">{hover.label}</div>
          <div>{USB_KIND[hover.kind] || hover.kind}</div>
          <div className="muted">{format(hover.t)}</div>
        </ChartTooltip>
      )}
    </div>
  );
}

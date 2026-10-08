import { createContext, useContext } from 'react';

export type TimeMode = 'utc' | 'local';
export const TimeModeContext = createContext<{ mode: TimeMode; setMode: (m: TimeMode) => void }>({
  mode: 'utc',
  setMode: () => {},
});

const pad = (n: number) => String(n).padStart(2, '0');

/** Formats a timestamp in UTC (forensic default) or the viewer's local zone. */
export function formatTime(value: string | null | undefined, mode: TimeMode, withZone = true): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  if (mode === 'utc') {
    const s = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
    return withZone ? `${s} UTC` : s;
  }
  const s = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return withZone ? `${s} local` : s;
}

/** Hook returning a formatter bound to the current time display mode. */
export function useTime() {
  const { mode } = useContext(TimeModeContext);
  return (value: string | null | undefined, withZone = true) => formatTime(value, mode, withZone);
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export const formatNumber = (n: number | null | undefined) => (n === null || n === undefined ? '—' : n.toLocaleString());

export const shortHash = (h?: string | null, n = 16) => (h ? `${h.slice(0, n)}…` : '—');

export const humanize = (s?: string | null) =>
  (s || '').toLowerCase().replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());

/** Converts a <input type="datetime-local"> value to ISO, interpreting it in the active time mode. */
export function localInputToIso(value: string, mode: TimeMode): string | null {
  if (!value) return null;
  if (mode === 'utc') return new Date(value + ':00Z').toISOString();
  return new Date(value).toISOString();
}

/** Converts an ISO timestamp to a datetime-local input value in the active time mode. */
export function isoToLocalInput(iso: string, mode: TimeMode): string {
  const d = new Date(iso);
  if (mode === 'utc') return d.toISOString().slice(0, 16);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

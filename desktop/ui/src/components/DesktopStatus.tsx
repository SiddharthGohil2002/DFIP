import React, { useEffect, useState } from 'react';
import * as I from 'lucide-react';
import { api } from '../services/api';

interface DeviceStatus {
  devices: any[];
  online_count: number;
  is_online: boolean;
  pending_desktop_jobs: number;
}

export default function DesktopStatus({ compact = false }: { compact?: boolean }) {
  const [status, setStatus] = useState<DeviceStatus | null>(null);
  const [lastSync, setLastSync] = useState<Date | null>(null);

  useEffect(() => {
    function fetch() {
      api<DeviceStatus>('/desktop/status')
        .then((s) => { setStatus(s); setLastSync(new Date()); })
        .catch(() => {});
    }
    fetch();
    const t = setInterval(fetch, 30_000);
    return () => clearInterval(t);
  }, []);

  const online = status?.is_online ?? false;
  const primaryDevice = status?.devices?.[0];
  const pending = status?.pending_desktop_jobs ?? 0;

  function fmtSince(d: Date) {
    const secs = Math.floor((Date.now() - d.getTime()) / 1000);
    if (secs < 60) return 'just now';
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    return `${Math.floor(secs / 3600)}h ago`;
  }

  if (compact) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, padding: '4px 0' }}>
        <span style={{ width: 8, height: 8, borderRadius: 999, background: online ? 'var(--green)' : 'var(--muted)', display: 'inline-block' }} />
        <span className="muted">{online ? (primaryDevice?.device_name || 'Desktop') : 'Offline'}</span>
        {pending > 0 && <span className="badge warn" style={{ fontSize: 10, padding: '1px 6px' }}>{pending} pending</span>}
      </div>
    );
  }

  return (
    <div className="card" style={{ padding: '14px 16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontWeight: 700, fontSize: 13 }}>
          <I.Monitor size={15} />
          DFIP Desktop
        </div>
        <span style={{ width: 9, height: 9, borderRadius: 999, background: online ? 'var(--green)' : 'var(--border)' }} />
      </div>
      {online && primaryDevice ? (
        <>
          <div style={{ fontSize: 12.5, fontWeight: 600 }}>{primaryDevice.device_name}</div>
          <div className="muted" style={{ fontSize: 11.5, marginTop: 2 }}>OS: {primaryDevice.os}</div>
          {lastSync && <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>Last sync: {fmtSince(lastSync)}</div>}
          {pending > 0 && (
            <div style={{ marginTop: 8 }}>
              <span className="badge warn" style={{ fontSize: 11 }}>{pending} job{pending !== 1 ? 's' : ''} pending</span>
            </div>
          )}
        </>
      ) : (
        <>
          <div className="muted" style={{ fontSize: 12.5 }}>No desktop connected</div>
          {lastSync && <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>Last sync: {fmtSince(lastSync)}</div>}
          <div style={{ marginTop: 8, fontSize: 11.5, color: 'var(--muted)' }}>
            Desktop-only operations will queue until a desktop reconnects.
          </div>
          <a href="/download" style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--red)', fontWeight: 600, marginTop: 8 }}>
            <I.Download size={12} /> Get DFIP Desktop
          </a>
        </>
      )}
    </div>
  );
}

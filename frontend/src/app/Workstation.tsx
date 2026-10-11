import { useEffect, useState } from 'react';
import { Monitor } from 'lucide-react';
import { hasNativeRuntime, native, type LocalTool, type WorkstationInfo } from '../lib/platform';
import { serverUrl } from '../lib/api';
import { Badge, Card } from '../ui';

/** Desktop app only: details of this workstation and the forensic tools installed on it. */
export function WorkstationCard({ showTools = false }: { showTools?: boolean }) {
  const [info, setInfo] = useState<WorkstationInfo | null>(null);
  const [tools, setTools] = useState<LocalTool[] | null>(null);
  const [error, setError] = useState('');
  const nativeOk = hasNativeRuntime();

  useEffect(() => {
    if (!nativeOk) return;
    native.systemInfo().then(setInfo).catch((e) => setError(e.message));
    native.toolInventory().then(setTools).catch(() => setTools([]));
  }, [nativeOk]);

  return (
    <Card title={<span className="row"><Monitor size={16} /> This workstation</span>} subtitle="Desktop app">
      <div className="stack" style={{ gap: 12 }}>
        {/* The top bar hides the server address in narrower windows; it is always shown here. */}
        <dl className="kv" style={{ gridTemplateColumns: '110px 1fr', margin: 0 }}>
          <dt>Server</dt><dd>{serverUrl().replace(/^https?:\/\//, '')}</dd>
          {nativeOk && !error && info && (
            <>
              <dt>Host</dt><dd>{info.hostname}</dd>
              <dt>System</dt><dd>{info.os} · {info.arch} · {info.cpu_cores} cores</dd>
              <dt>App</dt><dd>{info.app} {info.version}</dd>
            </>
          )}
        </dl>
        {!nativeOk ? (
          <p className="small muted mt-0" style={{ margin: 0 }}>
            Running outside the desktop shell (development mode): all case work is available, but workstation-side features such as local hash verification need the installed DFIP desktop app.
          </p>
        ) : error ? (
          <p className="small" style={{ color: 'var(--danger)', margin: 0 }}>{error}</p>
        ) : (
          tools && (
            <div className="small">
              <span className="muted">Local forensic tools: </span>
              {tools.filter((t) => t.available).length} of {tools.length} available
              {showTools && (
                <div className="row" style={{ marginTop: 8 }}>
                  {tools.map((t) => (
                    <Badge key={t.name} tone={t.available ? 'ok' : 'neutral'} title={t.path || t.hint}>{t.name}</Badge>
                  ))}
                </div>
              )}
            </div>
          )
        )}
      </div>
    </Card>
  );
}

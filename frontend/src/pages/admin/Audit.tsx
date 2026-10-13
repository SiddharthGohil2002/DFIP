import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { useAuth } from '../../lib/auth';
import { api } from '../../lib/api';
import { humanize, useTime } from '../../lib/format';
import { useApi } from '../../lib/useApi';
import { Banner, Button, Card, Empty, Loading, PageHeader } from '../../ui';
import { ExportButton } from '../../ui/ExportButton';

export function AuditPage() {
  const { can } = useAuth();
  const time = useTime();
  const path = can('AUDIT_READ') ? '/admin/audit' : null;
  const log = useApi<{ data: any[] }>(path);
  const [verify, setVerify] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState('');

  if (!can('AUDIT_READ')) return <Banner tone="warn">Your role cannot read the audit log.</Banner>;

  async function check() {
    setBusy(true);
    try {
      setVerify(await api('/chain/verify'));
    } catch (e: any) {
      setVerify({ valid: false, error: e.message });
    } finally {
      setBusy(false);
    }
  }

  const rows = (log.data?.data || []).filter((r) => !filter || JSON.stringify(r).toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="stack">
      <PageHeader
        title="Audit log"
        subtitle="Every action, chained by SHA-256: each record includes the hash of the one before, so editing or deleting any record breaks the chain. Latest 300 records."
        actions={<Button icon={<ShieldCheck size={15} />} busy={busy} onClick={check}>Verify hash chain</Button>}
      />
      {verify && (
        <Banner tone={verify.valid ? 'ok' : 'danger'}>
          {verify.valid ? `Chain intact: ${verify.records_checked} records verified up to sequence ${verify.last_sequence}.` : verify.error || `Chain BROKEN at sequence ${verify.broken_sequence}.`}
        </Banner>
      )}
      <Card flush>
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
          <input className="input sm" style={{ maxWidth: 320 }} value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by user, action, case…" aria-label="Filter" />
          <span className="small muted">{rows.length} records</span>
          <span style={{ flex: 1 }} />
          {!!log.data?.data.length && <ExportButton path={path} what="audit log" />}
        </div>
        {log.loading && !log.data ? <Loading /> : !rows.length ? <Empty title="No records" /> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>#</th><th>Time</th><th>User</th><th>Action</th><th>Resource</th><th>Record hash</th></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r._id}>
                    <td className="mono small">{r.sequence}</td>
                    <td className="mono small nowrap">{time(r.timestamp)}</td>
                    <td className="small">{r.user_name}<div className="tiny muted">{r.user_role}</div></td>
                    <td className="small strong">{humanize(r.action)}</td>
                    <td className="small mono">{r.resource_type} {r.metadata?.case_id || r.resource_id}</td>
                    <td className="mono tiny muted">{(r.record_hash || '').slice(0, 16)}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

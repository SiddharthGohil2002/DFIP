import { useState } from 'react';
import { ShieldCheck, ShieldX } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { actionLabel, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { Banner, Card, Empty, Hash, Loading, PageHeader, StatusBadge } from '../ui';

export function CustodyPage() {
  const { caseId, overview } = useCase();
  const time = useTime();
  const [evidence, setEvidence] = useState('');
  const path = `/chain?case_id=${encodeURIComponent(caseId)}${evidence ? `&evidence_id=${encodeURIComponent(evidence)}` : ''}`;
  const { data, loading } = useApi<{ data: any[]; audit_chain: { valid: boolean; records_checked?: number; broken_sequence?: number } }>(path);
  const chain = data?.audit_chain;

  return (
    <div className="stack">
      <PageHeader
        title="Chain of custody"
        subtitle="Append-only record of who handled each evidence item and what was done: registration, integrity checks, analysis integrity checks, file recoveries and deletions. Newest first."
        actions={
          (overview?.evidence.length || 0) > 1 && (
            <select className="select" style={{ width: 220 }} value={evidence} onChange={(e) => setEvidence(e.target.value)} aria-label="Evidence">
              <option value="">All evidence</option>
              {overview!.evidence.map((e) => <option key={e.evidence_id} value={e.evidence_id}>{e.evidence_id}</option>)}
            </select>
          )
        }
      />
      {chain && (
        <Banner tone={chain.valid ? 'ok' : 'danger'}>
          {chain.valid ? <ShieldCheck size={18} /> : <ShieldX size={18} />}
          {chain.valid
            ? `Audit hash chain verified: ${chain.records_checked?.toLocaleString()} records, no tampering detected.`
            : `Audit hash chain BROKEN at sequence ${chain.broken_sequence}: records may have been altered.`}
        </Banner>
      )}
      <Card flush>
        {loading && !data ? <Loading /> : !data?.data.length ? (
          <Empty title="No custody records" text="Records are created when evidence is registered, verified, analyzed or files are recovered." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Time</th><th>Evidence</th><th>Action</th><th>Handler</th><th>SHA-256</th><th>Result / detail</th></tr></thead>
              <tbody>
                {data.data.map((c) => (
                  <tr key={c._id}>
                    <td className="mono small nowrap">{time(c.timestamp)}</td>
                    <td className="mono small nowrap">{c.evidence_id}</td>
                    <td className="small strong" title={c.action}>{actionLabel(c.action)}</td>
                    <td className="small">{c.user_name || c.user_id}</td>
                    <td>{c.sha256 ? <Hash value={c.sha256} short={16} /> : <span className="muted">—</span>}</td>
                    <td className="small">
                      {(c.status || c.result) && <StatusBadge status={c.status || c.result} />}
                      {c.original_path && <div className="muted break">{c.original_path}</div>}
                      {c.reason && <div className="break">Reason: {c.reason}</div>}
                    </td>
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

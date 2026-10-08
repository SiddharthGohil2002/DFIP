import { useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { post } from '../lib/api';
import { humanize, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Artifact } from '../lib/types';
import { Badge, Button, Card, Empty, Loading, PageHeader, StatusBadge, useToast } from '../ui';

export function IndicatorsPage() {
  const { caseId, reloadOverview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const enc = encodeURIComponent(caseId);
  const yara = useApi<{ data: Artifact[] }>(`/forensics/artifacts?case_id=${enc}&artifact_type=MALWARE_INDICATOR`);
  const patterns = useApi<{ data: any[] }>(`/forensics/patterns?case_id=${enc}`);
  const anomalies = useApi<{ data: any[] }>(`/forensics/anomalies?case_id=${enc}`);
  const [busy, setBusy] = useState('');

  async function recompute(kind: 'patterns' | 'anomalies') {
    setBusy(kind);
    try {
      await post(`/forensics/${kind}?case_id=${enc}`);
      (kind === 'patterns' ? patterns : anomalies).reload();
      reloadOverview();
      toast(`${humanize(kind)} recomputed`, 'ok');
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  const anomalyRows = (anomalies.data?.data || []).filter((a) => a.detection_method !== 'ISOLATION_FOREST' || a.is_anomaly);
  const method = anomalies.data?.data[0]?.detection_method;

  return (
    <div className="stack">
      <PageHeader
        title="Indicators"
        subtitle="Leads for the investigator to review, not conclusions: YARA signature matches in user-profile scripts and executables, rule-based activity patterns, and statistically unusual events."
      />

      <Card title="Malware signature matches (YARA)" subtitle="Scripts and executables under user profiles are extracted and scanned with the server's YARA rules during analysis." flush>
        {yara.loading && !yara.data ? <Loading /> : !yara.data?.data.length ? (
          <Empty title="No YARA matches" text="No scanned file matched the rule set." />
        ) : (
          <table className="table">
            <thead><tr><th>Rule</th><th>File in image</th><th>Inode</th><th>Evidence</th></tr></thead>
            <tbody>
              {yara.data.data.map((m) => (
                <tr key={m._id}>
                  <td><Badge tone="danger">{m.rule}</Badge></td>
                  <td className="cell-path mono small">{m.original_path}</td>
                  <td className="mono small">{m.inode}</td>
                  <td className="mono small">{m.evidence_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <div className="grid cols-2">
        <Card
          title="Activity patterns"
          subtitle="Rule-based checks over the case timeline."
          actions={can('ANALYSIS_RUN') && <Button size="sm" icon={<RefreshCw size={13} />} busy={busy === 'patterns'} onClick={() => recompute('patterns')}>Recompute</Button>}
          flush
        >
          {patterns.loading && !patterns.data ? <Loading /> : !patterns.data?.data.length ? (
            <Empty title="No patterns detected" />
          ) : (
            <table className="table">
              <thead><tr><th>Pattern</th><th>Risk</th><th>Reason</th></tr></thead>
              <tbody>
                {patterns.data.data.map((p) => (
                  <tr key={p._id}>
                    <td className="strong">{p.pattern}</td>
                    <td><StatusBadge status={p.risk} /></td>
                    <td className="small">{p.reason}<div className="tiny muted">confidence {Math.round((p.confidence || 0) * 100)}%</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card
          title="Anomalies"
          subtitle={method === 'ISOLATION_FOREST' ? 'IsolationForest over event type, hour of day and gaps between events; only flagged events are listed.' : 'Rule-based score (too few events for the statistical model).'}
          actions={can('ANALYSIS_RUN') && <Button size="sm" icon={<RefreshCw size={13} />} busy={busy === 'anomalies'} onClick={() => recompute('anomalies')}>Recompute</Button>}
          flush
        >
          {anomalies.loading && !anomalies.data ? <Loading /> : !anomalyRows.length ? (
            <Empty title="No anomalies flagged" />
          ) : (
            <div className="table-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
              <table className="table">
                <thead><tr><th>Event time</th><th>Type</th><th className="right">Score</th></tr></thead>
                <tbody>
                  {anomalyRows.slice(0, 100).map((a) => (
                    <tr key={a._id}>
                      <td className="mono small nowrap">{time(a.timestamp)}</td>
                      <td className="small">{a.event_type ? humanize(a.event_type) : a.reason}</td>
                      <td className="right"><Badge tone={a.anomaly_score >= 75 ? 'danger' : a.anomaly_score >= 50 ? 'warn' : 'neutral'}>{Math.round(a.anomaly_score)}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

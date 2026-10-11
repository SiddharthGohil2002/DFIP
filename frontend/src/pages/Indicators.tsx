import { useState } from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { post } from '../lib/api';
import { humanize, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Artifact, FsEntry } from '../lib/types';
import { Badge, Button, Card, Empty, Hash, Loading, PageHeader, StatusBadge, useToast } from '../ui';
import { FileDetails, HASH_KIND } from './Files';

export function IndicatorsPage() {
  const { caseId, reloadOverview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const enc = encodeURIComponent(caseId);
  const yara = useApi<{ data: Artifact[] }>(`/forensics/artifacts?case_id=${enc}&artifact_type=MALWARE_INDICATOR`);
  const patterns = useApi<{ data: any[] }>(`/forensics/patterns?case_id=${enc}`);
  const anomalies = useApi<{ data: any[] }>(`/forensics/anomalies?case_id=${enc}`);
  const hashHits = useApi<{ data: Artifact[] }>(`/forensics/artifacts?case_id=${enc}&artifact_type=HASH_SET_MATCH&limit=500`);
  const renamed = useApi<{ data: FsEntry[]; total: number }>(`/forensics/flagged?case_id=${enc}&kind=renamed&limit=200`);
  const encrypted = useApi<{ data: FsEntry[]; total: number }>(`/forensics/flagged?case_id=${enc}&kind=encrypted&limit=200`);
  const [busy, setBusy] = useState('');
  const [details, setDetails] = useState<FsEntry | null>(null);
  const hits = [...(hashHits.data?.data || [])].sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'KNOWN_BAD' ? -1 : 1));
  const flagged = [...(renamed.data?.data || []), ...(encrypted.data?.data || []).filter((e) => !e.ext_mismatch)]
    .sort((a, b) => a.path.localeCompare(b.path));

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
        subtitle="Leads for the investigator to review, not conclusions: YARA signature matches, files in known-bad or notable hash sets, files whose name hides what they are or whose content is encrypted, rule-based activity patterns, and statistically unusual events."
      />

      <Card title="Hash set matches" subtitle="Files whose MD5, SHA-1 or SHA-256 is in a known-bad or notable hash set (Administration → Hash sets). Every copy is listed, deleted ones too." flush>
        {hashHits.loading && !hashHits.data ? <Loading /> : !hits.length ? (
          <Empty title="No hash set matches" text="No file is in a known-bad or notable hash set, or no such set has been imported." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Status</th><th>File in image</th><th>SHA-256</th><th>Hash sets</th><th>Evidence</th></tr></thead>
              <tbody>
                {hits.map((h) => (
                  <tr key={h._id}>
                    <td><Badge tone={HASH_KIND[h.kind as keyof typeof HASH_KIND]?.tone}>{HASH_KIND[h.kind as keyof typeof HASH_KIND]?.label.toUpperCase()}</Badge></td>
                    <td className="cell-path mono small">{h.original_path}{h.deleted && <div><Badge tone="danger">DELETED</Badge></div>}</td>
                    <td><Hash value={h.sha256} short={16} /></td>
                    <td className="small">{(h.sets || []).map((x: any) => x.name).join(', ')}</td>
                    <td className="mono small">{h.evidence_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title="Renamed and encrypted files"
        subtitle="Files whose content contradicts their name (for example a CSV named holiday.jpg), and files that are encrypted or look like an encrypted container. Found from the content, not the name."
        actions={<Link className="btn sm" to="/app/files?flag=renamed">Open in Files</Link>}
        flush
      >
        {(renamed.loading && !renamed.data) || (encrypted.loading && !encrypted.data) ? <Loading /> : !flagged.length ? (
          <Empty title="Nothing hidden or encrypted" text="No file's content contradicts its name and no encrypted file was recognised." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>File in image</th><th>Content</th><th>Finding</th><th /></tr></thead>
              <tbody>
                {flagged.map((f) => (
                  <tr key={f._id} className={f.deleted ? 'is-deleted' : ''}>
                    <td className="cell-path mono small">{f.path}<div className="tiny muted">{f.evidence_id}</div></td>
                    <td className="small mono">{f.mime}</td>
                    <td className="small">
                      {f.ext_mismatch && <div><Badge tone="warn">RENAMED</Badge> the name suggests {f.expected_type}</div>}
                      {f.encryption && <div><Badge tone="warn">ENCRYPTED</Badge> {f.encryption.detail}</div>}
                    </td>
                    <td className="right"><Button size="sm" variant="ghost" onClick={() => setDetails(f)} aria-label={`Details of ${f.path}`}>Details</Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <FileDetails caseId={caseId} file={details} onClose={() => setDetails(null)} />

      <Card title="Malware signature matches (YARA)" subtitle="Programs, scripts, documents and archives anywhere on the disk, chosen by their real type, are scanned with the server's YARA rules during analysis." flush>
        {yara.loading && !yara.data ? <Loading /> : !yara.data?.data.length ? (
          <Empty title="No YARA matches" text="No scanned file matched the rule set." />
        ) : (
          <table className="table">
            <thead><tr><th>Rule</th><th>File in image</th><th>Inode</th><th>Evidence</th></tr></thead>
            <tbody>
              {yara.data.data.map((m) => (
                <tr key={m._id}>
                  <td><Badge tone="danger">{m.rule}</Badge></td>
                  <td className="cell-path mono small">{m.original_path}{m.deleted && <div><Badge tone="danger">DELETED</Badge></div>}</td>
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

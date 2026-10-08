import { useState } from 'react';
import { Download, FileText } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { downloadFile, post } from '../lib/api';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Report } from '../lib/types';
import { Badge, Button, Card, Empty, Hash, Loading, PageHeader, useToast } from '../ui';

const SECTIONS = [
  'Case details and lead investigator',
  'Evidence register with full SHA-256 hashes',
  'Chain of custody',
  'Analysis summary per image',
  'Deleted files (filesystem metadata)',
  'Recovered files with hashes',
  'USB device history',
  'Browser history',
  'Browser downloads',
  'Malware indicators (YARA)',
  'Investigator findings',
  'Timeline of notable events',
  'Audit trail integrity check',
];

export function ReportsPage() {
  const { caseId, reloadOverview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const list = useApi<{ data: Report[] }>(`/reports?case_id=${encodeURIComponent(caseId)}`);
  const reports = (list.data?.data || []).filter((r) => r.case_id === caseId);
  const [busy, setBusy] = useState(false);

  async function generate() {
    setBusy(true);
    try {
      const r = await post<Report>(`/reports?case_id=${encodeURIComponent(caseId)}`);
      toast(`${r.report_id} (version ${r.version}) generated`, 'ok');
      list.reload();
      reloadOverview();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy(false);
    }
  }

  async function download(r: Report) {
    try {
      const sha = await downloadFile(`/reports/${encodeURIComponent(r.report_id)}/download`, `${r.report_id}-${r.case_id}.pdf`);
      if (sha && sha !== r.sha256) toast('Warning: the server returned a different hash than recorded', 'danger');
    } catch (e: any) {
      toast(e.message, 'danger');
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Reports"
        subtitle="Each report is a new PDF version built from the case's current data. Its SHA-256 is recorded when generated, so any later change to the file can be detected."
        actions={can('REPORT_CREATE') && <Button variant="primary" icon={<FileText size={15} />} busy={busy} onClick={generate}>Generate report</Button>}
      />
      <div className="grid grid-side">
        <Card title="Report versions" flush>
          {list.loading && !list.data ? <Loading /> : !reports.length ? (
            <Empty icon={<FileText size={20} />} title="No reports for this case" text="Generate the first report when the analysis is complete and findings are recorded." />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Report</th><th>Version</th><th>Generated</th><th>PDF SHA-256</th><th /></tr></thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r._id}>
                      <td className="mono strong nowrap">{r.report_id}</td>
                      <td><Badge tone="accent">v{r.version}</Badge></td>
                      <td className="small nowrap">{time(r.created_at)}</td>
                      <td><Hash value={r.sha256} short={20} /></td>
                      <td className="nowrap right"><Button size="sm" icon={<Download size={13} />} onClick={() => download(r)}>PDF</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="What a report contains">
          <ol className="small" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 4 }}>
            {SECTIONS.map((s) => <li key={s}>{s}</li>)}
          </ol>
          <p className="small muted" style={{ marginBottom: 0 }}>To check a downloaded copy: <code>Get-FileHash file.pdf -Algorithm SHA256</code> must equal the SHA-256 listed here.</p>
        </Card>
      </div>
    </div>
  );
}

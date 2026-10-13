import { useState } from 'react';
import { Trash2, Upload } from 'lucide-react';
import { api, del } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { formatBytes, shortHash, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { Badge, Button, Card, Empty, ErrorBanner, Field, Modal, StatusBadge, useToast } from '../ui';
import { ExportButton } from '../ui/ExportButton';

/** Timelines made by Plaso, imported into the case: their events appear on the timeline as Plaso events. */
export function TimelineImportsCard({ onChanged }: { onChanged: () => void }) {
  const { caseId, overview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const path = `/cases/${encodeURIComponent(caseId)}/timeline-imports`;
  const res = useApi<{ data: any[] }>(path, { pollMs: 4000 });
  const [open, setOpen] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [evidence, setEvidence] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const rows = res.data?.data || [];

  async function submit() {
    if (!file) return setError('Choose a file');
    setBusy(true);
    setError('');
    try {
      const form = new FormData();
      form.append('file', file);
      if (evidence) form.append('evidence_id', evidence);
      const r = await api<any>(`/cases/${encodeURIComponent(caseId)}/timeline-imports`, { method: 'POST', body: form });
      toast(`${r.filename}: importing (${r.job_id})`, 'ok');
      setOpen(false);
      res.reload();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(x: any) {
    try {
      const r = await del<any>(`/cases/${encodeURIComponent(caseId)}/timeline-imports/${encodeURIComponent(x.import_id)}`);
      toast(`${x.import_id} deleted with its ${r.events_removed.toLocaleString()} events`, 'ok');
      res.reload();
      onChanged();
    } catch (e: any) {
      toast(e.message, 'danger');
    }
  }

  return (
    <Card title="Imported timelines" flush
      subtitle="Timelines made by Plaso (psort -o json_line or -o l2tcsv), shown here as Plaso events next to DFIP's own. The file is kept read-only with its SHA-256."
      actions={<>
        {can('ANALYSIS_RUN') && <Button size="sm" icon={<Upload size={13} />} onClick={() => { setOpen(true); setFile(null); setError(''); }}>Import a Plaso timeline</Button>}
        {rows.length > 0 && <ExportButton path={path} what="list of imports" />}
      </>}>
      <ErrorBanner error={res.error} />
      {!rows.length ? <Empty title="No imported timelines" /> : (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>File</th><th>Format</th><th className="right">Events</th><th>Parsers</th><th>Imported</th><th>Status</th><th /></tr></thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x.import_id}>
                  <td className="small"><span className="strong">{x.filename}</span> <span className="mono tiny muted">{x.import_id}</span>
                    <div className="tiny muted">{formatBytes(x.size)} · SHA-256 {shortHash(x.sha256)}{x.evidence_id ? ` · made from ${x.evidence_id}` : ''}</div></td>
                  <td className="small">{x.format}</td>
                  <td className="right small">{x.events != null ? x.events.toLocaleString() : '—'}
                    {x.events_without_time ? <div className="tiny muted">{x.events_without_time.toLocaleString()} without a time</div> : null}</td>
                  <td className="small">{Object.entries(x.parsers || {}).slice(0, 3).map(([p, n]: any) => <div key={p} className="tiny"><span className="mono">{p}</span> {n}</div>)}</td>
                  <td className="small nowrap">{time(x.created_at)}<div className="tiny muted">{x.created_by_name}</div></td>
                  <td>{x.status === 'COMPLETED' ? <Badge tone="ok">COMPLETED</Badge> : <StatusBadge status={x.status} />}
                    {x.error && <div className="tiny muted">{x.error}</div>}</td>
                  <td className="right">{can('ANALYSIS_RUN') && !['QUEUED', 'RUNNING'].includes(x.status) && (
                    <Button size="sm" variant="ghost" icon={<Trash2 size={13} />} aria-label={`Delete ${x.import_id}`} onClick={() => remove(x)}>Delete</Button>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal open={open} title="Import a Plaso timeline" onClose={() => setOpen(false)}
        footer={<><Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" onClick={submit} disabled={busy || !file} busy={busy}>Import</Button></>}>
        <div className="stack">
          <ErrorBanner error={error} />
          <Field label="Timeline file" hint="psort -o json_line (.jsonl) or -o l2tcsv (.csv)">
            <input type="file" aria-label="Timeline file" accept=".jsonl,.json,.csv,.txt" onChange={(e) => setFile(e.target.files?.[0] || null)} />
          </Field>
          <Field label="Made from" hint="The evidence Plaso read (optional). Deleting that evidence deletes the import too.">
            <select className="input" value={evidence} onChange={(e) => setEvidence(e.target.value)}>
              <option value="">Not linked to evidence</option>
              {(overview?.evidence || []).map((e) => <option key={e.evidence_id} value={e.evidence_id}>{e.evidence_id} · {e.filename}</option>)}
            </select>
          </Field>
        </div>
      </Modal>
    </Card>
  );
}

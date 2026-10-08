import { useState } from 'react';
import { NotebookPen, Plus } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { post } from '../lib/api';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Finding } from '../lib/types';
import { Badge, Banner, Button, Card, Empty, Field, Loading, Modal, PageHeader, StatusBadge, useToast } from '../ui';

const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function FindingsPage() {
  const { caseId, overview, reloadOverview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const list = useApi<{ data: Finding[] }>(`/findings?case_id=${encodeURIComponent(caseId)}`);
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('MEDIUM');
  const [description, setDescription] = useState('');
  const [linked, setLinked] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  function start() {
    setTitle('');
    setSeverity('MEDIUM');
    setDescription('');
    setLinked([]);
    setError('');
    setOpen(true);
  }

  async function save() {
    setBusy(true);
    setError('');
    try {
      await post('/findings', { case_id: caseId, title: title.trim(), severity, description: description.trim(), evidence_ids: linked });
      toast('Finding recorded', 'ok');
      setOpen(false);
      list.reload();
      reloadOverview();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Findings"
        subtitle="Investigator observations, linked to the evidence they rest on. Findings appear in every report generated afterwards."
        actions={can('FINDING_CREATE') && <Button variant="primary" icon={<Plus size={15} />} onClick={start}>Record finding</Button>}
      />
      {list.loading && !list.data ? (
        <Loading />
      ) : !list.data?.data.length ? (
        <Card><Empty icon={<NotebookPen size={20} />} title="No findings yet" text="Record what the evidence shows, for example: “payroll-export.csv was deleted 31 minutes before a SanDisk USB drive was first connected”." /></Card>
      ) : (
        list.data.data.map((f) => (
          <Card key={f._id}>
            <div className="row between" style={{ alignItems: 'flex-start' }}>
              <div style={{ minWidth: 0 }}>
                <div className="row"><StatusBadge status={f.severity} /><h3 style={{ fontSize: 15.5 }}>{f.title}</h3></div>
                <p style={{ margin: '8px 0 0', whiteSpace: 'pre-wrap' }}>{f.description}</p>
                {!!f.evidence_ids?.length && <div className="row" style={{ marginTop: 10 }}>{f.evidence_ids.map((e) => <Badge key={e} tone="accent">{e}</Badge>)}</div>}
              </div>
              <span className="small muted nowrap">{time(f.created_at)}</span>
            </div>
          </Card>
        ))
      )}

      <Modal
        open={open}
        title="Record finding"
        onClose={() => setOpen(false)}
        footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={title.trim().length < 2 || !description.trim()} onClick={save}>Save finding</Button></>}
      >
        <Field label="Title">
          <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} autoFocus placeholder="e.g. Payroll export deleted after USB activity" />
        </Field>
        <Field label="Severity">
          <select className="select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Observation" hint="State what the evidence shows and where (paths, times, serials). Avoid conclusions the evidence does not support.">
          <textarea className="textarea" rows={6} value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        {!!overview?.evidence.length && (
          <Field label="Supporting evidence">
            <div className="row">
              {overview.evidence.map((e) => (
                <label key={e.evidence_id} className="check">
                  <input type="checkbox" checked={linked.includes(e.evidence_id)} onChange={(ev) => setLinked(ev.target.checked ? [...linked, e.evidence_id] : linked.filter((x) => x !== e.evidence_id))} />
                  {e.evidence_id} <span className="muted">{e.filename}</span>
                </label>
              ))}
            </div>
          </Field>
        )}
        {error && <Banner tone="danger">{error}</Banner>}
      </Modal>
    </div>
  );
}

import { useEffect, useState } from 'react';
import { CheckCircle2, ImagePlus, MessageSquare, NotebookPen, Pencil, Plus, RotateCcw, Send, Trash2, Undo2, X } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { api, del, fetchBlob, patch, post } from '../lib/api';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { Finding, FindingAttachment, FindingEvent, FindingStatus } from '../lib/types';
import { Badge, Banner, Button, Card, Empty, Field, Loading, Modal, PageHeader, StatusBadge, Tabs, type Tone, useToast } from '../ui';
import { Comments, usePeople } from '../ui/Comments';

const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const STATUS: Record<FindingStatus, { label: string; tone: Tone }> = {
  DRAFT: { label: 'Draft', tone: 'neutral' }, IN_REVIEW: { label: 'In review', tone: 'info' },
  CHANGES_REQUESTED: { label: 'Changes requested', tone: 'warn' }, APPROVED: { label: 'Approved', tone: 'ok' },
};
const EVENT: Record<FindingEvent['action'], string> = {
  CREATED: 'wrote it', EDITED: 'edited it', SUBMITTED: 'sent it for review', APPROVED: 'approved it', CHANGES_REQUESTED: 'asked for changes', REOPENED: 'reopened it',
};
type Filter = 'ALL' | FindingStatus;
type Dialog = { kind: 'new' } | { kind: 'edit' | 'submit' | 'approve' | 'changes' | 'reopen' | 'delete'; f: Finding } | null;

export function FindingsPage() {
  const { caseId, overview, reloadOverview } = useCase();
  const { can, user } = useAuth();
  const toast = useToast();
  const time = useTime();
  const list = useApi<{ data: Finding[] }>(`/findings?case_id=${encodeURIComponent(caseId)}`);
  const people = usePeople(caseId).data?.data ?? [];
  const [filter, setFilter] = useState<Filter>('ALL');
  const [dialog, setDialog] = useState<Dialog>(null);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('MEDIUM');
  const [description, setDescription] = useState('');
  const [linked, setLinked] = useState<string[]>([]);
  const [text, setText] = useState('');
  const [reviewer, setReviewer] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const rows = list.data?.data ?? [];
  const shown = filter === 'ALL' ? rows : rows.filter((f) => f.status === filter);
  const mine = (f: Finding) => !!user && (f.created_by === user._id || user.role === 'ADMIN');
  const canReview = (f: Finding) => !!user && can('FINDING_REVIEW') && f.created_by !== user._id && f.status === 'IN_REVIEW';

  function start(d: Dialog) {
    setError(''); setText(''); setReviewer('');
    if (d && d.kind === 'new') { setTitle(''); setSeverity('MEDIUM'); setDescription(''); setLinked([]); }
    if (d && d.kind === 'edit') { setTitle(d.f.title); setSeverity(d.f.severity); setDescription(d.f.description); setLinked(d.f.evidence_ids ?? []); }
    setDialog(d);
  }

  async function run() {
    if (!dialog) return;
    setBusy(true); setError('');
    try {
      const id = 'f' in dialog ? encodeURIComponent(dialog.f._id) : '';
      const fields = { title: title.trim(), severity, description: description.trim(), evidence_ids: linked };
      if (dialog.kind === 'new') await post('/findings', { case_id: caseId, ...fields });
      if (dialog.kind === 'edit') await patch(`/findings/${id}`, fields);
      if (dialog.kind === 'submit') await post(`/findings/${id}/submit`, { reviewer_id: reviewer || null, note: text.trim() });
      if (dialog.kind === 'approve') await post(`/findings/${id}/review`, { decision: 'APPROVED', note: text.trim() });
      if (dialog.kind === 'changes') await post(`/findings/${id}/review`, { decision: 'CHANGES_REQUESTED', note: text.trim() });
      if (dialog.kind === 'reopen') await post(`/findings/${id}/reopen`, { reason: text.trim() });
      if (dialog.kind === 'delete') await del(`/findings/${id}`, { reason: text.trim() });
      toast({ new: 'Finding recorded', edit: 'Finding updated', submit: 'Sent for review', approve: 'Finding approved', changes: 'Changes requested',
        reopen: 'Finding reopened', delete: 'Finding deleted' }[dialog.kind], 'ok');
      setDialog(null);
      list.reload();
      reloadOverview();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const reviewers = people.filter((p) => p.can_review && p.user_id !== ('f' in (dialog ?? {}) ? (dialog as any).f.created_by : user?._id));
  const count = (s: FindingStatus) => rows.filter((f) => f.status === s).length;
  const needsText = dialog && ['changes', 'reopen', 'delete'].includes(dialog.kind);
  const textOk = !needsText || text.trim().length >= (dialog?.kind === 'changes' ? 1 : 5);
  const formOk = !dialog || !['new', 'edit'].includes(dialog.kind) || (title.trim().length >= 2 && !!description.trim());

  return (
    <div className="stack">
      <PageHeader
        title="Findings"
        subtitle="Investigator observations, linked to the evidence they rest on. A finding is reviewed by someone else before it is approved; reports show each finding's status."
        actions={can('FINDING_CREATE') && <Button variant="primary" icon={<Plus size={15} />} onClick={() => start({ kind: 'new' })}>Record finding</Button>}
      />
      {rows.length > 0 && (
        <Card flush>
          <Tabs<Filter> value={filter} onChange={setFilter} tabs={[
            { id: 'ALL', label: 'All', count: rows.length }, { id: 'DRAFT', label: 'Drafts', count: count('DRAFT') },
            { id: 'IN_REVIEW', label: 'In review', count: count('IN_REVIEW') }, { id: 'CHANGES_REQUESTED', label: 'Changes requested', count: count('CHANGES_REQUESTED') },
            { id: 'APPROVED', label: 'Approved', count: count('APPROVED') },
          ]} />
        </Card>
      )}
      {list.loading && !list.data ? (
        <Loading />
      ) : !rows.length ? (
        <Card><Empty icon={<NotebookPen size={20} />} title="No findings yet" text="Record what the evidence shows, for example: “payroll-export.csv was deleted 31 minutes before a SanDisk USB drive was first connected”." /></Card>
      ) : !shown.length ? (
        <Card><Empty title="Nothing here" text="No finding has this status." /></Card>
      ) : (
        shown.map((f) => (
          <Card key={f._id}>
            <div className="row between" style={{ alignItems: 'flex-start' }}>
              <div style={{ minWidth: 0 }}>
                <div className="row"><StatusBadge status={f.severity} /><Badge tone={STATUS[f.status].tone}>{STATUS[f.status].label}</Badge><h3 style={{ fontSize: 15.5 }}>{f.title}</h3></div>
                <p style={{ margin: '8px 0 0', whiteSpace: 'pre-wrap' }}>{f.description}</p>
                {!!f.evidence_ids?.length && <div className="row" style={{ marginTop: 10 }}>{f.evidence_ids.map((e) => <Badge key={e} tone="accent">{e}</Badge>)}</div>}
                <FindingPictures f={f} editable={can('FINDING_CREATE') && mine(f) && ['DRAFT', 'CHANGES_REQUESTED'].includes(f.status)} reload={list.reload} />
                <div className="tiny muted" style={{ marginTop: 8 }}>
                  By {f.created_by_name ?? 'unknown'}{f.status === 'APPROVED' && f.reviewed_by_name ? ` · approved by ${f.reviewed_by_name} ${time(f.reviewed_at)}` : ''}
                  {f.status === 'IN_REVIEW' && f.reviewer_id ? ` · waiting for ${people.find((p) => p.user_id === f.reviewer_id)?.name ?? 'a reviewer'}` : ''}
                </div>
              </div>
              <span className="small muted nowrap">{time(f.created_at)}</span>
            </div>
            <div className="row" style={{ marginTop: 12, flexWrap: 'wrap' }}>
              {can('FINDING_CREATE') && mine(f) && ['DRAFT', 'CHANGES_REQUESTED'].includes(f.status) && <>
                <Button size="sm" icon={<Pencil size={13} />} onClick={() => start({ kind: 'edit', f })}>Edit</Button>
                <Button size="sm" variant="primary" icon={<Send size={13} />} onClick={() => start({ kind: 'submit', f })}>Send for review</Button>
              </>}
              {canReview(f) && <>
                <Button size="sm" variant="primary" icon={<CheckCircle2 size={13} />} onClick={() => start({ kind: 'approve', f })}>Approve</Button>
                <Button size="sm" icon={<Undo2 size={13} />} onClick={() => start({ kind: 'changes', f })}>Request changes</Button>
              </>}
              {can('FINDING_CREATE') && mine(f) && ['IN_REVIEW', 'APPROVED'].includes(f.status) &&
                <Button size="sm" icon={<RotateCcw size={13} />} onClick={() => start({ kind: 'reopen', f })}>{f.status === 'APPROVED' ? 'Reopen' : 'Withdraw'}</Button>}
              {can('FINDING_CREATE') && mine(f) && f.status !== 'APPROVED' &&
                <Button size="sm" variant="ghost" icon={<Trash2 size={13} />} onClick={() => start({ kind: 'delete', f })}>Delete</Button>}
              <Button size="sm" variant="ghost" icon={<MessageSquare size={13} />} onClick={() => setOpen({ ...open, [f._id]: !open[f._id] })}
                aria-expanded={!!open[f._id]}>{open[f._id] ? 'Hide' : 'History and comments'}{f.comment_count ? ` (${f.comment_count})` : ''}</Button>
            </div>
            {open[f._id] && (
              <div className="grid cols-2" style={{ marginTop: 12, alignItems: 'start' }}>
                <div>
                  <div className="small strong">History</div>
                  <ol className="history small">
                    {(f.history ?? []).map((h, i) => (
                      <li key={i}>
                        <span className="muted">{time(h.at)}</span> {h.by_name} {EVENT[h.action] ?? h.action.toLowerCase()}
                        {h.changes && <span className="muted"> ({Object.keys(h.changes).join(', ')})</span>}
                        {(h.note || h.reason) && <div className="tiny" style={{ whiteSpace: 'pre-wrap' }}>“{h.note || h.reason}”</div>}
                      </li>
                    ))}
                  </ol>
                </div>
                <Comments caseId={caseId} targetType="FINDING" targetId={f._id} />
              </div>
            )}
          </Card>
        ))
      )}

      <Modal
        open={!!dialog}
        title={!dialog ? '' : { new: 'Record finding', edit: 'Edit finding', submit: 'Send for review', approve: 'Approve finding', changes: 'Request changes',
          reopen: (dialog as any).f?.status === 'APPROVED' ? 'Reopen finding' : 'Withdraw from review', delete: 'Delete finding' }[dialog.kind]}
        onClose={() => setDialog(null)}
        footer={<><Button onClick={() => setDialog(null)}>Cancel</Button>
          <Button variant={dialog?.kind === 'delete' ? 'danger' : 'primary'} busy={busy} disabled={!textOk || !formOk} onClick={run}>
            {!dialog ? '' : { new: 'Save finding', edit: 'Save changes', submit: 'Send', approve: 'Approve', changes: 'Send back', reopen: 'Reopen', delete: 'Delete' }[dialog.kind]}
          </Button></>}
      >
        {dialog && (dialog.kind === 'new' || dialog.kind === 'edit') && <>
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
            <fieldset className="field" style={{ border: 'none', padding: 0, margin: 0 }}>
              <legend className="small strong" style={{ color: 'var(--ink-2)', marginBottom: 6 }}>Supporting evidence</legend>
              <div className="row">
                {overview.evidence.map((e) => (
                  <label key={e.evidence_id} className="check">
                    <input type="checkbox" checked={linked.includes(e.evidence_id)} onChange={(ev) => setLinked(ev.target.checked ? [...linked, e.evidence_id] : linked.filter((x) => x !== e.evidence_id))} />
                    {e.evidence_id} <span className="muted">{e.filename}</span>
                  </label>
                ))}
              </div>
            </fieldset>
          )}
        </>}
        {dialog?.kind === 'submit' && <>
          <Field label="Reviewer" hint="Someone on the case who may review findings. Without one, the case's investigator is told.">
            <select className="select" value={reviewer} onChange={(e) => setReviewer(e.target.value)} aria-label="Reviewer">
              <option value="">Anyone who may review</option>
              {reviewers.map((p) => <option key={p.user_id} value={p.user_id}>{p.name} ({p.role.toLowerCase()})</option>)}
            </select>
          </Field>
          <Field label="Note for the reviewer (optional)"><textarea className="textarea" rows={3} value={text} onChange={(e) => setText(e.target.value)} /></Field>
        </>}
        {dialog && ['approve', 'changes'].includes(dialog.kind) && <>
          <p className="small" style={{ marginTop: 0 }}><b>{(dialog as any).f.title}</b></p>
          <Field label={dialog.kind === 'changes' ? 'What should change' : 'Note (optional)'}>
            <textarea className="textarea" rows={4} value={text} onChange={(e) => setText(e.target.value)} autoFocus />
          </Field>
        </>}
        {dialog && ['reopen', 'delete'].includes(dialog.kind) && (
          <Field label="Reason" hint="At least 5 characters; kept in the history and the audit log.">
            <textarea className="textarea" rows={3} value={text} onChange={(e) => setText(e.target.value)} autoFocus />
          </Field>
        )}
        {error && <Banner tone="danger">{error}</Banner>}
      </Modal>
    </div>
  );
}

/** A picture attached to a finding, fetched with the user's credentials. */
function Picture({ fid, a, onOpen }: { fid: string; a: FindingAttachment; onOpen: (url: string) => void }) {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    let u: string | null = null;
    fetchBlob(`/findings/${encodeURIComponent(fid)}/attachments/${a.attachment_id}`).then((b) => { u = URL.createObjectURL(b); setUrl(u); }).catch(() => setUrl(null));
    return () => { if (u) URL.revokeObjectURL(u); };
  }, [fid, a.attachment_id]);
  return url ? <button type="button" className="link-button" onClick={() => onOpen(url)} aria-label={`Enlarge ${a.caption || a.name}`}><img src={url} alt={a.caption || a.name} /></button>
    : <div className="media-box" style={{ width: 180, height: 120 }}>…</div>;
}

/** Screenshots of what a finding rests on: PNG or JPEG, added while the finding can be edited; reports can show them. */
function FindingPictures({ f, editable, reload }: { f: Finding; editable: boolean; reload: () => void }) {
  const toast = useToast();
  const [big, setBig] = useState<{ url: string; alt: string } | null>(null);
  const [caption, setCaption] = useState('');
  const [busy, setBusy] = useState(false);
  const pics = f.attachments ?? [];
  if (!pics.length && !editable) return null;
  const base = `/findings/${encodeURIComponent(f._id)}/attachments`;

  async function change(fn: () => Promise<unknown>, done: string) {
    setBusy(true);
    try {
      await fn();
      toast(done, 'ok');
      reload();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy(false);
    }
  }
  const add = (file: File) => change(() => {
    const form = new FormData();
    form.append('file', file);
    form.append('caption', caption.trim());
    setCaption('');
    return api(base, { method: 'POST', body: form });
  }, 'Picture attached');

  return (
    <div>
      {!!pics.length && (
        <div className="attach-strip">
          {pics.map((a) => (
            <figure key={a.attachment_id}>
              <Picture fid={f._id} a={a} onOpen={(url) => setBig({ url, alt: a.caption || a.name })} />
              <figcaption className="tiny muted"><span style={{ flex: 1 }} className="break">{a.caption || a.name}</span>
                {editable && <button type="button" className="btn ghost icon-btn" style={{ width: 22, height: 22 }} disabled={busy}
                  onClick={() => change(() => del(`${base}/${a.attachment_id}`), 'Picture removed')} aria-label={`Remove picture ${a.caption || a.name}`}><X size={12} /></button>}
              </figcaption>
            </figure>
          ))}
        </div>
      )}
      {editable && (
        <div className="row" style={{ marginTop: 10 }}>
          <input className="input sm" style={{ maxWidth: 240 }} placeholder="Caption (optional)" value={caption} maxLength={300}
            onChange={(e) => setCaption(e.target.value)} aria-label={`Caption for a picture of ${f.title}`} />
          <label className={`btn sm${busy ? ' disabled' : ''}`} style={{ cursor: busy ? 'progress' : 'pointer' }}>
            {busy ? <span className="spinner" /> : <ImagePlus size={13} />} Add picture
            <input type="file" accept="image/png,image/jpeg" hidden disabled={busy} aria-label={`Add a picture to ${f.title}`}
              onChange={(e) => { const file = e.target.files?.[0]; e.target.value = ''; if (file) add(file); }} />
          </label>
          <span className="tiny muted">PNG or JPEG, up to 10 MB</span>
        </div>
      )}
      <Modal open={!!big} title={big?.alt || ''} wide onClose={() => setBig(null)}>
        {big && <img src={big.url} alt={big.alt} style={{ maxWidth: '100%', display: 'block', margin: '0 auto' }} />}
      </Modal>
    </div>
  );
}

import { Fragment, useEffect, useState } from 'react';
import { Archive, Camera, LogIn, LogOut, MoveRight, PackageCheck, Pencil, Plus, Printer, Trash2, X } from 'lucide-react';
import { api, del, downloadFile, fetchBlob, patch, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { isoToLocalInput, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { Badge, Banner, Button, Card, Empty, Field, Loading, Modal, PageHeader, type Tone, useToast } from '../ui';
import { ExportButton } from '../ui/ExportButton';

const KINDS = ['Laptop', 'Desktop computer', 'Phone', 'Tablet', 'USB drive', 'Hard disk', 'SSD', 'Memory card', 'Optical disc', 'Paper documents', 'Other'];
const STATUS: Record<string, { label: string; tone: Tone }> = {
  IN_STORAGE: { label: 'In storage', tone: 'ok' }, CHECKED_OUT: { label: 'Checked out', tone: 'warn' },
  RELEASED: { label: 'Released', tone: 'neutral' }, DESTROYED: { label: 'Destroyed', tone: 'neutral' },
};
const ACTION_LABEL: Record<string, string> = {
  RECEIVED: 'Received into storage', CHECK_OUT: 'Checked out', CHECK_IN: 'Checked in', TRANSFER: 'Moved', RELEASE: 'Released', DESTROY: 'Destroyed',
};
type Action = 'CHECK_OUT' | 'CHECK_IN' | 'TRANSFER' | 'RELEASE' | 'DESTROY';

interface Item {
  item_id: string; case_id: string; description: string; kind: string; make?: string; model?: string; serial_number?: string; bag_number?: string;
  seal_number?: string; seized_at?: string; seized_from?: string; seized_by?: string; location: string; notes?: string; evidence_ids: string[];
  status: string; holder?: { person: string; since: string; purpose: string } | null;
  photos: { photo_id: string; sha256: string; caption: string; name: string; added_by_name: string; added_at: string }[];
  custody: { action: string; at: string; by_name: string; person?: string; location?: string; purpose?: string; seal_intact?: boolean; seal_number?: string; notes?: string }[];
}

export function PhysicalPage() {
  const { caseId, overview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const path = `/physical?case_id=${encodeURIComponent(caseId)}`;
  const list = useApi<{ data: Item[] }>(path);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Item | null>(null);
  const [openId, setOpenId] = useState<string | null>(null);
  const items = list.data?.data ?? [];
  const current = items.find((i) => i.item_id === openId) ?? null;
  return (
    <div className="stack">
      <PageHeader title="Physical evidence"
        subtitle="The devices and media seized for the case: bag and seal numbers, where each is kept, photos, and every hand-over, with a custody form to print for signatures."
        actions={can('EVIDENCE_UPLOAD') && <Button variant="primary" icon={<Plus size={15} />} onClick={() => setAdding(true)}>Add item</Button>} />
      {list.loading && !list.data ? <Loading /> : !items.length ? (
        <Card><Empty icon={<Archive size={20} />} title="No physical evidence recorded" text="Record each item as it is booked in: what it is, its bag and seal numbers and where it is stored." /></Card>
      ) : (
        <Card flush actions={can('REPORT_EXPORT') && <ExportButton path={path} what="list of items" />}>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Item</th><th>Description</th><th>Bag / seal</th><th>Status</th><th>Kept at / held by</th><th>Images made</th><th /></tr></thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.item_id}>
                    <td className="mono small strong">{i.item_id}</td>
                    <td className="small break">{i.description}<div className="tiny muted">{[i.kind, i.make, i.model, i.serial_number && `serial ${i.serial_number}`].filter(Boolean).join(' · ')}</div></td>
                    <td className="small mono">{i.bag_number || '—'} / {i.seal_number || '—'}</td>
                    <td><Badge tone={STATUS[i.status]?.tone ?? 'neutral'}>{STATUS[i.status]?.label ?? i.status}</Badge></td>
                    <td className="small">{i.holder ? <>with <b>{i.holder.person}</b><div className="tiny muted">{i.holder.purpose}</div></> : i.location}</td>
                    <td className="small">{i.evidence_ids.join(', ') || '—'}</td>
                    <td className="nowrap right"><Button size="sm" onClick={() => setOpenId(i.item_id)}>Open</Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      {adding && <ItemForm caseId={caseId} evidence={overview?.evidence ?? []} onClose={() => setAdding(false)} onDone={(id) => { setAdding(false); list.reload(); setOpenId(id); toast(`${id} recorded`, 'ok'); }} />}
      {editing && <ItemForm caseId={caseId} evidence={overview?.evidence ?? []} item={editing} onClose={() => setEditing(null)} onDone={(id) => { setEditing(null); list.reload(); toast(`${id} updated`, 'ok'); }} />}
      {current && !editing && <ItemDetail item={current} onClose={() => setOpenId(null)} onChanged={() => list.reload()} onEdit={() => setEditing(current)} />}
    </div>
  );
}

/** Books an item in, or (with `item`) corrects its details. Where it is kept and its seal change only through custody
 * actions (check in, move…), so they are not edited here. */
function ItemForm({ caseId, evidence, item, onClose, onDone }: { caseId: string; evidence: { evidence_id: string; filename: string }[]; item?: Item; onClose: () => void; onDone: (id: string) => void }) {
  const [f, setF] = useState<Record<string, string>>((): Record<string, string> => item ? {
    description: item.description, kind: item.kind, make: item.make ?? '', model: item.model ?? '', serial_number: item.serial_number ?? '',
    bag_number: item.bag_number ?? '', seized_at: item.seized_at ? isoToLocalInput(item.seized_at, 'local') : '', seized_from: item.seized_from ?? '',
    seized_by: item.seized_by ?? '', notes: item.notes ?? '',
  } : { kind: 'Laptop' });
  const [linked, setLinked] = useState<string[]>(item?.evidence_ids ?? []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  async function save() {
    setBusy(true); setError('');
    const body = { ...f, seized_at: f.seized_at ? new Date(f.seized_at).toISOString() : null, evidence_ids: linked };
    try {
      const r = item ? await patch<Item>(`/physical/${encodeURIComponent(item.item_id)}`, body) : await post<Item>('/physical', { case_id: caseId, ...body });
      onDone(r.item_id);
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }
  return (
    <Modal open title={item ? `Edit ${item.item_id}` : 'Add physical evidence'} onClose={onClose} wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={busy} disabled={(f.description ?? '').trim().length < 2 || (!item && (f.location ?? '').trim().length < 2)} onClick={save}>{item ? 'Save changes' : 'Book in'}</Button></>}>
      {item && <Banner tone="info">Where the item is kept and its seal number change through Check in, Check out and Move, so they stay in the custody log.</Banner>}
      <div className="grid cols-2">
        <Field label="Description"><input className="input" value={f.description ?? ''} onChange={set('description')} autoFocus placeholder="e.g. Dell Latitude laptop, grey" /></Field>
        <Field label="Kind"><select className="select" value={f.kind} onChange={set('kind')}>{KINDS.map((k) => <option key={k}>{k}</option>)}</select></Field>
        <Field label="Make"><input className="input" value={f.make ?? ''} onChange={set('make')} /></Field>
        <Field label="Model"><input className="input" value={f.model ?? ''} onChange={set('model')} /></Field>
        <Field label="Serial number"><input className="input" value={f.serial_number ?? ''} onChange={set('serial_number')} /></Field>
        <Field label="Bag number"><input className="input" value={f.bag_number ?? ''} onChange={set('bag_number')} /></Field>
        {!item && <Field label="Seal number"><input className="input" value={f.seal_number ?? ''} onChange={set('seal_number')} /></Field>}
        {!item && <Field label="Stored at" hint="Where the item is kept now, e.g. Evidence room A, shelf 3"><input className="input" value={f.location ?? ''} onChange={set('location')} /></Field>}
        <Field label="Seized (date and time)"><input className="input" type="datetime-local" value={f.seized_at ?? ''} onChange={set('seized_at')} /></Field>
        <Field label="Seized from"><input className="input" value={f.seized_from ?? ''} onChange={set('seized_from')} placeholder="Place or person" /></Field>
        <Field label="Seized by"><input className="input" value={f.seized_by ?? ''} onChange={set('seized_by')} /></Field>
        <Field label="Notes"><textarea className="textarea" rows={2} value={f.notes ?? ''} onChange={set('notes')} /></Field>
      </div>
      {!!evidence.length && (
        <fieldset className="field" style={{ border: 'none', padding: 0, margin: 0 }}>
          <legend className="small strong" style={{ marginBottom: 6 }}>Disk images made from it</legend>
          <div className="row">{evidence.map((e) => (
            <label key={e.evidence_id} className="check"><input type="checkbox" checked={linked.includes(e.evidence_id)}
              onChange={(ev) => setLinked(ev.target.checked ? [...linked, e.evidence_id] : linked.filter((x) => x !== e.evidence_id))} />{e.evidence_id} <span className="muted">{e.filename}</span></label>
          ))}</div>
        </fieldset>
      )}
      {error && <Banner tone="danger">{error}</Banner>}
    </Modal>
  );
}

function Photo({ itemId, photoId, alt }: { itemId: string; photoId: string; alt: string }) {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    let u: string | null = null;
    fetchBlob(`/physical/${encodeURIComponent(itemId)}/photos/${photoId}`).then((b) => { u = URL.createObjectURL(b); setUrl(u); }).catch(() => setUrl(null));
    return () => { if (u) URL.revokeObjectURL(u); };
  }, [itemId, photoId]);
  return url ? <img src={url} alt={alt} /> : <div className="media-box" style={{ height: 110 }}>…</div>;
}

function ItemDetail({ item, onClose, onChanged, onEdit }: { item: Item; onClose: () => void; onChanged: () => void; onEdit: () => void }) {
  const { can } = useAuth();
  const time = useTime();
  const toast = useToast();
  const [action, setAction] = useState<Action | null>(null);
  const [form, setForm] = useState<Record<string, string>>({});
  const [sealIntact, setSealIntact] = useState<'' | 'yes' | 'no'>('');
  const [removing, setRemoving] = useState<Item['photos'][number] | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function removePhoto() {
    if (!removing) return;
    setBusy(true); setError('');
    try {
      await del(`/physical/${encodeURIComponent(item.item_id)}/photos/${removing.photo_id}`, { reason: reason.trim() });
      toast(`Photo removed from ${item.item_id}`, 'ok');
      setRemoving(null); setReason('');
      onChanged();
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }
  const edit = can('EVIDENCE_UPLOAD');
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setForm({ ...form, [k]: e.target.value });
  async function act() {
    if (!action) return;
    setBusy(true); setError('');
    try {
      await post(`/physical/${encodeURIComponent(item.item_id)}/custody`, { action, ...form, seal_intact: sealIntact === '' ? null : sealIntact === 'yes' });
      toast(`${item.item_id}: ${ACTION_LABEL[action].toLowerCase()}`, 'ok');
      setAction(null); setForm({}); setSealIntact('');
      onChanged();
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }
  async function upload(file: File) {
    setError('');
    const fd = new FormData();
    fd.append('file', file);
    fd.append('caption', file.name);
    try { await api(`/physical/${encodeURIComponent(item.item_id)}/photos`, { method: 'POST', body: fd }); onChanged(); } catch (e: any) { setError(e.message); }
  }
  const can_ = (a: Action) => edit && ({ CHECK_OUT: item.status === 'IN_STORAGE', CHECK_IN: item.status === 'CHECKED_OUT', TRANSFER: item.status === 'IN_STORAGE',
    RELEASE: item.status === 'IN_STORAGE', DESTROY: item.status === 'IN_STORAGE' } as Record<Action, boolean>)[a];
  const need: Record<Action, string[]> = { CHECK_OUT: ['person', 'purpose'], CHECK_IN: ['location'], TRANSFER: ['location'], RELEASE: ['person'], DESTROY: ['notes'] };
  const ready = action && need[action].every((k) => (form[k] ?? '').trim()) && (action !== 'CHECK_IN' || sealIntact !== '');
  return (
    <Modal open wide title={`${item.item_id} · ${item.description}`} onClose={onClose}
      footer={<Button icon={<Printer size={14} />} onClick={() => downloadFile(`/physical/${encodeURIComponent(item.item_id)}/form`, `${item.item_id}-custody.pdf`).catch((e) => setError(e.message))}>Print custody form</Button>}>
      <div className="row" style={{ flexWrap: 'wrap', gap: 6 }}>
        <Badge tone={STATUS[item.status]?.tone ?? 'neutral'}>{STATUS[item.status]?.label ?? item.status}</Badge>
        <span className="small">{item.holder ? <>With <b>{item.holder.person}</b> since {time(item.holder.since)} ({item.holder.purpose})</> : <>Kept at <b>{item.location}</b></>}</span>
      </div>
      <dl className="kv small" style={{ marginTop: 10 }}>
        {[['Kind', item.kind], ['Make and model', [item.make, item.model].filter(Boolean).join(' ')], ['Serial number', item.serial_number], ['Bag number', item.bag_number],
          ['Seal number', item.seal_number], ['Seized', [item.seized_at && time(item.seized_at), item.seized_from, item.seized_by && `by ${item.seized_by}`].filter(Boolean).join(' · ')],
          ['Images made', item.evidence_ids.join(', ')], ['Notes', item.notes]].map(([k, v]) => <Fragment key={k as string}><dt>{k}</dt><dd>{v || '—'}</dd></Fragment>)}
      </dl>
      {edit && (
        <div className="row" style={{ flexWrap: 'wrap', marginTop: 10 }}>
          <Button size="sm" variant="ghost" icon={<Pencil size={13} />} onClick={onEdit}>Edit details</Button>
          {can_('CHECK_OUT') && <Button size="sm" icon={<LogOut size={13} />} onClick={() => setAction('CHECK_OUT')}>Check out</Button>}
          {can_('CHECK_IN') && <Button size="sm" variant="primary" icon={<LogIn size={13} />} onClick={() => setAction('CHECK_IN')}>Check in</Button>}
          {can_('TRANSFER') && <Button size="sm" icon={<MoveRight size={13} />} onClick={() => setAction('TRANSFER')}>Move</Button>}
          {can_('RELEASE') && <Button size="sm" icon={<PackageCheck size={13} />} onClick={() => setAction('RELEASE')}>Release</Button>}
          {can_('DESTROY') && <Button size="sm" variant="ghost" icon={<Trash2 size={13} />} onClick={() => setAction('DESTROY')}>Destroy</Button>}
        </div>
      )}
      {action && (
        <Card title={ACTION_LABEL[action]}>
          <div className="grid cols-2">
            {(action === 'CHECK_OUT' || action === 'RELEASE') && <Field label={action === 'RELEASE' ? 'Released to' : 'Taken by'}><input className="input" value={form.person ?? ''} onChange={set('person')} autoFocus /></Field>}
            {action === 'CHECK_OUT' && <Field label="Purpose"><input className="input" value={form.purpose ?? ''} onChange={set('purpose')} placeholder="e.g. imaging in the lab" /></Field>}
            {(action === 'CHECK_IN' || action === 'TRANSFER') && <Field label="Stored at"><input className="input" value={form.location ?? ''} onChange={set('location')} autoFocus /></Field>}
            {action === 'CHECK_IN' && (
              <Field label="Seal when it came back">
                <select className="select" value={sealIntact} onChange={(e) => setSealIntact(e.target.value as any)} aria-label="Seal when it came back">
                  <option value="">Choose…</option><option value="yes">Intact</option><option value="no">Broken</option>
                </select>
              </Field>
            )}
            {(action === 'CHECK_IN' || action === 'CHECK_OUT') && <Field label="New seal number (if resealed)"><input className="input" value={form.seal_number ?? ''} onChange={set('seal_number')} /></Field>}
            <Field label={action === 'DESTROY' ? 'How it was destroyed, and the authority' : 'Notes'}><textarea className="textarea" rows={2} value={form.notes ?? ''} onChange={set('notes')} /></Field>
          </div>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button onClick={() => { setAction(null); setForm({}); }}>Cancel</Button>
            <Button variant="primary" busy={busy} disabled={!ready} onClick={act}>Record</Button>
          </div>
        </Card>
      )}
      <h4 style={{ margin: '14px 0 6px' }}>Photos</h4>
      <div className="photo-strip">
        {item.photos.map((p) => <figure key={p.photo_id}><Photo itemId={item.item_id} photoId={p.photo_id} alt={p.caption || p.name} />
          <figcaption className="tiny muted">{p.caption || p.name}<br />{p.added_by_name} · {time(p.added_at)}
            {edit && <><br /><button type="button" className="link-btn" onClick={() => { setRemoving(p); setReason(''); }}>Remove</button></>}</figcaption></figure>)}
        {!item.photos.length && <span className="small muted">No photos yet.</span>}
      </div>
      {removing && (
        <Card title={`Remove the photo ${removing.caption || removing.name}`}>
          <Field label="Reason" hint="At least 5 characters; kept in the audit log. Not possible while the case is under legal hold.">
            <input className="input" value={reason} onChange={(e) => setReason(e.target.value)} autoFocus placeholder="e.g. Photo of the wrong item" />
          </Field>
          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button onClick={() => setRemoving(null)}>Cancel</Button>
            <Button variant="danger" icon={<X size={13} />} busy={busy} disabled={reason.trim().length < 5} onClick={removePhoto}>Remove photo</Button>
          </div>
        </Card>
      )}
      {edit && (
        <label className="btn sm" style={{ marginTop: 8, display: 'inline-flex', gap: 6, alignItems: 'center', cursor: 'pointer' }}>
          <Camera size={13} /> Add photo<input type="file" accept="image/jpeg,image/png" hidden aria-label="Add photo" onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = ''; }} />
        </label>
      )}
      <h4 style={{ margin: '14px 0 6px' }}>Custody</h4>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Time</th><th>Action</th><th>Recorded by</th><th>Details</th></tr></thead>
          <tbody>
            {item.custody.map((c, i) => (
              <tr key={i}>
                <td className="small nowrap">{time(c.at)}</td>
                <td className="small">{ACTION_LABEL[c.action] ?? c.action}{c.seal_intact === false && <div><Badge tone="danger">seal broken</Badge></div>}</td>
                <td className="small">{c.by_name}</td>
                <td className="small break">{[c.person && (c.action === 'RELEASE' ? `to ${c.person}` : c.person), c.location && `kept at ${c.location}`, c.purpose,
                  c.seal_intact === true && 'seal intact', c.seal_number && `seal ${c.seal_number}`, c.notes].filter(Boolean).join(' · ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {error && <Banner tone="danger">{error}</Banner>}
    </Modal>
  );
}

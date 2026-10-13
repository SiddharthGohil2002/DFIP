import { useMemo, useRef, useState } from 'react';
import { MessageSquare } from 'lucide-react';
import { del, patch, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { Banner, Button } from './index';

export interface Person { user_id: string; name: string; email: string; role: string; can_review: boolean }
interface Comment {
  _id: string; author_id: string; author_name: string; text: string; created_at: string; edited_at?: string;
  deleted?: boolean; deleted_by_name?: string;
}

/** The people who can see a case (they can be mentioned, and asked to review findings). */
export function usePeople(caseId: string) {
  return useApi<{ data: Person[] }>(caseId ? `/cases/${encodeURIComponent(caseId)}/people` : null);
}

const MENTION = /(^|[^\w.@])@([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g;

function Text({ text, people }: { text: string; people: Person[] }) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(MENTION)) {
    const at = (m.index ?? 0) + m[1].length;
    parts.push(text.slice(last, at));
    const who = people.find((p) => p.email.toLowerCase() === m[2].toLowerCase());
    parts.push(<span key={at} className="mention" title={m[2]}>@{who?.name ?? m[2]}</span>);
    last = at + m[2].length + 1;
  }
  parts.push(text.slice(last));
  return <span style={{ whiteSpace: 'pre-wrap' }}>{parts}</span>;
}

/** A comment box that offers the case's people after "@" and inserts their email address (how mentions are written). */
function Composer({ people, value, onChange, onSubmit, busy, label }: {
  people: Person[]; value: string; onChange: (v: string) => void; onSubmit: () => void; busy: boolean; label: string;
}) {
  const ref = useRef<HTMLTextAreaElement>(null);
  const [cursor, setCursor] = useState(0);
  const query = useMemo(() => {
    const m = /(^|[\s(])@([^\s@]*)$/.exec(value.slice(0, cursor));
    return m ? m[2].toLowerCase() : null;
  }, [value, cursor]);
  const matches = query === null ? [] : people.filter((p) => p.name.toLowerCase().includes(query) || p.email.toLowerCase().includes(query)).slice(0, 6);
  function pick(p: Person) {
    const before = value.slice(0, cursor).replace(/@([^\s@]*)$/, `@${p.email} `);
    const next = before + value.slice(cursor);
    onChange(next);
    setCursor(before.length);
    requestAnimationFrame(() => { ref.current?.focus(); ref.current?.setSelectionRange(before.length, before.length); });
  }
  return (
    <div style={{ position: 'relative' }}>
      <textarea ref={ref} className="textarea" rows={2} value={value} aria-label={label} placeholder="Write a comment; type @ to mention someone on the case"
        onChange={(e) => { onChange(e.target.value); setCursor(e.target.selectionStart ?? 0); }}
        onKeyUp={(e) => setCursor((e.target as HTMLTextAreaElement).selectionStart ?? 0)}
        onClick={(e) => setCursor((e.target as HTMLTextAreaElement).selectionStart ?? 0)}
        onKeyDown={(e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && value.trim()) onSubmit(); }} />
      {matches.length > 0 && (
        <div className="mention-menu" role="listbox" aria-label="People on the case">
          {matches.map((p) => (
            <button key={p.user_id} type="button" role="option" aria-selected={false} className="mention-option" onMouseDown={(e) => { e.preventDefault(); pick(p); }}>
              <span className="strong">{p.name}</span> <span className="tiny muted">{p.email} · {p.role.toLowerCase()}</span>
            </button>
          ))}
        </div>
      )}
      <div className="row" style={{ justifyContent: 'flex-end', marginTop: 6 }}>
        <Button size="sm" variant="primary" busy={busy} disabled={!value.trim()} onClick={onSubmit}>Comment</Button>
      </div>
    </div>
  );
}

export function Comments({ caseId, targetType, targetId, title = 'Comments' }: {
  caseId: string; targetType: 'FINDING' | 'TAG' | 'FILE' | 'EVIDENCE'; targetId: string; title?: string;
}) {
  const { user, can } = useAuth();
  const time = useTime();
  const list = useApi<{ data: Comment[] }>(`/comments?case_id=${encodeURIComponent(caseId)}&target_type=${targetType}&target_id=${encodeURIComponent(targetId)}`);
  const people = usePeople(caseId).data?.data ?? [];
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState('');

  async function add() {
    setBusy(true); setError(''); setNote('');
    try {
      const r = await post<{ not_notified: string[]; mentioned: { name: string }[] }>('/comments', { case_id: caseId, target_type: targetType, target_id: targetId, text: text.trim() });
      setText('');
      if (r.not_notified.length) setNote(`Not notified (they cannot see this case): ${r.not_notified.join(', ')}`);
      else if (r.mentioned.length) setNote(`Notified: ${r.mentioned.map((m) => m.name).join(', ')}`);
      list.reload();
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }
  async function save(id: string) {
    setBusy(true); setError('');
    try { await patch(`/comments/${id}`, { text: draft.trim() }); setEditing(null); list.reload(); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }
  async function remove(id: string) {
    setError('');
    try { await del(`/comments/${id}`); list.reload(); } catch (e: any) { setError(e.message); }
  }
  const rows = list.data?.data ?? [];
  return (
    <div className="comments" aria-label={title}>
      <div className="small strong row" style={{ gap: 6, marginBottom: 6 }}><MessageSquare size={14} /> {title} {rows.length > 0 && <span className="muted">({rows.filter((c) => !c.deleted).length})</span>}</div>
      {rows.map((c) => (
        <div key={c._id} className="comment">
          {c.deleted ? (
            <span className="tiny muted">Comment deleted{c.deleted_by_name ? ` by ${c.deleted_by_name}` : ''}.</span>
          ) : editing === c._id ? (
            <div>
              <textarea className="textarea" rows={2} value={draft} onChange={(e) => setDraft(e.target.value)} aria-label="Edit comment" />
              <div className="row" style={{ justifyContent: 'flex-end', marginTop: 4 }}>
                <Button size="sm" onClick={() => setEditing(null)}>Cancel</Button>
                <Button size="sm" variant="primary" busy={busy} disabled={!draft.trim()} onClick={() => save(c._id)}>Save</Button>
              </div>
            </div>
          ) : (
            <>
              <div className="tiny muted">{c.author_name} · {time(c.created_at)}{c.edited_at ? ' · edited' : ''}
                {user && can('FINDING_CREATE') && (c.author_id === user._id || user.role === 'ADMIN') && (
                  <span style={{ marginLeft: 8 }}>
                    {c.author_id === user._id && <button className="link-btn" onClick={() => { setEditing(c._id); setDraft(c.text); }}>Edit</button>}{' '}
                    <button className="link-btn" onClick={() => remove(c._id)}>Delete</button>
                  </span>
                )}
              </div>
              <div className="small"><Text text={c.text} people={people} /></div>
            </>
          )}
        </div>
      ))}
      {can('FINDING_CREATE') && <Composer people={people} value={text} onChange={setText} onSubmit={add} busy={busy} label={`Add a comment to ${title.toLowerCase()}`} />}
      {note && <div className="tiny muted" role="status">{note}</div>}
      {error && <Banner tone="danger">{error}</Banner>}
    </div>
  );
}

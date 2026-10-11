import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Bookmark, BookmarkCheck, Trash2 } from 'lucide-react';
import { api, del, patch, post } from './api';
import { useAuth } from './auth';
import { useCase } from './caseContext';
import { Banner, Button, Field, Modal, useToast } from '../ui';

export type TagItemType = 'FILE' | 'TIMELINE_EVENT' | 'BROWSER' | 'USB' | 'ACTIVITY' | 'ARTIFACT' | 'ENTITY';
export type TagLabel = 'EVIDENCE' | 'NOTABLE' | 'FOLLOW_UP';

export interface Tag {
  _id: string;
  tag_id: string;
  case_id: string;
  evidence_id?: string;
  item_type: TagItemType;
  item_id: string;
  label: TagLabel;
  note: string;
  snapshot: { title?: string; detail?: string; timestamp?: string; source?: string };
  created_by_name?: string;
  created_at: string;
  updated_at?: string;
  resolved?: boolean;
}

export const TAG_LABELS: Record<TagLabel, string> = { EVIDENCE: 'Evidence', NOTABLE: 'Notable', FOLLOW_UP: 'Follow up' };
export const TAG_TONES: Record<TagLabel, 'danger' | 'accent' | 'warn'> = { EVIDENCE: 'danger', NOTABLE: 'accent', FOLLOW_UP: 'warn' };
const TAG_COLORS: Record<TagLabel, string> = { EVIDENCE: 'var(--danger)', NOTABLE: 'var(--accent)', FOLLOW_UP: 'var(--warn)' };

interface TagsState {
  tags: Tag[];
  find: (type: TagItemType, id: string) => Tag | undefined;
  open: (type: TagItemType, id: string, title?: string) => void;
  reload: () => void;
}

const TagsContext = createContext<TagsState | null>(null);

/** The active case's tags, and the dialog that adds, edits or removes one. */
export function TagsProvider({ children }: { children: ReactNode }) {
  const { caseId, reloadOverview } = useCase();
  const [tags, setTags] = useState<Tag[]>([]);
  const [editing, setEditing] = useState<{ type: TagItemType; id: string; title?: string } | null>(null);

  const reload = useCallback(() => {
    if (!caseId) {
      setTags([]);
      return;
    }
    api<{ data: Tag[] }>(`/tags?case_id=${encodeURIComponent(caseId)}`).then((r) => setTags(r.data)).catch(() => setTags([]));
  }, [caseId]);
  useEffect(() => reload(), [reload]);

  const byItem = useMemo(() => new Map(tags.map((t) => [`${t.item_type}:${t.item_id}`, t])), [tags]);
  const value = useMemo<TagsState>(() => ({
    tags,
    find: (type, id) => byItem.get(`${type}:${id}`),
    open: (type, id, title) => setEditing({ type, id, title }),
    reload,
  }), [tags, byItem, reload]);

  return (
    <TagsContext.Provider value={value}>
      {children}
      {editing && (
        <TagModal
          item={editing}
          existing={byItem.get(`${editing.type}:${editing.id}`)}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            reload();
            reloadOverview();
          }}
        />
      )}
    </TagsContext.Provider>
  );
}

export function useTags() {
  const ctx = useContext(TagsContext);
  if (!ctx) throw new Error('useTags must be used inside TagsProvider');
  return ctx;
}

/** Bookmark icon for one item: outlined when untagged, filled in the label's colour when tagged. */
export function TagButton({ type, id, title }: { type: TagItemType; id?: string | null; title?: string }) {
  const { can } = useAuth();
  const { find, open } = useTags();
  if (!id) return null;
  const tag = find(type, id);
  const canTag = can('FINDING_CREATE');
  if (!tag && !canTag) return null;
  const label = tag ? `Tagged ${TAG_LABELS[tag.label]}${tag.note ? `: ${tag.note}` : ''}` : 'Tag this item';
  return (
    <button
      type="button"
      className="btn ghost icon-btn tag-btn"
      title={label}
      aria-label={label}
      disabled={!canTag}
      onClick={() => open(type, id, title)}
    >
      {tag ? <BookmarkCheck size={16} color={TAG_COLORS[tag.label]} fill={TAG_COLORS[tag.label]} fillOpacity={0.15} /> : <Bookmark size={16} />}
    </button>
  );
}

function TagModal({ item, existing, onClose, onSaved }: {
  item: { type: TagItemType; id: string; title?: string };
  existing?: Tag;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { caseId } = useCase();
  const toast = useToast();
  const [label, setLabel] = useState<TagLabel>(existing?.label || 'EVIDENCE');
  const [note, setNote] = useState(existing?.note || '');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  async function save() {
    setBusy('save');
    setError('');
    try {
      if (existing) await patch(`/tags/${encodeURIComponent(existing.tag_id)}`, { label, note });
      else await post('/tags', { case_id: caseId, item_type: item.type, item_id: item.id, label, note });
      toast(existing ? 'Tag updated' : `Tagged as ${TAG_LABELS[label]}`, 'ok');
      onSaved();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy('');
    }
  }

  async function remove() {
    if (!existing) return;
    setBusy('remove');
    try {
      await del(`/tags/${encodeURIComponent(existing.tag_id)}`);
      toast('Tag removed', 'ok');
      onSaved();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy('');
    }
  }

  const title = existing?.snapshot.title || item.title;
  return (
    <Modal
      open
      title={existing ? `Tag ${existing.tag_id}` : 'Tag this item'}
      onClose={onClose}
      footer={
        <>
          {existing && <Button variant="danger" icon={<Trash2 size={14} />} busy={busy === 'remove'} disabled={!!busy} onClick={remove} style={{ marginRight: 'auto' }}>Remove tag</Button>}
          <Button variant="ghost" onClick={onClose} disabled={!!busy}>Cancel</Button>
          <Button variant="primary" busy={busy === 'save'} disabled={!!busy} onClick={save}>{existing ? 'Save' : 'Add tag'}</Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 12 }}>
        {title && <div className="mono small strong break">{title}</div>}
        <div className="field">
          <span className="small strong">Label</span>
          <div className="row" role="radiogroup" aria-label="Label">
            {(Object.keys(TAG_LABELS) as TagLabel[]).map((l) => (
              <label key={l} className="check">
                <input type="radio" name="tag-label" checked={label === l} onChange={() => setLabel(l)} /> {TAG_LABELS[l]}
              </label>
            ))}
          </div>
        </div>
        <Field label="Note" hint="Shown on Tagged items and in the case report.">
          <textarea className="textarea" value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} placeholder="Why this item matters" />
        </Field>
        {error && <Banner tone="danger">{error}</Banner>}
      </div>
    </Modal>
  );
}

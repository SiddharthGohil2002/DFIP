import { useEffect, useState } from 'react';
import { FolderInput, Trash2, Upload } from 'lucide-react';
import { useAuth } from '../../lib/auth';
import { api, del, post } from '../../lib/api';
import { formatBytes, formatNumber, useTime } from '../../lib/format';
import { useApi } from '../../lib/useApi';
import type { HashKind, HashSet } from '../../lib/types';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Field, Hash, Loading, Modal, PageHeader, StatusBadge, useToast } from '../../ui';
import { ExportButton } from '../../ui/ExportButton';
import { HASH_KIND } from '../Files';

const KIND_NOTES: Record<HashKind, string> = {
  KNOWN_GOOD: 'Operating system and program files (for example the NIST NSRL). Hidden from the Files page by default.',
  KNOWN_BAD: 'Malware and other files that must not be there. A match raises an indicator and notifies the investigator.',
  NOTABLE: 'Files of interest to the investigation (for example a leaked document). A match raises an indicator.',
};

interface Draft { name: string; kind: HashKind; description: string }

export function HashSetsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const manage = can('HASHSET_MANAGE');
  const [poll, setPoll] = useState(false);
  const path = '/hashsets';
  const incomingPath = manage ? '/hashsets/incoming' : null;
  const list = useApi<{ data: HashSet[] }>(path, { pollMs: poll ? 2000 : undefined });
  const incoming = useApi<{ data: { filename: string; size: number }[] }>(incomingPath);
  const [dialog, setDialog] = useState<null | { mode: 'upload' } | { mode: 'local'; filename: string }>(null);
  const [draft, setDraft] = useState<Draft>({ name: '', kind: 'KNOWN_BAD', description: '' });
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [remove, setRemove] = useState<HashSet | null>(null);

  const sets = list.data?.data || [];
  const importing = sets.some((s) => s.status === 'IMPORTING');
  useEffect(() => setPoll(importing), [importing]);  // refresh every 2 s while a set is importing

  function open(next: NonNullable<typeof dialog>) {
    setDraft({ name: next.mode === 'local' ? next.filename.replace(/\.[^.]+$/, '') : '', kind: next.mode === 'local' ? 'KNOWN_GOOD' : 'KNOWN_BAD', description: '' });
    setFile(null);
    setError('');
    setDialog(next);
  }

  async function submit() {
    if (!dialog) return;
    setBusy('import');
    setError('');
    try {
      if (dialog.mode === 'upload') {
        if (!file) throw new Error('Choose a file to import');
        const form = new FormData();
        form.append('name', draft.name);
        form.append('kind', draft.kind);
        if (draft.description) form.append('description', draft.description);
        form.append('file', file);
        await api('/hashsets', { method: 'POST', body: form });
      } else {
        await post('/hashsets/import-local', { filename: dialog.filename, ...draft, description: draft.description || null });
      }
      toast(`Importing ${draft.name}: every analysed evidence item is re-matched when it is ready`, 'ok');
      setDialog(null);
      list.reload();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy('');
    }
  }

  async function confirmDelete() {
    if (!remove) return;
    setBusy('delete');
    try {
      const r = await del<{ rematch_jobs: string[] }>(`/hashsets/${remove.set_id}`);
      toast(`${remove.name} deleted; ${r.rematch_jobs.length} evidence item(s) are being re-matched`, 'ok');
      setRemove(null);
      list.reload();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Hash sets"
        subtitle="Lists of known file hashes that every evidence file is compared with: known good (hidden by default), known bad and notable. Importing or deleting a set re-matches every analysed evidence item."
        actions={manage && <Button variant="primary" icon={<Upload size={15} />} onClick={() => open({ mode: 'upload' })}>Import a hash set</Button>}
      />
      {!manage && <Banner tone="info">Only administrators can import or delete hash sets.</Banner>}
      <ErrorBanner error={list.error} />
      <Card title="Imported sets" flush actions={sets.length > 0 && <ExportButton path={path} what="list of hash sets" />}>
        {list.loading && !list.data ? <Loading /> : !sets.length ? (
          <Empty title="No hash sets" text="Import a plain list of MD5, SHA-1 or SHA-256 hashes (one per line, sha256sum output works), a CSV with md5/sha1/sha256 columns, or the NSRL RDS v3 SQLite database." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Set</th><th>Kind</th><th>Status</th><th className="right">Hashes</th><th>Source</th><th>Imported</th>{manage && <th />}</tr></thead>
              <tbody>
                {sets.map((s) => (
                  <tr key={s.set_id}>
                    <td><div className="strong">{s.name}</div><div className="tiny muted">{s.set_id}{s.description ? ` · ${s.description}` : ''}</div></td>
                    <td><Badge tone={HASH_KIND[s.kind].tone}>{HASH_KIND[s.kind].label}</Badge></td>
                    <td>
                      <StatusBadge status={s.status} />
                      {s.error && <div className="tiny" style={{ color: 'var(--danger)' }}>{s.error}</div>}
                    </td>
                    <td className="right small">
                      {s.count !== undefined ? formatNumber(s.count) : '—'}
                      {s.counts && <div className="tiny muted">{Object.entries(s.counts).filter(([, n]) => n).map(([a, n]) => `${formatNumber(n)} ${a.toUpperCase()}`).join(' · ')}</div>}
                      {!!s.invalid_lines && <div className="tiny muted">{formatNumber(s.invalid_lines)} lines skipped</div>}
                    </td>
                    <td className="small">
                      {s.source_filename} <span className="muted">({formatBytes(s.source_size)}{s.format ? `, ${s.format}` : ''})</span>
                      <div><Hash value={s.source_sha256} short={12} /></div>
                    </td>
                    <td className="small nowrap">{time(s.imported_at)}<div className="tiny muted">{s.imported_by_name}</div></td>
                    {manage && (
                      <td className="right">
                        <Button size="sm" variant="ghost" icon={<Trash2 size={13} />} disabled={s.status === 'IMPORTING'} onClick={() => setRemove(s)} aria-label={`Delete ${s.name}`}>Delete</Button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {manage && (
        <Card title="Files on the server" subtitle="Large sets such as the NSRL are copied to storage/hashsets/incoming on the server instead of being uploaded." flush
          actions={!!incoming.data?.data.length && <ExportButton path={incomingPath} what="list of files" />}>
          {incoming.loading && !incoming.data ? <Loading /> : !incoming.data?.data.length ? (
            <Empty title="The folder is empty" />
          ) : (
            <table className="table">
              <thead><tr><th>File</th><th className="right">Size</th><th /></tr></thead>
              <tbody>
                {incoming.data.data.map((f) => (
                  <tr key={f.filename}>
                    <td className="mono small">{f.filename}</td>
                    <td className="right small">{formatBytes(f.size)}</td>
                    <td className="right"><Button size="sm" icon={<FolderInput size={13} />} onClick={() => open({ mode: 'local', filename: f.filename })}>Import</Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}

      <Modal
        open={!!dialog}
        title={dialog?.mode === 'local' ? `Import ${dialog.filename}` : 'Import a hash set'}
        onClose={() => setDialog(null)}
        footer={<>
          <Button variant="ghost" onClick={() => setDialog(null)}>Cancel</Button>
          <Button variant="primary" busy={busy === 'import'} disabled={!draft.name.trim() || (dialog?.mode === 'upload' && !file)} onClick={submit}>Import</Button>
        </>}
      >
        <div className="stack">
          {error && <Banner tone="danger">{error}</Banner>}
          {dialog?.mode === 'upload' && (
            <Field label="File" hint="Plain list, CSV with md5/sha1/sha256 columns, or NSRL RDS v3 SQLite. The file is deleted once its hashes are stored.">
              <input className="input" type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
            </Field>
          )}
          <Field label="Name">
            <input className="input" value={draft.name} maxLength={120} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          </Field>
          <Field label="Kind" hint={KIND_NOTES[draft.kind]}>
            <select className="select" value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value as HashKind })}>
              {(Object.keys(HASH_KIND) as HashKind[]).map((k) => <option key={k} value={k}>{HASH_KIND[k].label}</option>)}
            </select>
          </Field>
          <Field label="Description (optional)">
            <input className="input" value={draft.description} maxLength={1000} onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
          </Field>
        </div>
      </Modal>

      <Modal
        open={!!remove}
        title={`Delete ${remove?.name}?`}
        onClose={() => setRemove(null)}
        footer={<>
          <Button variant="ghost" onClick={() => setRemove(null)}>Cancel</Button>
          <Button variant="danger" busy={busy === 'delete'} onClick={confirmDelete}>Delete set</Button>
        </>}
      >
        <p className="small">Its {formatNumber(remove?.count)} hashes are removed and every analysed evidence item is re-matched without it. The deletion is recorded in the audit log.</p>
      </Modal>
    </div>
  );
}

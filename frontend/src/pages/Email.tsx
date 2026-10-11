import { useEffect, useMemo, useState } from 'react';
import DOMPurify from 'dompurify';
import { Paperclip, Search } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatBytes, shortHash, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import { ViewButton } from '../ui/FileViewer';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Loading, Modal, PageHeader, Pager, Tabs } from '../ui';

const LIMIT = 100;
type Address = { name?: string | null; address?: string | null };
const who = (a?: Address | null) => (a ? (a.name && a.address ? `${a.name} <${a.address}>` : a.address || a.name || '') : '');
const list = (xs?: Address[] | null) => (xs || []).map(who).filter(Boolean).join(', ');

export function EmailPage() {
  const { caseId, overview } = useCase();
  const time = useTime();
  const stores = useApi<{ data: any[] }>(`/forensics/email/stores?case_id=${encodeURIComponent(caseId)}`);
  const [store, setStore] = useState('');
  const [folder, setFolder] = useState('');
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [attachments, setAttachments] = useState(false);
  const [deleted, setDeleted] = useState(false);
  const [direction, setDirection] = useState('');
  const [skip, setSkip] = useState(0);
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => setSkip(0), [store, folder, search, attachments, deleted, direction]);
  useEffect(() => setFolder(''), [store]);

  const params = new URLSearchParams({ case_id: caseId, limit: String(LIMIT), skip: String(skip) });
  if (store) params.set('store', store);
  if (folder) params.set('folder', folder);
  if (search) params.set('search', search);
  if (attachments) params.set('attachments', 'true');
  if (deleted) params.set('deleted', 'true');
  if (direction) params.set('direction', direction);
  const { data, error, loading } = useApi<{ data: any[]; total: number }>(`/forensics/email/messages?${params}`);
  const folders = useMemo(() => {
    const s = (stores.data?.data || []).find((x) => x.path === store);
    return s ? (s.folders || []).map((f: any) => f.name) : [];
  }, [stores.data, store]);
  const c = overview?.counts;

  return (
    <div className="stack">
      <PageHeader
        title="Email"
        subtitle="Messages and attachments from Outlook PST/OST files, MBOX files, Thunderbird profiles and single EML/MSG files. Attachments are hashed and checked like other files (see Files → Archives and attachments)."
      />
      <Card title="Mailboxes" subtitle={c ? `${(c.email_messages ?? 0).toLocaleString()} messages · ${(c.email_attachments ?? 0).toLocaleString()} attachments` : undefined}>
        <ErrorBanner error={stores.error} />
        {stores.loading && !stores.data ? <Loading /> : !stores.data?.data.length ? (
          <Empty title="No mailboxes" text="No Outlook, MBOX, Thunderbird or EML/MSG files were found in the analysed images. Email is read by the Standard and Full analysis profiles (module &quot;Email&quot;)." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Mailbox</th><th>Format</th><th>User</th><th className="right">Messages</th><th className="right">Attachments</th><th className="right">Deleted</th><th>SHA-256</th><th /></tr></thead>
              <tbody>
                {stores.data.data.map((s) => (
                  <tr key={s._id} className={store === s.path ? 'selected' : undefined}>
                    <td className="small"><span className="mono cell-path">{s.path}</span>
                      {!!s.errors?.length && <div className="tiny" style={{ color: 'var(--warn)' }}>{s.errors[0]}</div>}</td>
                    <td><Badge tone="info">{s.client || s.format}</Badge></td>
                    <td className="small">{s.user || '—'}</td>
                    <td className="right mono">{(s.messages ?? 0).toLocaleString()}</td>
                    <td className="right mono">{(s.attachments ?? 0).toLocaleString()}</td>
                    <td className="right mono">{s.deleted_messages ? <Badge tone="warn">{s.deleted_messages}</Badge> : 0}</td>
                    <td className="mono tiny">{shortHash(s.sha256)}</td>
                    <td className="right nowrap">
                      <Button size="sm" variant="ghost" onClick={() => setStore(store === s.path ? '' : s.path)}>{store === s.path ? 'All mailboxes' : 'Show only'}</Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card flush>
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
          <input className="input sm" style={{ maxWidth: 300 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
            placeholder="Search subject, people, attachments, text" aria-label="Search messages" />
          <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Search</Button>
          {store && folders.length > 1 && (
            <select className="select sm" style={{ width: 200 }} value={folder} onChange={(e) => setFolder(e.target.value)} aria-label="Folder">
              <option value="">All folders</option>
              {folders.map((f: string) => <option key={f} value={f}>{f || '/'}</option>)}
            </select>
          )}
          <select className="select sm" style={{ width: 140 }} value={direction} onChange={(e) => setDirection(e.target.value)} aria-label="Direction">
            <option value="">Sent and received</option><option value="sent">Sent</option><option value="received">Received</option>
          </select>
          <label className="check"><input type="checkbox" checked={attachments} onChange={(e) => setAttachments(e.target.checked)} /> With attachments</label>
          <label className="check"><input type="checkbox" checked={deleted} onChange={(e) => setDeleted(e.target.checked)} /> Deleted only</label>
          <span className="small muted">{data ? `${data.total.toLocaleString()} messages` : ''}</span>
        </div>
        <ErrorBanner error={error} />
        {loading && !data ? <Loading /> : !data?.data.length ? <Empty title="No messages" text={search || attachments || deleted || direction ? 'Nothing matches these filters.' : undefined} /> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Time</th><th>From</th><th>To</th><th>Subject</th><th>Folder</th><th /></tr></thead>
              <tbody>
                {data.data.map((m) => (
                  <tr key={m._id}>
                    <td className="mono small nowrap">{time(m.time)}</td>
                    <td className="small">{m.from_name || m.from_address}<div className="tiny muted mono">{m.from_name ? m.from_address : ''}</div></td>
                    <td className="small">{list((m.to || []).slice(0, 3))}{(m.to || []).length > 3 ? ` +${m.to.length - 3}` : ''}</td>
                    <td className="small">
                      <button className="link-button strong" onClick={() => setOpen(m._id)}>{m.subject || '(no subject)'}</button>{' '}
                      {m.deleted && <Badge tone="danger">DELETED</Badge>}{' '}
                      {m.attachment_count > 0 && <Badge tone="accent" title={(m.attachments || []).filter((a: any) => !a.inline).map((a: any) => a.name).join(', ')}><Paperclip size={11} /> {m.attachment_count}</Badge>}
                      <div className="tiny muted">{m.snippet}</div>
                    </td>
                    <td className="small">{m.folder || '/'}<div className="tiny muted">{m.direction}</div></td>
                    <td className="nowrap right"><TagButton type="EMAIL" id={m._id} title={m.subject || '(no subject)'} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && <Pager skip={skip} limit={LIMIT} total={data.total} onChange={setSkip} />}
      </Card>
      {open && <MessageView id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

type View = 'text' | 'html' | 'headers';

function MessageView({ id, onClose }: { id: string; onClose: () => void }) {
  const time = useTime();
  const { data: m, error, loading } = useApi<any>(`/forensics/email/messages/${encodeURIComponent(id)}`);
  const [view, setView] = useState<View>('text');
  const html = useApi<{ html: string; remote_references: number }>(view === 'html' ? `/forensics/email/messages/${encodeURIComponent(id)}/html` : null);
  return (
    <Modal open wide title={m?.subject || 'Message'} onClose={onClose}>
      <ErrorBanner error={error} />
      {loading && !m ? <Loading /> : m && (
        <div className="stack" style={{ gap: 12 }}>
          <dl className="kv">
            <dt>From</dt><dd>{who({ name: m.from_name, address: m.from_address })}</dd>
            <dt>To</dt><dd>{list(m.to) || '—'}</dd>
            {!!m.cc?.length && (<><dt>Cc</dt><dd>{list(m.cc)}</dd></>)}
            {!!m.bcc?.length && (<><dt>Bcc</dt><dd>{list(m.bcc)}</dd></>)}
            <dt>Sent</dt><dd className="mono small">{time(m.sent)}</dd>
            <dt>Received</dt><dd className="mono small">{time(m.received)}</dd>
            <dt>Mailbox</dt><dd className="small"><span className="mono">{m.store_path}</span> · {m.folder || '/'} (message {m.number})</dd>
            {m.message_id && (<><dt>Message-ID</dt><dd className="mono tiny">{m.message_id}</dd></>)}
            {m.originating_ip && (<><dt>Originating IP</dt><dd className="mono small">{m.originating_ip}</dd></>)}
            {!!m.flags?.length && (<><dt>Flags</dt><dd>{m.flags.map((f: string) => <Badge key={f} tone={f === 'deleted' ? 'danger' : 'neutral'}>{f.toUpperCase()}</Badge>)}</dd></>)}
          </dl>
          {m.deleted && <Banner tone="warn">The user deleted this message. Thunderbird keeps deleted messages in the folder file until it is compacted.</Banner>}
          {!!m.attachments?.length && (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Attachment</th><th>Type</th><th className="right">Size</th><th>SHA-256</th><th /></tr></thead>
                <tbody>
                  {m.attachments.map((a: any, i: number) => (
                    <tr key={i}>
                      <td className="small"><span className="mono">{a.name}</span> {a.inline && <Badge>INLINE</Badge>}{a.note && <div className="tiny muted">{a.note}</div>}</td>
                      <td className="small">{a.mime || '—'}</td>
                      <td className="right small nowrap">{a.size != null ? formatBytes(a.size) : '—'}</td>
                      <td className="mono tiny">{shortHash(a.sha256)}</td>
                      <td className="right nowrap">{a.entry_id && <ViewButton source={{ kind: 'member', entryId: a.entry_id, name: a.entry_path }} />}{' '}
                        {a.entry_id && <TagButton type="FILE" id={a.entry_id} title={a.entry_path} />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Tabs<View> value={view} onChange={setView} tabs={[
            { id: 'text', label: 'Text' },
            ...(m.has_html ? [{ id: 'html' as View, label: 'HTML (safe view)' }] : []),
            { id: 'headers', label: 'Headers' },
          ]} />
          {view === 'text' && <pre className="pre viewer-text">{m.body_text || '(no text)'}</pre>}
          {view === 'headers' && <pre className="pre viewer-text">{m.headers || '(no headers kept)'}</pre>}
          {view === 'html' && (
            html.error ? <ErrorBanner error={html.error} /> : !html.data ? <Loading /> : <SafeHtml html={html.data.html} remote={html.data.remote_references} />
          )}
          {m.truncated && <Banner tone="info">The body is longer than DFIP keeps; only its beginning is shown.</Banner>}
        </div>
      )}
    </Modal>
  );
}

/** An email's HTML, sanitised (no scripts, forms or event handlers; links disabled) and shown in a sandbox that runs no scripts
 *  and loads nothing from the network: only pictures sent inside the message (data: URIs) are shown. */
export function SafeHtml({ html, remote }: { html: string; remote: number }) {
  const doc = useMemo(() => {
    const purify = DOMPurify();
    purify.addHook('afterSanitizeAttributes', (node) => {
      if (node.hasAttribute('href')) {
        node.setAttribute('title', `Link (disabled): ${node.getAttribute('href')}`);
        node.removeAttribute('href');
      }
      for (const attr of ['src', 'background', 'srcset']) {
        const v = node.getAttribute(attr);
        if (v && !v.startsWith('data:')) node.removeAttribute(attr);
      }
    });
    const clean = purify.sanitize(html, { FORBID_TAGS: ['form', 'input', 'button', 'textarea', 'select', 'iframe', 'frame', 'object', 'embed', 'base', 'meta', 'link'],
      FORBID_ATTR: ['action', 'formaction', 'ping'] });
    return '<!doctype html><html><head><meta charset="utf-8">'
      + '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; font-src data:">'
      + '<style>body{font-family:system-ui,sans-serif;font-size:14px;color:#1c2430;background:#fff;margin:12px}img{max-width:100%}</style>'
      + `</head><body>${clean}</body></html>`;
  }, [html]);
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="small muted">
        Scripts, forms and links are removed and nothing is loaded from the internet{remote ? ` (${remote} remote picture${remote === 1 ? '' : 's'} or style${remote === 1 ? '' : 's'} not loaded, such as tracking pixels)` : ''}.
      </div>
      <iframe className="email-html" sandbox="" srcDoc={doc} title="Email HTML (safe view)" referrerPolicy="no-referrer" />
    </div>
  );
}

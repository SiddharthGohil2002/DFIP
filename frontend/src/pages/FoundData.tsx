import { Fragment, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Eye, FileSearch, ListTree, Search } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { api, post } from '../lib/api';
import { formatNumber } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import type { FoundKind, FoundValue } from '../lib/types';
import { ViewButton, locate } from '../ui/FileViewer';
import { ExportButton } from '../ui/ExportButton';
import { Badge, Banner, Button, Card, Empty, ErrorBanner, Loading, PageHeader, Tabs, useToast } from '../ui';

const KINDS: { id: FoundKind; label: string; how: string }[] = [
  { id: 'email', label: 'Email', how: 'Email addresses with a valid domain.' },
  { id: 'url', label: 'Web addresses', how: 'http, https and ftp addresses. Values read from the raw strings of a database can run into the next field.' },
  { id: 'ip', label: 'IP addresses', how: 'IPv4 addresses, marked private or public.' },
  { id: 'phone', label: 'Phone numbers', how: 'International numbers written with a leading +, 8 to 15 digits.' },
  { id: 'card', label: 'Card numbers', how: 'Numbers with a known card brand prefix and length that pass the Luhn check. Shown masked.' },
  { id: 'iban', label: 'IBANs', how: 'Bank account numbers of the right length for their country with valid check digits (mod-97).' },
  { id: 'crypto', label: 'Crypto addresses', how: 'Bitcoin (Base58Check, Bech32) and Ethereum (EIP-55 checksum when mixed case) addresses.' },
  { id: 'aadhaar', label: 'Aadhaar', how: 'Aadhaar numbers written 4-4-4 with a valid Verhoeff check digit. Shown masked.' },
];

interface ListResult {
  data: FoundValue[];
  total: number;
  kinds: Record<FoundKind, number>;
  analysed: string[];
  not_analysed: string[];
}

function detailText(v: FoundValue): string {
  const d = v.details || {};
  return [d.brand, d.country, d.scope, d.network, d.host, d.checksum === 'valid' ? 'EIP-55 checksum' : d.checksum === 'none' ? 'no checksum (one case)' : '']
    .filter(Boolean).join(' · ');
}

export function FoundDataPage() {
  const { caseId, reloadOverview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const [kind, setKind] = useState<FoundKind>('email');
  const [q, setQ] = useState('');
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [queued, setQueued] = useState(false);
  const enc = encodeURIComponent(caseId);
  const path = `/forensics/entities?case_id=${enc}&kind=${kind}&limit=500${search ? `&q=${encodeURIComponent(search)}` : ''}`;
  const list = useApi<ListResult>(path);
  useEffect(() => setOpen(null), [kind, search]);
  const meta = KINDS.find((k) => k.id === kind)!;
  const counts = list.data?.kinds;

  async function reveal(v: FoundValue) {
    try {
      const r = await post<{ value: string }>(`/forensics/entities/${v._id}/reveal`);
      setRevealed((m) => ({ ...m, [v._id]: r.value }));
      toast('Shown in full. This is recorded in the audit log.', 'ok');
    } catch (e: any) {
      toast(e.message, 'danger');
    }
  }

  async function analyse(ids: string[]) {
    try {
      for (const eid of ids) await post(`/jobs/analysis/${encodeURIComponent(eid)}`, { modules: ['content', 'found_data'] });
      setQueued(true);
      toast('Indexing file contents and looking for data. This page fills in when the analysis completes.', 'ok');
      reloadOverview();
    } catch (e: any) {
      toast(e.message, 'danger');
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="Found data"
        subtitle="Email, web and IP addresses, phone, card, IBAN, cryptocurrency and Aadhaar numbers recognised in the file contents, deleted files included. Each value is validated (for example card numbers by the Luhn check), and every occurrence has its file and byte offset. Card and Aadhaar numbers are masked; showing one in full is recorded in the audit log."
        actions={<Link className="btn" to="/app/search?mode=text"><Search size={15} /> Search file contents</Link>}
      />
      {list.data && list.data.not_analysed.length > 0 && (
        <Banner tone="info">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <span>
              {list.data.not_analysed.join(', ')} {list.data.not_analysed.length === 1 ? 'has' : 'have'} no found data yet: the file contents are read by the Full analysis profile.
            </span>
            {can('ANALYSIS_RUN') && (queued ? <Badge tone="accent">ANALYSIS QUEUED</Badge>
              : <Button size="sm" icon={<FileSearch size={13} />} onClick={() => analyse(list.data!.not_analysed)}>Index contents and find data</Button>)}
          </div>
        </Banner>
      )}
      <Card flush>
        <Tabs<FoundKind> value={kind} onChange={setKind} tabs={KINDS.map((k) => ({ id: k.id, label: k.label, count: counts ? counts[k.id] : undefined }))} />
        <div className="row" style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)' }}>
          <input className="input sm" style={{ maxWidth: 320 }} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && setSearch(q.trim())}
            placeholder={kind === 'card' || kind === 'aadhaar' ? 'Filter by the last digits' : 'Filter values'} aria-label="Filter values" />
          <Button size="sm" icon={<Search size={13} />} onClick={() => setSearch(q.trim())}>Filter</Button>
          {search && <Button size="sm" variant="ghost" onClick={() => { setQ(''); setSearch(''); }}>Clear</Button>}
          <span className="small muted">{meta.how}</span>
          <span style={{ flex: 1 }} />
          {!!list.data?.data.length && <ExportButton path={path} what="list of values" />}
        </div>
        <ErrorBanner error={list.error} />
        {list.loading && !list.data ? <Loading /> : !list.data?.data.length ? (
          <Empty title={`No ${meta.label.toLowerCase()} found`} text={list.data?.analysed.length ? undefined : 'Run the Full analysis profile to read the file contents.'} />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Value</th><th>Details</th><th className="right">Occurrences</th><th className="right">Files</th><th>Evidence</th><th /></tr></thead>
              <tbody>
                {list.data.data.map((v) => (
                  <Fragment key={v._id}>
                    <tr>
                      <td className="mono small" style={{ wordBreak: 'break-all' }}>
                        {revealed[v._id] || v.display}
                        {v.sensitive && !revealed[v._id] && (
                          <Button size="sm" variant="ghost" icon={<Eye size={13} />} onClick={() => reveal(v)} aria-label={`Show ${v.display} in full`}>Show</Button>
                        )}
                      </td>
                      <td className="small">{detailText(v)}</td>
                      <td className="right small">{formatNumber(v.count)}</td>
                      <td className="right small">{formatNumber(v.file_count)}</td>
                      <td className="mono small">{v.evidence_id}</td>
                      <td className="right nowrap">
                        <TagButton type="ENTITY" id={v._id} title={v.display} />{' '}
                        <Button size="sm" icon={<ListTree size={13} />} onClick={() => setOpen(open === v._id ? null : v._id)} aria-expanded={open === v._id}
                          aria-label={`Where ${v.display} was found`}>Where</Button>
                      </td>
                    </tr>
                    {open === v._id && (
                      <tr><td colSpan={6} style={{ background: 'var(--surface-2)' }}><Occurrences id={v._id} /></td></tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {list.data && list.data.total > list.data.data.length && <div className="small muted" style={{ padding: 12 }}>Showing the {list.data.data.length} most frequent of {formatNumber(list.data.total)}; filter to find others.</div>}
      </Card>
    </div>
  );
}

function Occurrences({ id }: { id: string }) {
  const [v, setV] = useState<FoundValue | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    api<FoundValue>(`/forensics/entities/${id}`).then(setV).catch((e) => setError(e.message));
  }, [id]);
  if (error) return <Banner tone="danger">{error}</Banner>;
  if (!v) return <Loading />;
  const occ = v.occurrences || [];
  return (
    <div className="stack" style={{ gap: 6 }}>
      {occ.map((o, i) => { const src = locate({ ...o, evidence_id: v.evidence_id }); return (
        <div key={i} className="row" style={{ justifyContent: 'space-between' }}>
          <span className="mono small" style={{ wordBreak: 'break-all' }}>
            {o.path} {o.deleted && <Badge tone="danger">DELETED</Badge>} {o.member && <Badge tone="accent">IN ARCHIVE</Badge>}
            <span className="muted"> · {o.byte_offset !== null ? `byte ${formatNumber(o.byte_offset)}` : 'in extracted text'}{o.as_found && o.as_found !== v.display ? ` · written “${o.as_found}”` : ''}</span>
          </span>
          {o.byte_offset !== null && src && <ViewButton source={src} at={{ offset: o.byte_offset, length: o.byte_length }} />}
        </div>
      ); })}
      {v.count > occ.length && <div className="tiny muted">Showing {occ.length} of {formatNumber(v.count)} occurrences.</div>}
    </div>
  );
}

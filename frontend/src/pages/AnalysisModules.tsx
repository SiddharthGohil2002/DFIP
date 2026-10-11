import { useState } from 'react';
import { RotateCcw } from 'lucide-react';
import { post } from '../lib/api';
import { formatNumber, humanize, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { AnalysisCatalog, Evidence } from '../lib/types';
import { Badge, Banner, Button, Card, Modal, StatusBadge, useToast } from '../ui';

const PROFILE_HINTS: Record<string, string> = {
  quick: 'A fast first look: every file (including deleted ones), the file timeline, browser, USB and Windows activity.',
  standard: 'Everything that is cheap enough to run on every disk. The default.',
  full: 'Everything, including the slower content modules.',
};

/** Starts an analysis with a chosen profile, or a custom set of modules. */
export function AnalysisOptionsModal({ evidence, open, onClose, onQueued }: {
  evidence: Evidence;
  open: boolean;
  onClose: () => void;
  onQueued: (jobId: string) => void;
}) {
  const catalog = useApi<AnalysisCatalog>(open ? '/jobs/analysis/modules' : null);
  const toast = useToast();
  const [choice, setChoice] = useState('standard');
  const [custom, setCustom] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const c = catalog.data;
  const labelOf = (name: string) => c?.modules.find((m) => m.name === name)?.label ?? name;

  async function start() {
    setBusy(true);
    setError('');
    try {
      const body = choice === 'custom' ? { modules: custom } : { profile: choice };
      const r = await post<{ job_id: string }>(`/jobs/analysis/${encodeURIComponent(evidence.evidence_id)}`, body);
      toast(`Analysis ${r.job_id} queued`, 'ok');
      onQueued(r.job_id);
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} title={`Analyze ${evidence.evidence_id}`} onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="primary" busy={busy} disabled={!c || (choice === 'custom' && !custom.length)} onClick={start}>Start analysis</Button>
        </>
      }>
      <div className="stack" style={{ gap: 12 }}>
        <p className="small muted" style={{ margin: 0 }}>
          The image's SHA-256 is verified before anything runs. Modules that a chosen module needs are added automatically.
        </p>
        {c?.profiles.map((p) => (
          <label key={p.name} className="check" style={{ alignItems: 'flex-start' }}>
            <input type="radio" name="profile" checked={choice === p.name} onChange={() => setChoice(p.name)} />
            <span>
              <span className="strong">{p.label}</span>{p.name === c.default_profile && <span className="muted"> (default)</span>}
              <div className="small muted">{PROFILE_HINTS[p.name]} Runs: {p.modules.map(labelOf).join(', ')}.</div>
            </span>
          </label>
        ))}
        {c && (
          <label className="check" style={{ alignItems: 'flex-start' }}>
            <input type="radio" name="profile" checked={choice === 'custom'} onChange={() => setChoice('custom')} />
            <span>
              <span className="strong">Choose modules</span>
              <div className="small muted">Run only the modules you pick, for example to re-run one after a change.</div>
            </span>
          </label>
        )}
        {c && choice === 'custom' && (
          <div className="stack" style={{ gap: 6, paddingLeft: 24 }}>
            {c.modules.map((m) => (
              <label key={m.name} className="check" style={{ alignItems: 'flex-start' }}>
                <input type="checkbox" checked={custom.includes(m.name)}
                  onChange={(ev) => setCustom(ev.target.checked ? [...custom, m.name] : custom.filter((x) => x !== m.name))} />
                <span>
                  <span className="strong">{m.label}</span>
                  <div className="small muted">{m.description}{m.requires.length > 0 && ` Needs: ${m.requires.map(labelOf).join(', ')}.`}</div>
                </span>
              </label>
            ))}
          </div>
        )}
        {error && <Banner tone="danger">{error}</Banner>}
      </div>
    </Modal>
  );
}

// How each count reads, singular and plural, in the order it is shown (timeline events last).
const COUNT_LABELS: [string, string, string][] = [
  ['files', 'file', 'files'], ['deleted_files', 'deleted', 'deleted'],
  ['browser_history', 'browser visit', 'browser visits'], ['browser_downloads', 'download', 'downloads'],
  ['usb_devices', 'USB device', 'USB devices'], ['programs_run', 'program run', 'programs run'],
  ['recent_files', 'recently opened file', 'recently opened files'], ['recycle_bin_items', 'Recycle Bin item', 'Recycle Bin items'],
  ['files_hashed', 'file hashed', 'files hashed'], ['files_unreadable', 'unreadable file', 'unreadable files'],
  ['renamed_files', 'renamed file', 'renamed files'], ['encrypted_files', 'encrypted file', 'encrypted files'],
  ['encrypted_volumes', 'encrypted volume', 'encrypted volumes'],
  ['known_bad_files', 'known-bad file', 'known-bad files'], ['notable_files', 'notable file', 'notable files'],
  ['known_good_files', 'known-good file', 'known-good files'],
  ['files_scanned', 'file scanned', 'files scanned'], ['yara_matches', 'YARA match', 'YARA matches'],
  ['files_text_indexed', 'file indexed for content search', 'files indexed for content search'],
  ['files_text_failed', 'file whose text could not be read', 'files whose text could not be read'],
  ['files_text_truncated', 'file indexed in part', 'files indexed in part'],
  ['found_emails', 'email address', 'email addresses'], ['found_urls', 'web address', 'web addresses'],
  ['found_ip_addresses', 'IP address', 'IP addresses'], ['found_phone_numbers', 'phone number', 'phone numbers'],
  ['found_card_numbers', 'card number', 'card numbers'], ['found_ibans', 'IBAN', 'IBANs'],
  ['found_crypto_addresses', 'crypto address', 'crypto addresses'], ['found_aadhaar_numbers', 'Aadhaar number', 'Aadhaar numbers'],
  ['containers_opened', 'archive or document opened', 'archives and documents opened'],
  ['members_found', 'file inside', 'files inside'], ['members_extracted', 'extracted', 'extracted'],
  ['members_encrypted', 'encrypted member', 'encrypted members'], ['members_not_extracted', 'member not extracted', 'members not extracted'],
  ['unallocated_text_blocks', 'block of unallocated text', 'blocks of unallocated text'],
  ['registry_hives', 'registry hive', 'registry hives'], ['userassist_entries', 'UserAssist entry', 'UserAssist entries'],
  ['folders_browsed', 'folder browsed', 'folders browsed'], ['explorer_searches', 'Explorer search', 'Explorer searches'],
  ['typed_paths', 'typed path', 'typed paths'], ['typed_urls', 'typed address', 'typed addresses'],
  ['recent_docs', 'recent document', 'recent documents'], ['run_dialog_entries', 'Run dialog command', 'Run dialog commands'],
  ['persistence_entries', 'autostart entry', 'autostart entries'], ['persistence_flagged', 'flagged autostart entry', 'flagged autostart entries'],
  ['installed_programs', 'installed program', 'installed programs'], ['amcache_entries', 'Amcache entry', 'Amcache entries'],
  ['shimcache_entries', 'ShimCache entry', 'ShimCache entries'], ['bam_entries', 'BAM entry', 'BAM entries'],
  ['rdp_connections', 'remote desktop connection', 'remote desktop connections'], ['network_drives', 'network drive', 'network drives'],
  ['event_logs', 'event log', 'event logs'], ['event_records', 'event record', 'event records'],
  ['recovered_event_records', 'recovered event record', 'recovered event records'], ['notable_events', 'notable event', 'notable events'],
  ['eventlog_detections', 'detection', 'detections'], ['jumplists', 'Jump List', 'Jump Lists'],
  ['jumplist_entries', 'Jump List item', 'Jump List items'], ['timeline_activities', 'Timeline activity', 'Timeline activities'],
  ['thumbnails', 'thumbnail', 'thumbnails'], ['srum_network_records', 'SRUM network record', 'SRUM network records'],
  ['srum_app_records', 'SRUM application record', 'SRUM application records'],
  ['srum_connectivity_records', 'SRUM connection record', 'SRUM connection records'],
  ['search_index_entries', 'search index entry', 'search index entries'],
  ['search_entries_not_on_disk', 'indexed file no longer on the disk', 'indexed files no longer on the disk'],
  ['ntfs_volumes', 'NTFS volume', 'NTFS volumes'], ['mft_entries', 'MFT entry', 'MFT entries'],
  ['timestomp_suspects', 'file whose times look altered', 'files whose times look altered'],
  ['timestomp_possible', 'file whose times may be altered', 'files whose times may be altered'],
  ['alternate_streams', 'alternate data stream', 'alternate data streams'], ['downloaded_files', 'downloaded file', 'downloaded files'],
  ['usn_records', 'USN journal record', 'USN journal records'], ['usb_devices_from_event_logs', 'USB device seen only in the event logs', 'USB devices seen only in the event logs'],
  ['timeline_events', 'timeline event', 'timeline events'],
];

function results(counts?: Record<string, number>) {
  const c = counts || {};
  const label = ([k, one, many]: [string, string, string]) => `${formatNumber(c[k])} ${c[k] === 1 ? one : many}`;
  const known = COUNT_LABELS.filter(([k]) => k !== 'timeline_events' && c[k] > 0).map(label);
  const other = Object.keys(c).filter((k) => c[k] > 0 && !COUNT_LABELS.some(([key]) => key === k))
    .map((k) => `${formatNumber(c[k])} ${humanize(k).toLowerCase()}`);
  const timeline = c.timeline_events > 0 ? [label(COUNT_LABELS[COUNT_LABELS.length - 1])] : [];
  const shown = [...known, ...other, ...timeline];
  return shown.length ? shown.join(' · ') : 'Nothing found';
}

/** Each analysis module's latest run on this evidence, with a per-module re-run. */
export function AnalysisModulesCard({ evidence, running, canRun, onQueued }: {
  evidence: Evidence;
  running: boolean;
  canRun: boolean;
  onQueued: (jobId: string) => void;
}) {
  const catalog = useApi<AnalysisCatalog>('/jobs/analysis/modules');
  const toast = useToast();
  const time = useTime();
  const [busy, setBusy] = useState('');
  const modules = evidence.modules || {};
  const list = catalog.data?.modules || [];
  if (!list.length || !Object.keys(modules).length) return null;

  async function rerun(name: string) {
    setBusy(name);
    try {
      const r = await post<{ job_id: string }>(`/jobs/analysis/${encodeURIComponent(evidence.evidence_id)}`, { modules: [name] });
      toast(`Re-running ${list.find((m) => m.name === name)?.label ?? name} (${r.job_id})`, 'ok');
      onQueued(r.job_id);
    } catch (err: any) {
      toast(err.message, 'danger');
    } finally {
      setBusy('');
    }
  }

  return (
    <Card title="Analysis modules" subtitle="Each module keeps its own results; re-running one replaces only its output (and refreshes the modules built on it)." flush>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Module</th><th>Status</th><th>Results</th><th>Finished</th><th /></tr></thead>
          <tbody>
            {list.map((m) => {
              const s = modules[m.name];
              return (
                <tr key={m.name}>
                  <td><div className="strong">{m.label}</div><div className="tiny muted">{m.name} · v{s?.version ?? m.version}</div></td>
                  <td>{s ? <StatusBadge status={s.status} /> : <Badge>Not run</Badge>}</td>
                  <td className="small">
                    {s?.status === 'COMPLETED' ? results(s.counts) : s?.error ? <span style={{ color: 'var(--danger)' }}>{s.error}</span> : '—'}
                    {!!s?.warnings_total && <div><Badge tone="warn">{formatNumber(s.warnings_total)} warning{s.warnings_total === 1 ? '' : 's'}</Badge></div>}
                  </td>
                  <td className="small nowrap">{s?.finished_at ? time(s.finished_at) : '—'}</td>
                  <td className="nowrap right">
                    {canRun && (
                      <Button size="sm" icon={<RotateCcw size={13} />} busy={busy === m.name} disabled={running || !!busy}
                        title={running ? 'An analysis is running for this evidence' : undefined} onClick={() => rerun(m.name)}>
                        {s ? 'Re-run' : 'Run'}
                      </Button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

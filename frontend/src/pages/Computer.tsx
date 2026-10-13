import { Link } from 'react-router-dom';
import { Monitor } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { formatNumber, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import type { ComputerEntry } from '../lib/types';
import { Badge, Card, Empty, ErrorBanner, Hash, Loading, PageHeader } from '../ui';
import { describeTimeZone } from './TimeZone';

export function ComputerPage() {
  const { caseId } = useCase();
  const res = useApi<{ data: ComputerEntry[] }>(`/forensics/computer?case_id=${encodeURIComponent(caseId)}`);

  return (
    <div className="stack">
      <PageHeader
        title="Computer and users"
        subtitle="What the Windows registry says about the computer: its name, Windows version, network, last shutdown and time zone (SYSTEM and SOFTWARE hives), and its user accounts (SAM hive and user profiles)."
      />
      <ErrorBanner error={res.error} />
      {res.loading && !res.data ? (
        <Loading />
      ) : !res.data?.data.length ? (
        <Card><Empty icon={<Monitor size={20} />} title="No computer details yet" text="Analyze a Windows disk image: the SYSTEM, SOFTWARE and SAM hives are read automatically." /></Card>
      ) : (
        res.data.data.map((entry) => <ComputerCard key={entry.evidence_id} entry={entry} />)
      )}
    </div>
  );
}

function ComputerCard({ entry }: { entry: ComputerEntry }) {
  const time = useTime();
  const c = entry.computer;
  const os = c?.os || {};
  return (
    <>
      <Card title={c?.computer_name || 'Computer'} subtitle={<>{entry.evidence_id} · {entry.filename} · <Link to={`/app/evidence/${entry.evidence_id}`}>evidence details</Link></>}>
        {!c ? (
          <Empty title="No Windows registry found" text="No SYSTEM, SOFTWARE or SAM hive was found on this evidence." />
        ) : (
          <div className="grid cols-2">
            <dl className="kv">
              <dt>Windows</dt>
              <dd>{[os.product_name, os.display_version].filter(Boolean).join(' ') || '—'}{os.build && <span className="muted"> · build {os.build}{os.ubr ? `.${os.ubr}` : ''}</span>}</dd>
              <dt>Installed</dt><dd>{time(os.install_date)}</dd>
              <dt>Registered owner</dt><dd>{os.registered_owner || '—'}{os.registered_organization && <span className="muted"> · {os.registered_organization}</span>}</dd>
              <dt>Last shutdown</dt><dd>{time(c.last_shutdown)}</dd>
              <dt>Last signed-in user</dt><dd>{c.last_logged_on_user || '—'}</dd>
              <dt>Time zone</dt><dd>{describeTimeZone(entry.time_zone)}</dd>
              <dt>Computer SID</dt><dd className="mono small">{c.machine_sid || '—'}</dd>
            </dl>
            <dl className="kv">
              {(c.hives || []).map((h) => (
                <span key={h.hive} style={{ display: 'contents' }}>
                  <dt>{h.hive} hive</dt>
                  <dd><div className="small mono">{h.path}</div><Hash value={h.sha256} short={16} /></dd>
                </span>
              ))}
            </dl>
          </div>
        )}
      </Card>
      {c && !!c.interfaces?.length && (
        <Card title="Network interfaces" subtitle="From the SYSTEM hive (Tcpip interfaces with an address)." flush>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>IP address</th><th>Subnet mask</th><th>Gateway</th><th>Configured by</th><th>DNS domain</th><th>Lease obtained</th></tr></thead>
              <tbody>
                {c.interfaces.map((i) => (
                  <tr key={i.guid}>
                    <td className="mono small strong">{i.ip}<div className="tiny muted">{i.guid}</div></td>
                    <td className="mono small">{i.subnet_mask || '—'}</td>
                    <td className="mono small">{i.gateway || '—'}</td>
                    <td className="small">{i.dhcp ? <>DHCP <span className="mono">{i.dhcp_server}</span></> : 'Static'}</td>
                    <td className="small">{i.domain || '—'}</td>
                    <td className="mono small nowrap">{time(i.lease_obtained)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
      <Card title="User accounts" subtitle="Local accounts: on Windows the SAM hive joined with the user profiles in SOFTWARE by SID; on Linux /etc/passwd, /etc/group and /etc/shadow; on macOS the local directory." flush>
        {!entry.accounts.length ? (
          <Empty title="No user accounts" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>User</th><th>SID or UID</th><th>Last logon</th><th className="right">Logons</th><th>Password set</th><th>Profile</th><th>Account</th></tr></thead>
              <tbody>
                {entry.accounts.map((a) => (
                  <tr key={a._id}>
                    <td><div className="strong">{a.username || '—'}</div>{a.full_name && <div className="small muted">{a.full_name}</div>}</td>
                    <td className="mono tiny">{a.sid || ((a as any).uid != null ? `UID ${(a as any).uid}` : '—')}{(a as any).shell && <div className="muted">{(a as any).shell}</div>}</td>
                    <td className="mono small nowrap">{time(a.last_logon)}</td>
                    <td className="right">{a.source === 'SAM' ? formatNumber(a.logon_count) : '—'}</td>
                    <td className="mono small nowrap">{time(a.password_last_set)}</td>
                    <td className="small">{a.profile_path || '—'}{a.profile_last_loaded && <div className="tiny muted">loaded {time(a.profile_last_loaded)}</div>}</td>
                    <td>
                      {(a as any).os_family ? (
                        <>
                          {(a as any).admin && <Badge tone="warn">ADMIN</Badge>} {(a as any).password_state === 'locked' && <Badge>Locked</Badge>}
                          {((a as any).flags || []).map((f: any) => <div key={f.code}><Badge tone={f.severity === 'high' ? 'danger' : 'warn'}>{f.label}</Badge></div>)}
                        </>
                      ) : a.source === 'PROFILE_LIST' ? <Badge tone="info">Profile only</Badge>
                        : a.disabled ? <Badge>Disabled</Badge> : <Badge tone="ok">Enabled</Badge>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}

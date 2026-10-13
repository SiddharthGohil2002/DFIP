import { useContext, useState } from 'react';
import { Link } from 'react-router-dom';
import { useCase } from '../lib/caseContext';
import { TimeModeContext, formatBytes, useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { Card, Empty, ErrorBanner, Loading, PageHeader } from '../ui';
import { HBarChart, Heatmap, UsbLanes, type UsbSpan } from '../ui/charts';

interface Dashboard {
  tz: string;
  scope: 'activity' | 'all';
  heatmap: { cells: [number, number, number][]; max: number; total: number };
  per_day: { date: string; total: number; by_group: Record<string, number> }[];
  top_domains: { data: { host: string; visits: number; pages: number }[]; total_hosts: number; other_visits: number };
  file_types: { data: { extension: string; count: number; size: number; deleted: number }[]; other: { count: number; extensions: number } };
  usb_spans: UsbSpan[];
}

const GROUP_NAMES: Record<string, string> = { web: 'web', usb: 'USB', windows: 'Windows activity', logon: 'logon and logoff', comms: 'email, chat and phone', files: 'filesystem', other: 'other' };
const MAX_DAYS = 14;

export function DashboardPage() {
  const { caseId, overview } = useCase();
  const { mode } = useContext(TimeModeContext);
  const time = useTime();
  const [all, setAll] = useState(false);
  const zone = mode === 'utc' ? 'UTC' : Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  const { data, error, loading } = useApi<Dashboard>(
    caseId ? `/cases/${encodeURIComponent(caseId)}/dashboard?tz=${encodeURIComponent(zone)}&scope=${all ? 'all' : 'activity'}` : null,
  );
  const analyzed = (overview?.evidence || []).some((e) => e.analysis_status === 'COMPLETED');

  // The busiest days, shown in date order.
  const days = data ? [...data.per_day].sort((a, b) => b.total - a.total).slice(0, MAX_DAYS).sort((a, b) => a.date.localeCompare(b.date)) : [];

  return (
    <div className="stack">
      <PageHeader
        title="Activity dashboard"
        subtitle={`When the computer was used, which websites were visited, what the disks hold and when USB drives were connected. Times are shown in ${zone}.`}
        actions={
          <label className="check" title="Filesystem times change for system reasons too; FAT disks record only the date of the last access.">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> Include filesystem times (MACB)
          </label>
        }
      />
      <ErrorBanner error={error} />
      {!analyzed ? (
        <Card><Empty title="No analyzed evidence" text={<>Run the full analysis on an image (<Link to="/app/evidence">Evidence</Link>) to see its activity.</>} /></Card>
      ) : loading && !data ? (
        <Loading />
      ) : data && (
        <>
          <Card
            title="Activity by day of the week and hour"
            subtitle={`${data.heatmap.total.toLocaleString()} ${all ? 'events, including filesystem times' : 'user activity events: web, USB, Windows activity, logons and logoffs, email sent, calls and file transfers'} · ${zone}`}
          >
            {data.heatmap.total ? <Heatmap cells={data.heatmap.cells} max={data.heatmap.max} zone={zone} /> : <Empty title="No events" />}
          </Card>
          <div className="grid cols-2">
            <Card title="Busiest days" subtitle={data.per_day.length > MAX_DAYS ? `${MAX_DAYS} of ${data.per_day.length} active days, in date order` : `${data.per_day.length} active days`}>
              {days.length ? (
                <HBarChart ariaLabel="Events per day" unit="events" labelWidth={100}
                  rows={days.map((d) => ({ key: d.date, label: d.date, value: d.total,
                    hint: Object.entries(d.by_group).map(([g, n]) => `${n} ${GROUP_NAMES[g] || g}`).join(' · ') }))} />
              ) : <Empty title="No events" />}
            </Card>
            <Card title="USB connections" subtitle="First install, connections and removals recorded for each device">
              {data.usb_spans.length ? <UsbLanes spans={data.usb_spans} format={(t) => time(t)} /> : <Empty title="No USB storage devices" />}
            </Card>
          </div>
          <div className="grid cols-2">
            <Card title="Top websites" subtitle={`By visits recorded by the browsers · ${data.top_domains.total_hosts} sites`}>
              {data.top_domains.data.length ? (
                <HBarChart ariaLabel="Websites by visits" unit="visits"
                  rows={data.top_domains.data.map((h) => ({ key: h.host, label: h.host, value: h.visits, hint: `${h.pages} page${h.pages === 1 ? '' : 's'} in history` }))} />
              ) : <Empty title="No browser history" />}
            </Card>
            <Card title="File types" subtitle={`Files by extension${data.file_types.other.count ? ` · ${data.file_types.other.count} more in ${data.file_types.other.extensions} other types` : ''}`}>
              {data.file_types.data.length ? (
                <HBarChart ariaLabel="Files by extension" unit="files" labelWidth={90}
                  rows={data.file_types.data.map((f) => ({ key: f.extension, label: f.extension === '(none)' ? '(none)' : `.${f.extension}`, value: f.count,
                    hint: `${formatBytes(f.size)}${f.deleted ? ` · ${f.deleted} deleted` : ''}` }))} />
              ) : <Empty title="No files indexed" />}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

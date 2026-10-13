import { Usb } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import type { TimelineEvent, UsbDevice } from '../lib/types';
import { Badge, Banner, Card, Empty, ErrorBanner, Loading, PageHeader } from '../ui';
import { ExportButton } from '../ui/ExportButton';

const TIMES: { key: keyof UsbDevice; label: string }[] = [
  { key: 'first_install', label: 'First installed (registry)' },
  { key: 'setupapi_first_install', label: 'First installed (setupapi.dev.log)' },
  { key: 'last_install', label: 'Last installed' },
  { key: 'last_arrival', label: 'Last connected' },
  { key: 'last_removal', label: 'Last removed' },
  { key: 'eventlog_first_connected', label: 'First connected (event log)' },
  { key: 'eventlog_last_connected', label: 'Last connected (event log)' },
  { key: 'eventlog_last_removed', label: 'Last removed (event log)' },
];
const SOURCE: Record<string, [string, 'accent' | 'warn']> = {
  SYSTEM_HIVE: ['Registry', 'accent'], SETUPAPI_LOG: ['setupapi.dev.log only', 'warn'], EVENT_LOG: ['Event logs only', 'warn'],
};

export function UsbPage() {
  const { caseId } = useCase();
  const time = useTime();
  const path = `/forensics/usb?case_id=${encodeURIComponent(caseId)}`;
  const devices = useApi<{ data: UsbDevice[] }>(path);
  const events = useApi<{ data: TimelineEvent[] }>(`/forensics/timeline?case_id=${encodeURIComponent(caseId)}&type=USB_ACTIVITY&order=asc&limit=500`);

  return (
    <div className="stack">
      <PageHeader
        title="USB devices"
        subtitle="Removable storage devices recorded by Windows in the SYSTEM registry hive (USBSTOR, USB, MountedDevices and device-property timestamps), in setupapi.dev.log and in the event logs (Partition/Diagnostic, Kernel-PnP, DriverFrameworks)."
        actions={!!devices.data?.data.length && <ExportButton path={path} what="list of devices" />}
      />
      <Banner tone="info">
        An empty time means the evidence does not record it (for example, Windows 7 does not store last-connected or last-removed times). DFIP never estimates a missing value. setupapi.dev.log times are converted to UTC using the time zone stored in the SYSTEM hive.
      </Banner>
      <ErrorBanner error={devices.error} />
      {devices.loading && !devices.data ? (
        <Loading />
      ) : !devices.data?.data.length ? (
        <Card><Empty icon={<Usb size={20} />} title="No USB storage devices" text="No USBSTOR entries or USB device installs were found in the analyzed images (or no Windows image has been analyzed yet)." /></Card>
      ) : (
        <div className="grid cols-2">
          {devices.data.data.map((d) => {
            const related = (events.data?.data || []).filter((e) => e.serial === d.serial);
            return (
              <section className="card usb-card" key={d._id}>
                <div className="row between">
                  <div className="row">
                    <div className="tile-icon amber"><Usb size={19} /></div>
                    <div>
                      <h3 style={{ fontSize: 16 }}>{d.friendly_name || `${d.vendor || ''} ${d.product || ''}`.trim() || 'USB storage device'}</h3>
                      <div className="small muted">{[d.vendor, d.product, d.revision && `rev ${d.revision}`].filter(Boolean).join(' · ')}</div>
                    </div>
                  </div>
                  <div className="row" style={{ gap: 4 }}>
                    <Badge tone={(SOURCE[d.source] || [d.source, 'warn'])[1]}>{(SOURCE[d.source] || [d.source])[0]}</Badge>
                    {!!d.eventlog_events?.length && d.source !== 'EVENT_LOG' && <Badge tone="accent">Event logs</Badge>}
                    <TagButton type="USB" id={d._id} title={d.friendly_name || `${d.vendor || ''} ${d.product || ''}`.trim()} />
                  </div>
                </div>
                <dl className="kv" style={{ gridTemplateColumns: '130px 1fr' }}>
                  <dt>Serial number</dt>
                  <dd className="mono">{d.serial} {d.serial_is_unique === false && <Badge tone="warn" title="Windows generated this ID because the device reports no unique serial">OS-generated</Badge>}</dd>
                  <dt>VID : PID</dt><dd className="mono">{d.vid ? `${d.vid} : ${d.pid}` : '—'}</dd>
                  <dt>Drive letter</dt><dd>{d.drive_letters?.length ? d.drive_letters.join(', ') : '—'}</dd>
                  {!!d.volume_guids?.length && (<><dt>Volume GUID</dt><dd className="mono small">{d.volume_guids.join(', ')}</dd></>)}
                  {d.registry_key && (<><dt>Registry key</dt><dd className="mono tiny break">SYSTEM\{d.registry_key}</dd></>)}
                  <dt>Evidence</dt><dd className="mono">{d.evidence_id}</dd>
                </dl>
                <div className="usb-times">
                  {TIMES.map((t) => (
                    <div className="usb-time" key={t.key}>
                      <div className="k">{t.label}</div>
                      <div className="v">{d[t.key] ? time(d[t.key] as string) : <span className="faint">not recorded</span>}</div>
                    </div>
                  ))}
                </div>
                {!!d.eventlog_events?.length && (
                  <details>
                    <summary className="small strong">{d.eventlog_events.length} event log record{d.eventlog_events.length === 1 ? '' : 's'} for this device</summary>
                    <table className="table">
                      <tbody>
                        {d.eventlog_events.map((e) => (
                          <tr key={`${e.log}${e.record_id}`}>
                            <td className="mono tiny nowrap">{time(e.time)}</td>
                            <td className="small">{e.action}</td>
                            <td className="small muted">{e.log.replace(/\.evtx$/i, '').replace('%4', '/')} event {e.event_id}, record {e.record_id}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </details>
                )}
                {related.length > 0 && <div className="small muted">{related.length} timeline event{related.length === 1 ? '' : 's'} for this device.</div>}
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}

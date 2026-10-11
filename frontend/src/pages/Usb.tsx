import { Usb } from 'lucide-react';
import { useCase } from '../lib/caseContext';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import type { TimelineEvent, UsbDevice } from '../lib/types';
import { Badge, Banner, Card, Empty, ErrorBanner, Loading, PageHeader } from '../ui';

const TIMES: { key: keyof UsbDevice; label: string }[] = [
  { key: 'first_install', label: 'First installed (registry)' },
  { key: 'setupapi_first_install', label: 'First installed (setupapi.dev.log)' },
  { key: 'last_install', label: 'Last installed' },
  { key: 'last_arrival', label: 'Last connected' },
  { key: 'last_removal', label: 'Last removed' },
];

export function UsbPage() {
  const { caseId } = useCase();
  const time = useTime();
  const devices = useApi<{ data: UsbDevice[] }>(`/forensics/usb?case_id=${encodeURIComponent(caseId)}`);
  const events = useApi<{ data: TimelineEvent[] }>(`/forensics/timeline?case_id=${encodeURIComponent(caseId)}&type=USB_ACTIVITY&order=asc&limit=500`);

  return (
    <div className="stack">
      <PageHeader
        title="USB devices"
        subtitle="Removable storage devices recorded by Windows in the SYSTEM registry hive (USBSTOR, USB, MountedDevices and device-property timestamps) and in setupapi.dev.log."
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
                    <Badge tone={d.source === 'SYSTEM_HIVE' ? 'accent' : 'warn'}>{d.source === 'SYSTEM_HIVE' ? 'Registry' : 'setupapi.dev.log only'}</Badge>
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
                {related.length > 0 && <div className="small muted">{related.length} timeline event{related.length === 1 ? '' : 's'} for this device.</div>}
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}

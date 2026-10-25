import { Fragment, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bookmark, MessageSquare } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { Comments } from '../ui/Comments';
import { ExportButton } from '../ui/ExportButton';
import { useTime } from '../lib/format';
import { TAG_LABELS, TAG_TONES, TagButton, useTags, type Tag, type TagItemType, type TagLabel } from '../lib/tags';
import { Badge, Button, Card, Empty, PageHeader, Tabs } from '../ui';

const TYPE_NAMES: Record<TagItemType, string> = {
  FILE: 'File', TIMELINE_EVENT: 'Timeline event', BROWSER: 'Browser record', USB: 'USB device',
  ACTIVITY: 'Windows activity', ARTIFACT: 'Recovered / carved file', ENTITY: 'Found data', REGISTRY: 'Registry activity', EVENT: 'Event log record', WINDOWS: 'Windows activity', USN: 'USN journal record',
  EMAIL: 'Email', CHAT_CLOUD: 'Chat or cloud record', PROGRAM: 'Program', SHADOW_FILE: 'Shadow copy file', UNIX: 'Linux or macOS record',
  NETWORK: 'Network capture record', PHONE: 'Phone record', MEMORY: 'Memory image record',
};
const SOURCE_PAGE: Record<TagItemType, string> = {
  FILE: '/app/files', TIMELINE_EVENT: '/app/timeline', BROWSER: '/app/browser', USB: '/app/usb', ACTIVITY: '/app/activity', ARTIFACT: '/app/files', ENTITY: '/app/found-data', REGISTRY: '/app/activity', EVENT: '/app/event-logs', WINDOWS: '/app/activity', USN: '/app/ntfs',
  EMAIL: '/app/email', CHAT_CLOUD: '/app/chat-cloud', PROGRAM: '/app/indicators', SHADOW_FILE: '/app/shadow-copies', UNIX: '/app/unix',
  NETWORK: '/app/network', PHONE: '/app/phones', MEMORY: '/app/memory',
};

/** Where Open goes: the page that lists the item. An ARTIFACT tag is a recovered, extracted or carved file or a YARA
 * match; its snapshot detail starts with which (services/tags.py snapshot). */
function openPath(t: Tag): string {
  if (t.item_type === 'FILE' && t.evidence_id) return `/app/files?evidence=${t.evidence_id}`;
  if (t.item_type === 'ARTIFACT') {
    const detail = t.snapshot.detail || '';
    if (detail.startsWith('Carved file')) return '/app/carving';
    if (detail.startsWith('YARA match')) return '/app/indicators';
    if (detail.startsWith('Extracted file')) return '/app/files?tab=members';
    return '/app/files?tab=recovered';
  }
  return SOURCE_PAGE[t.item_type];
}

type Filter = 'ALL' | TagLabel;

export function TaggedPage() {
  const { tags, reload } = useTags();
  const { caseId } = useCase();
  const { can } = useAuth();
  const time = useTime();
  const [open, setOpen] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('ALL');
  useEffect(() => reload(), [reload]);

  const count = (l: TagLabel) => tags.filter((t) => t.label === l).length;
  const shown = filter === 'ALL' ? tags : tags.filter((t) => t.label === filter);
  // The list useTags loads, narrowed to the tab shown.
  const path = `/tags?case_id=${encodeURIComponent(caseId)}${filter === 'ALL' ? '' : `&label=${filter}`}`;

  return (
    <div className="stack">
      <PageHeader
        title="Tagged items"
        subtitle="Files, events, web visits, USB devices and Windows activity marked during the review. Tagged items and their notes are listed in the case report."
      />
      <Card flush actions={can('REPORT_EXPORT') && shown.length > 0 && <ExportButton path={path} what="list of tagged items" />}>
        <Tabs<Filter>
          value={filter}
          onChange={setFilter}
          tabs={[
            { id: 'ALL', label: 'All', count: tags.length },
            { id: 'EVIDENCE', label: 'Evidence', count: count('EVIDENCE') },
            { id: 'NOTABLE', label: 'Notable', count: count('NOTABLE') },
            { id: 'FOLLOW_UP', label: 'Follow up', count: count('FOLLOW_UP') },
          ]}
        />
        {!shown.length ? (
          <Empty icon={<Bookmark size={20} />} title="Nothing tagged yet"
            text="Use the bookmark button on a deleted file, timeline event, browser record, USB device or Windows activity record to tag it." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Label</th><th>Item</th><th>Time</th><th>Note</th><th>Tagged by</th><th /></tr></thead>
              <tbody>
                {shown.map((t: Tag) => (
                  <Fragment key={t.tag_id}>
                  <tr>
                    <td><Badge tone={TAG_TONES[t.label]}>{TAG_LABELS[t.label]}</Badge></td>
                    <td className="cell-path">
                      <div className="small strong">{t.snapshot.title || '—'}</div>
                      <div className="tiny muted">{TYPE_NAMES[t.item_type]} · {t.snapshot.detail}</div>
                      {t.resolved === false && <Badge>Not in the latest analysis</Badge>}
                    </td>
                    <td className="mono small nowrap">{time(t.snapshot.timestamp)}</td>
                    <td className="small">{t.note || <span className="muted">—</span>}</td>
                    <td className="small nowrap">{t.created_by_name}<div className="tiny muted">{time(t.created_at)} · {t.tag_id}</div></td>
                    <td className="nowrap right">
                      <TagButton type={t.item_type} id={t.item_id} title={t.snapshot.title} />{' '}
                      <Link className="btn sm" to={openPath(t)}>Open</Link>{' '}
                      <Button size="sm" variant="ghost" icon={<MessageSquare size={13} />} aria-expanded={open === t.tag_id} onClick={() => setOpen(open === t.tag_id ? null : t.tag_id)}>Comments</Button>
                    </td>
                  </tr>
                  {open === t.tag_id && <tr><td colSpan={6}><Comments caseId={caseId} targetType="TAG" targetId={t.tag_id} title="Comments on this tag" /></td></tr>}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

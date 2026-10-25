import { useState } from 'react';
import { Bell, CheckCheck } from 'lucide-react';
import { patch } from '../lib/api';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { Badge, Button, Empty, Modal, useToast } from '../ui';

interface Notification { _id: string; title: string; message: string; level: string; read: boolean; created_at: string }

const LEVEL_TONES: Record<string, 'info' | 'warn' | 'danger'> = { INFO: 'info', WARNING: 'warn', ERROR: 'danger' };

/** The signed-in user's notifications (GET /notifications, the latest 100): finished and failed jobs, mentions in
 * comments, findings to review and review decisions, known-bad hash-set matches, imports and downloads, cases due
 * for deletion. Polled, because the UI keeps no WebSocket open. */
export function NotificationsButton() {
  const toast = useToast();
  const time = useTime();
  const list = useApi<{ data: Notification[] }>('/notifications', { pollMs: 30000 });
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const items = list.data?.data || [];
  const unread = items.filter((n) => !n.read);

  async function markRead(ids: string[]) {
    setBusy(true);
    try {
      await Promise.all(ids.map((id) => patch(`/notifications/${encodeURIComponent(id)}/read`)));
      list.reload();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Button size="sm" variant="ghost" icon={<Bell size={14} />} onClick={() => setOpen(true)}
        title={unread.length ? `${unread.length} unread notification(s)` : 'Notifications'} aria-label="Notifications">
        {unread.length > 0 && <span className="notif-count">{unread.length > 99 ? '99+' : unread.length}</span>}
      </Button>
      <Modal
        open={open}
        title="Notifications"
        onClose={() => setOpen(false)}
        footer={unread.length > 0 && (
          <Button icon={<CheckCheck size={14} />} busy={busy} onClick={() => markRead(unread.map((n) => n._id))}>Mark all as read</Button>
        )}
      >
        {!items.length ? (
          <Empty icon={<Bell size={20} />} title="No notifications" text="You are told here when an analysis finishes or fails, when someone mentions you or asks you to review a finding, and about other events that need you." />
        ) : (
          <div className="notif-list">
            {items.map((n) => (
              <div key={n._id} className={`notif ${n.read ? '' : 'unread'}`}>
                <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline' }}>
                  <span className="row"><Badge tone={LEVEL_TONES[n.level] || 'info'}>{n.level}</Badge> <b>{n.title}</b></span>
                  <span className="tiny muted nowrap">{time(n.created_at)}</span>
                </div>
                <div className="small" style={{ marginTop: 4 }}>{n.message}</div>
                {!n.read && <Button size="sm" variant="ghost" busy={busy} onClick={() => markRead([n._id])}>Mark as read</Button>}
              </div>
            ))}
          </div>
        )}
      </Modal>
    </>
  );
}

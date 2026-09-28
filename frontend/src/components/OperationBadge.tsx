import React from 'react';
import * as I from 'lucide-react';

type OpType = 'WEB' | 'DESKTOP' | 'WEB+SYNC' | 'READ_ONLY' | 'PENDING_DESKTOP' | 'OFFLINE';

const CONFIG: Record<OpType, { label: string; icon: any; cls: string }> = {
  WEB:             { label: 'Web',             icon: I.Globe,     cls: 'badge ok'   },
  DESKTOP:         { label: 'Desktop',         icon: I.Monitor,   cls: 'badge info' },
  'WEB+SYNC':      { label: 'Web + Sync',      icon: I.RefreshCw, cls: 'badge'      },
  READ_ONLY:       { label: 'Read Only',       icon: I.Eye,       cls: 'badge'      },
  PENDING_DESKTOP: { label: 'Pending Desktop', icon: I.Clock,     cls: 'badge warn' },
  OFFLINE:         { label: 'Offline',         icon: I.WifiOff,   cls: 'badge'      },
};

export default function OperationBadge({ type, className = '' }: { type: OpType; className?: string }) {
  const cfg = CONFIG[type] || CONFIG.WEB;
  const Icon = cfg.icon;
  return (
    <span className={`${cfg.cls} ${className}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10.5, padding: '2px 7px' }}>
      <Icon size={10} />{cfg.label}
    </span>
  );
}

export type { OpType };

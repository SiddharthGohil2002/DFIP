import { createContext, useCallback, useContext, useEffect, useState, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { useLocation } from 'react-router-dom';
import { Check, Copy, Inbox, X } from 'lucide-react';
import { NAV } from '../app/nav';

type Variant = 'default' | 'primary' | 'danger' | 'ghost';

export function Button({
  variant = 'default',
  size,
  icon,
  busy,
  block,
  children,
  className = '',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: 'sm' | 'lg'; icon?: ReactNode; busy?: boolean; block?: boolean }) {
  const cls = ['btn', variant !== 'default' ? variant : '', size || '', block ? 'block' : '', className].filter(Boolean).join(' ');
  return (
    <button type="button" className={cls} disabled={rest.disabled || busy} {...rest}>
      {busy ? <span className="spinner" /> : icon}
      {children}
    </button>
  );
}

export function Card({ title, subtitle, actions, children, flush, className = '' }: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  flush?: boolean;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-head">
          <div>
            {title && <h3>{title}</h3>}
            {subtitle && <div className="sub">{subtitle}</div>}
          </div>
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      {children !== undefined && <div className={`card-body ${flush ? 'flush' : ''}`}>{children}</div>}
    </section>
  );
}

export function PageHeader({ title, subtitle, eyebrow, actions }: { title: string; subtitle?: ReactNode; eyebrow?: string; actions?: ReactNode }) {
  // The page's icon is the one its sidebar entry uses, so both always match.
  const { pathname } = useLocation();
  const item = NAV.flatMap((g) => g.items).find((i) => i.to !== '/app' && (pathname === i.to || pathname.startsWith(i.to + '/')));
  const Icon = item?.icon;
  return (
    <div className="page-head">
      <div className="page-head-main">
        {Icon && (
          <div className={`page-icon tile-icon ${item?.tone || ''}`} aria-hidden="true">
            <Icon size={20} />
          </div>
        )}
        <div>
          {eyebrow && <div className="eyebrow">{eyebrow}</div>}
          <h1>{title}</h1>
          {subtitle && <p>{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'accent' | 'neutral';

export function Badge({ tone = 'neutral', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge ${tone === 'neutral' ? '' : tone}`} title={title}>
      {children}
    </span>
  );
}

const STATUS_TONES: Record<string, Tone> = {
  VERIFIED: 'ok', COMPLETED: 'ok', ACTIVE: 'ok', OPEN: 'info', IN_PROGRESS: 'accent', ON_HOLD: 'warn',
  RUNNING: 'accent', QUEUED: 'warn', PENDING: 'warn', PENDING_DESKTOP: 'warn', FAILED: 'danger', INTEGRITY_FAILED: 'danger',
  CANCELLED: 'neutral', DELETED: 'danger', SUSPENDED: 'danger', DISABLED: 'neutral', ARCHIVED: 'neutral',
  CRITICAL: 'danger', HIGH: 'warn', MEDIUM: 'accent', LOW: 'info', INFO: 'neutral',
};

export function StatusBadge({ status, label }: { status?: string | null; label?: string }) {
  const s = (status || 'NOT_RUN').toUpperCase();
  return <Badge tone={STATUS_TONES[s] || 'neutral'}>{label || s.replace(/_/g, ' ')}</Badge>;
}

export function Empty({ title, text, icon, action }: { title: string; text?: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon || <Inbox size={20} />}</div>
      <h4>{title}</h4>
      {text && <p>{text}</p>}
      {action}
    </div>
  );
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="empty">
      <span className="spinner lg" />
      <p style={{ marginTop: 12 }}>{label}</p>
    </div>
  );
}

export function Banner({ tone = 'info', children }: { tone?: 'info' | 'ok' | 'warn' | 'danger'; children: ReactNode }) {
  return <div className={`banner ${tone}`}>{children}</div>;
}

export function ErrorBanner({ error }: { error?: string | null }) {
  return error ? <Banner tone="danger">{error}</Banner> : null;
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="field">
      {/* The hint stays outside the label so it is not part of the input's accessible name. */}
      <label>
        <span>{label}</span>
        {children}
      </label>
      {hint && <small className="hint">{hint}</small>}
    </div>
  );
}

export function Modal({ open, title, onClose, children, footer, wide }: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  // Rendered on <body>, so a dialog opened from a table cell does not inherit the cell's alignment or wrapping.
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head">
          <h3>{title}</h3>
          <button className="btn ghost icon-btn" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: { id: T; label: string; count?: number | null }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={`tab ${value === t.id ? 'active' : ''}`} onClick={() => onChange(t.id)}>
          {t.label}
          {t.count !== undefined && t.count !== null && <span className="count">{t.count.toLocaleString()}</span>}
        </button>
      ))}
    </div>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{value ?? '—'}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function ProgressBar({ value }: { value?: number }) {
  return (
    <div className="progress" role="progressbar" aria-valuenow={value || 0} aria-valuemin={0} aria-valuemax={100}>
      <div style={{ width: `${Math.max(0, Math.min(100, value || 0))}%` }} />
    </div>
  );
}

export function Hash({ value, short }: { value?: string | null; short?: number }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="muted">—</span>;
  const copy = () => {
    navigator.clipboard?.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  };
  return (
    <span className={short ? 'hash short' : 'hash'} title={value}>
      {short ? `${value.slice(0, short)}…` : value}
      <button onClick={copy} aria-label="Copy hash" title="Copy">
        {copied ? <Check size={13} /> : <Copy size={13} />}
      </button>
    </span>
  );
}

export function Pager({ skip, limit, total, onChange }: { skip: number; limit: number; total: number; onChange: (skip: number) => void }) {
  if (total <= limit) return null;
  return (
    <div className="pager">
      <Button size="sm" disabled={skip === 0} onClick={() => onChange(Math.max(0, skip - limit))}>
        ← Previous
      </Button>
      <span>
        {(skip + 1).toLocaleString()}–{Math.min(skip + limit, total).toLocaleString()} of {total.toLocaleString()}
      </span>
      <Button size="sm" disabled={skip + limit >= total} onClick={() => onChange(skip + limit)}>
        Next →
      </Button>
    </div>
  );
}

/* ---------- toasts ---------- */
type Toast = { id: number; tone: 'ok' | 'danger' | 'info'; text: string };
const ToastContext = createContext<(text: string, tone?: Toast['tone']) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: Toast['tone'] = 'info') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, tone, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === 'danger' ? 7000 : 4000);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.tone === 'info' ? '' : t.tone}`}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

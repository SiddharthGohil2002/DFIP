import { useState } from 'react';
import { FileDown } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { downloadExport } from '../lib/api';
import { Button, useToast } from './index';

/** The view a table loads, as the export's `resource`: every row the filters select, not only the page shown. */
export function exportResource(path: string): string {
  const [p, q = ''] = path.split('?');
  const qs = new URLSearchParams(q);
  qs.delete('skip');
  qs.delete('limit');
  return `/api${p}${qs.toString() ? `?${qs}` : ''}`;
}

/** CSV and XLSX downloads of a table: `path` is the API path the table loads (paging is dropped). Shown to users who may export. */
export function ExportButton({ path, what = 'table' }: { path: string | null; what?: string }) {
  const { can } = useAuth();
  const toast = useToast();
  const [busy, setBusy] = useState<'csv' | 'xlsx' | null>(null);
  if (!path || !can('REPORT_EXPORT')) return null;

  async function run(format: 'csv' | 'xlsx') {
    setBusy(format);
    try {
      const r = await downloadExport(`/exports/table?${new URLSearchParams({ resource: exportResource(path!), format })}`);
      const rows = r.rows === null ? 'All rows' : `${r.rows.toLocaleString()} row${r.rows === 1 ? '' : 's'}`;
      toast(`${rows} exported${r.truncated ? ' (the first 100,000 only)' : ''}${r.sha256 ? `; SHA-256 ${r.sha256.slice(0, 16)}…` : ''}`, r.truncated ? 'info' : 'ok');
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setBusy(null);
    }
  }

  return (
    <span className="row export-group" role="group" aria-label={`Export this ${what}`}>
      <Button size="sm" variant="ghost" icon={<FileDown size={13} />} busy={busy === 'csv'} disabled={!!busy} onClick={() => run('csv')}
        title={`Every row of this ${what} as CSV (opens in Excel)`}>CSV</Button>
      <Button size="sm" variant="ghost" busy={busy === 'xlsx'} disabled={!!busy} onClick={() => run('xlsx')}
        title={`Every row of this ${what} as an Excel workbook`}>XLSX</Button>
    </span>
  );
}

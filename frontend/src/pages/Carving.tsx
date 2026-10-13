import { useEffect, useState } from 'react';
import { Download, Layers } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { downloadFile, post } from '../lib/api';
import { formatBytes } from '../lib/format';
import { useApi } from '../lib/useApi';
import { TagButton } from '../lib/tags';
import { ViewButton } from '../ui/FileViewer';
import { ExportButton } from '../ui/ExportButton';
import type { Artifact } from '../lib/types';
import { Banner, Button, Card, Empty, Field, Hash, Loading, PageHeader, Pager, useToast } from '../ui';

const LIMIT = 100;

export function CarvingPage() {
  const { caseId, overview, reloadOverview } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const evidence = (overview?.evidence || []).filter((e) => !e.demo);
  const [evidenceId, setEvidenceId] = useState('');
  const [engine, setEngine] = useState('photorec');
  const [running, setRunning] = useState(false);
  const [last, setLast] = useState<any>(null);
  const [ext, setExt] = useState('');
  const [skip, setSkip] = useState(0);
  useEffect(() => {
    if (!evidenceId && evidence[0]) setEvidenceId(evidence[0].evidence_id);
  }, [evidence, evidenceId]);

  const path = `/forensics/artifacts?case_id=${encodeURIComponent(caseId)}&artifact_type=CARVED_FILE`;
  const carved = useApi<{ data: Artifact[] }>(path);
  const all = carved.data?.data || [];
  const exts = Array.from(new Set(all.map((a) => (a.filename || '').split('.').pop()?.toLowerCase() || ''))).filter(Boolean).sort();
  const rows = ext ? all.filter((a) => a.filename?.toLowerCase().endsWith(`.${ext}`)) : all;

  async function carve() {
    setRunning(true);
    setLast(null);
    try {
      const r = await post<any>(`/forensics/evidence/${encodeURIComponent(evidenceId)}/carve?engine=${engine}`);
      setLast(r);
      toast(r.status === 'COMPLETED' ? `${r.engine}: ${r.files_recovered} files carved` : `${r.engine}: ${r.status}`, r.status === 'COMPLETED' ? 'ok' : 'danger');
      carved.reload();
      reloadOverview();
    } catch (e: any) {
      toast(e.message, 'danger');
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="stack">
      <PageHeader
        title="File carving"
        subtitle="Recovers files from raw disk space by their content signatures, including data whose filesystem records are gone. Complements deleted-file recovery, which relies on filesystem metadata."
      />
      {can('ANALYSIS_RUN') && (
        <Card title="Run a carver">
          {!evidence.length ? (
            <Empty title="No evidence" text="Upload a disk image first." />
          ) : (
            <div className="stack" style={{ gap: 12 }}>
              <div className="grid cols-3">
                <Field label="Evidence">
                  <select className="select" value={evidenceId} onChange={(e) => setEvidenceId(e.target.value)}>
                    {evidence.map((e) => <option key={e.evidence_id} value={e.evidence_id}>{e.evidence_id} — {e.filename}</option>)}
                  </select>
                </Field>
                <Field label="Engine" hint={engine === 'photorec' ? 'All PhotoRec signatures except the noisy dovecot one.' : 'Signatures in backend/rules/scalpel.conf (images, documents, archives, SQLite).'}>
                  <select className="select" value={engine} onChange={(e) => setEngine(e.target.value)}>
                    <option value="photorec">PhotoRec</option>
                    <option value="scalpel">Scalpel</option>
                  </select>
                </Field>
                <div style={{ alignSelf: 'end' }}>
                  <Button variant="primary" icon={<Layers size={15} />} busy={running} disabled={!evidenceId} onClick={carve}>Start carving</Button>
                </div>
              </div>
              {running && <Banner tone="info">Carving scans the whole image; this can take many minutes for large images. Keep this page open.</Banner>}
              {last && last.status !== 'COMPLETED' && <Banner tone="danger">{last.engine}: {last.status} {last.stderr}</Banner>}
            </div>
          )}
        </Card>
      )}

      <Card
        title="Carved files"
        subtitle={`${all.length.toLocaleString()} files, each hashed and registered as an artifact`}
        actions={<>
          {exts.length > 1 && (
            <select className="select sm" style={{ width: 130 }} value={ext} onChange={(e) => { setExt(e.target.value); setSkip(0); }} aria-label="File type">
              <option value="">All types</option>
              {exts.map((x) => <option key={x} value={x}>.{x}</option>)}
            </select>
          )}
          {all.length > 0 && <ExportButton path={path} what="list of carved files" />}
        </>}
        flush
      >
        {carved.loading && !carved.data ? <Loading /> : !rows.length ? (
          <Empty title="No carved files" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>File</th><th>Size</th><th>SHA-256</th><th>Engine</th><th>Evidence</th><th /></tr></thead>
              <tbody>
                {rows.slice(skip, skip + LIMIT).map((a) => (
                  <tr key={a._id}>
                    <td className="mono small">{a.filename}</td>
                    <td className="small nowrap">{formatBytes(a.size)}</td>
                    <td><Hash value={a.sha256} short={16} /></td>
                    <td className="small">{(a.source || '').replace('FILE_CARVING_', '')}</td>
                    <td className="mono small">{a.evidence_id}</td>
                    <td className="nowrap right">
                      <TagButton type="ARTIFACT" id={a.artifact_id} title={a.filename} />{' '}
                      {a.artifact_id && <ViewButton source={{ kind: 'artifact', artifactId: a.artifact_id, name: a.filename || 'Carved file' }} />}{' '}
                      {a.artifact_id && (
                        <Button size="sm" icon={<Download size={13} />} onClick={() => downloadFile(`/forensics/artifacts/${a.artifact_id}/download`, a.filename || 'carved.bin').catch((e) => toast(e.message, 'danger'))}>
                          Download
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pager skip={skip} limit={LIMIT} total={rows.length} onChange={setSkip} />
      </Card>
    </div>
  );
}

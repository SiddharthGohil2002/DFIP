import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api } from './api';
import type { CaseItem, CaseOverview } from './types';

const ACTIVE_CASE = 'dfip_active_case';
const RUNNING = new Set(['QUEUED', 'RUNNING']);

interface CaseState {
  cases: CaseItem[];
  casesLoaded: boolean;
  caseId: string;
  activeCase: CaseItem | null;
  overview: CaseOverview | null;
  overviewError: string;
  setCaseId: (id: string) => void;
  reloadCases: () => Promise<void>;
  reloadOverview: () => void;
}

const CaseContext = createContext<CaseState | null>(null);

/** The case every workspace page works on, persisted per browser/workstation. */
export function CaseProvider({ children }: { children: ReactNode }) {
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [casesLoaded, setCasesLoaded] = useState(false);
  const [caseId, setCaseIdState] = useState(() => localStorage.getItem(ACTIVE_CASE) || '');
  const [overview, setOverview] = useState<CaseOverview | null>(null);
  const [overviewError, setOverviewError] = useState('');

  const setCaseId = useCallback((id: string) => {
    setCaseIdState(id);
    if (id) localStorage.setItem(ACTIVE_CASE, id);
    else localStorage.removeItem(ACTIVE_CASE);
  }, []);

  const reloadCases = useCallback(async () => {
    const r = await api<{ data: CaseItem[] }>('/cases').catch(() => ({ data: [] as CaseItem[] }));
    setCases(r.data);
    setCasesLoaded(true);
    setCaseIdState((current) => {
      const next = r.data.some((c) => c.case_id === current) ? current : r.data[0]?.case_id || '';
      if (next) localStorage.setItem(ACTIVE_CASE, next);
      return next;
    });
  }, []);

  useEffect(() => {
    reloadCases();
  }, [reloadCases]);

  const reloadOverview = useCallback(() => {
    if (!caseId) {
      setOverview(null);
      return;
    }
    api<CaseOverview>(`/cases/${encodeURIComponent(caseId)}/overview`)
      .then((o) => {
        setOverview(o);
        setOverviewError('');
      })
      .catch((e) => setOverviewError(e.message));
  }, [caseId]);

  useEffect(() => {
    setOverview(null);
    reloadOverview();
  }, [reloadOverview]);

  // While an analysis job is queued or running, keep the overview (counts, progress) fresh.
  const busy =
    !!overview &&
    (overview.jobs.some((j) => RUNNING.has(j.status)) || overview.evidence.some((e) => e.analysis_status === 'RUNNING'));
  useEffect(() => {
    if (!busy) return;
    const t = setInterval(reloadOverview, 2000);
    return () => clearInterval(t);
  }, [busy, reloadOverview]);

  const activeCase = cases.find((c) => c.case_id === caseId) || overview?.case || null;
  const value = useMemo(
    () => ({ cases, casesLoaded, caseId, activeCase, overview, overviewError, setCaseId, reloadCases, reloadOverview }),
    [cases, casesLoaded, caseId, activeCase, overview, overviewError, setCaseId, reloadCases, reloadOverview],
  );
  return <CaseContext.Provider value={value}>{children}</CaseContext.Provider>;
}

export function useCase(): CaseState {
  const ctx = useContext(CaseContext);
  if (!ctx) throw new Error('useCase must be used inside CaseProvider');
  return ctx;
}

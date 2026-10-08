import { useState, type ReactNode } from 'react';
import { BrowserRouter, HashRouter, Navigate, Route, Routes } from 'react-router-dom';
import { FolderOpen } from 'lucide-react';
import { AuthProvider, useAuth } from '../lib/auth';
import { CaseProvider, useCase } from '../lib/caseContext';
import { TimeModeContext, type TimeMode } from '../lib/format';
import { IS_DESKTOP } from '../lib/platform';
import { Empty, Loading, ToastProvider } from '../ui';
import { Shell } from './Shell';
import { LoginPage } from '../pages/Login';
import { HomePage } from '../pages/Home';
import { CasesPage } from '../pages/Cases';
import { EvidencePage } from '../pages/Evidence';
import { EvidenceDetailPage } from '../pages/EvidenceDetail';
import { FilesPage } from '../pages/Files';
import { TimelinePage } from '../pages/Timeline';
import { BrowserPage } from '../pages/Browser';
import { UsbPage } from '../pages/Usb';
import { IndicatorsPage } from '../pages/Indicators';
import { CarvingPage } from '../pages/Carving';
import { SearchPage } from '../pages/Search';
import { FindingsPage } from '../pages/Findings';
import { ReportsPage } from '../pages/Reports';
import { CustodyPage } from '../pages/Custody';
import { UsersPage } from '../pages/admin/Users';
import { AuditPage } from '../pages/admin/Audit';
import { SystemPage } from '../pages/admin/System';
import { Landing } from '../site/Landing';

// The desktop shell loads files from its own protocol, so it uses hash routing.
const Router = IS_DESKTOP ? HashRouter : BrowserRouter;

export default function App() {
  const [mode, setModeState] = useState<TimeMode>(() => (localStorage.getItem('dfip_time_mode') === 'local' ? 'local' : 'utc'));
  const setMode = (m: TimeMode) => {
    localStorage.setItem('dfip_time_mode', m);
    setModeState(m);
  };
  return (
    <TimeModeContext.Provider value={{ mode, setMode }}>
      <ToastProvider>
        <AuthProvider>
          <Router>
            <AppRoutes />
          </Router>
        </AuthProvider>
      </ToastProvider>
    </TimeModeContext.Provider>
  );
}

function AppRoutes() {
  const { user, ready } = useAuth();
  if (!ready) {
    return (
      <div className="center-fill">
        <Loading label="Starting DFIP…" />
      </div>
    );
  }
  return (
    <Routes>
      {!IS_DESKTOP && <Route path="/" element={<Landing />} />}
      <Route path="/login" element={user ? <Navigate to="/app" replace /> : <LoginPage />} />
      <Route
        path="/app/*"
        element={
          user ? (
            <CaseProvider>
              <Workspace />
            </CaseProvider>
          ) : (
            <Navigate to="/login" replace />
          )
        }
      />
      <Route path="*" element={<Navigate to={IS_DESKTOP ? (user ? '/app' : '/login') : '/'} replace />} />
    </Routes>
  );
}

/** Pages that work on the active case show a prompt until one exists. */
function NeedsCase({ children }: { children: ReactNode }) {
  const { caseId, casesLoaded } = useCase();
  if (!casesLoaded) return <Loading />;
  if (!caseId) {
    return (
      <Empty
        icon={<FolderOpen size={20} />}
        title="No case selected"
        text="Create a case (New case, top bar) or ask a case owner to add you to one."
      />
    );
  }
  return <>{children}</>;
}

function Workspace() {
  const c = (el: ReactNode) => <NeedsCase>{el}</NeedsCase>;
  return (
    <Shell>
      <Routes>
        <Route index element={<HomePage />} />
        <Route path="cases" element={<CasesPage />} />
        <Route path="evidence" element={c(<EvidencePage />)} />
        <Route path="evidence/:id" element={<EvidenceDetailPage />} />
        <Route path="files" element={c(<FilesPage />)} />
        <Route path="timeline" element={c(<TimelinePage />)} />
        <Route path="browser" element={c(<BrowserPage />)} />
        <Route path="usb" element={c(<UsbPage />)} />
        <Route path="indicators" element={c(<IndicatorsPage />)} />
        <Route path="carving" element={c(<CarvingPage />)} />
        <Route path="search" element={c(<SearchPage />)} />
        <Route path="findings" element={c(<FindingsPage />)} />
        <Route path="reports" element={c(<ReportsPage />)} />
        <Route path="custody" element={c(<CustodyPage />)} />
        <Route path="admin/users" element={<UsersPage />} />
        <Route path="admin/audit" element={<AuditPage />} />
        <Route path="admin/system" element={<SystemPage />} />
        <Route path="*" element={<Navigate to="/app" replace />} />
      </Routes>
    </Shell>
  );
}

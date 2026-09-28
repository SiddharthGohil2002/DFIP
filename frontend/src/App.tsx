import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useContext } from 'react';
import { AuthContext } from './main';
import { AppLayout } from './components/Layout';
import { Landing, Login, InfoPage, DownloadPage, FunctionsPage } from './pages/Public';
import { Dashboard, Cases, Evidence, EvidenceVerify, Timeline, Module, Reports, Findings, Chain, Audit, Notifications, AdminUsers, AdminRoles, AdminSecurity, AdminSettings, Jobs, Tooling, ThreatIntel, Carving } from './pages/AppPages';
import DesktopOperations from './pages/DesktopOperations';
import * as I from 'lucide-react';

function Protected({ children, admin = false }: { children: any; admin?: boolean }) {
  const { user } = useContext(AuthContext);
  const loc = useLocation();
  if (!user) return <Navigate to="/login" replace />;
  if (admin && user.role !== 'ADMIN') return <Navigate to="/investigator/dashboard" replace />;
  if (!admin && user.role === 'ADMIN' && loc.pathname.startsWith('/investigator')) return <Navigate to="/admin/dashboard" replace />;
  return <AppLayout admin={admin}>{children}</AppLayout>;
}

const modules: any[] = [
  ['acquisition', 'Acquisition', I.Upload, 'Secure evidence acquisition workflow.'],
  ['browser', 'Browser Forensics', I.Globe, 'Review browser artifacts available from analyzed evidence.'],
  ['usb', 'USB Forensics', I.Usb, 'Review removable-device activity.'],
  ['email', 'Email Forensics', I.Mail, 'Inspect email metadata and attachments.'],
  ['network', 'Network Forensics', I.Network, 'Review network artifacts and events.'],
  ['malware', 'Malware Analysis', I.Bug, 'Review static indicators and malware artifacts.'],
  ['patterns', 'Patterns', I.Activity, 'Rule-based activity pattern analysis.'],
  ['anomalies', 'Anomalies', I.BrainCircuit, 'Review potentially anomalous activity.'],
  ['ai-assistant', 'AI Assistant', I.Sparkles, 'Evidence-grounded investigation assistance.'],
];

function Investigator() {
  return (
    <Routes>
      <Route path="dashboard" element={<Dashboard />} />
      <Route path="cases" element={<Cases />} />
      <Route path="evidence" element={<Evidence />} />
      <Route path="evidence/:id" element={<EvidenceVerify />} />
      <Route path="timeline" element={<Timeline />} />
      <Route path="file-recovery" element={<Module name="File Recovery" icon={I.FileSearch} description="Inspect filesystem artifacts and recovery results without modifying original evidence." />} />
      {modules.map(([p, n, Icon, d]) => <Route key={p} path={p} element={<Module name={n} icon={Icon} description={d} />} />)}
      <Route path="findings" element={<Findings />} />
      <Route path="reports" element={<Reports />} />
      <Route path="chain-of-custody" element={<Chain />} />
      <Route path="audit" element={<Audit />} />
      <Route path="notifications" element={<Notifications />} />
      <Route path="jobs" element={<Jobs />} />
      <Route path="tooling" element={<Tooling />} />
      <Route path="threat-intel" element={<ThreatIntel />} />
      <Route path="carving" element={<Carving />} />
      <Route path="desktop-operations" element={<DesktopOperations />} />
      <Route path="functions" element={<FunctionsPage />} />
      <Route path="settings" element={<AdminSettings />} />
      <Route path="*" element={<Navigate to="dashboard" replace />} />
    </Routes>
  );
}

function Admin() {
  return (
    <Routes>
      <Route path="dashboard" element={<Dashboard admin />} />
      <Route path="users" element={<AdminUsers />} />
      <Route path="roles" element={<AdminRoles />} />
      <Route path="permissions" element={<AdminRoles />} />
      <Route path="cases" element={<Cases />} />
      <Route path="evidence" element={<Evidence />} />
      <Route path="security" element={<AdminSecurity />} />
      <Route path="audit" element={<Audit />} />
      <Route path="reports" element={<Reports />} />
      <Route path="notifications" element={<Notifications />} />
      <Route path="jobs" element={<Jobs />} />
      <Route path="tooling" element={<Tooling />} />
      <Route path="settings" element={<AdminSettings />} />
      <Route path="*" element={<Navigate to="dashboard" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/login" element={<Login />} />
      <Route path="/functions" element={<FunctionsPage />} />
      <Route path="/features" element={<FunctionsPage />} />
      <Route path="/download" element={<DownloadPage />} />
      <Route path="/about" element={<InfoPage page="about" />} />
      <Route path="/technology" element={<InfoPage page="technology" />} />
      <Route path="/security" element={<InfoPage page="security" />} />
      <Route path="/investigator/*" element={<Protected><Investigator /></Protected>} />
      <Route path="/admin/*" element={<Protected admin><Admin /></Protected>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

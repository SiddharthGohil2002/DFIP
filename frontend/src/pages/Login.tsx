import { useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle2, Clock, FileText, FileX, Globe, Settings2, ShieldCheck, Usb, UserPlus } from 'lucide-react';
import { useAuth } from '../lib/auth';
import { health, post, serverUrl, setServerUrl, type Health } from '../lib/api';
import { IS_DESKTOP } from '../lib/platform';
import { Banner, Button, Field } from '../ui';
import { Logo } from '../app/Logo';
import { DesktopDownload } from '../app/DesktopDownload';

const DEMO_ACCOUNTS = [
  { email: 'investigator@dfip.local', label: 'Investigator', note: 'Full case work' },
  { email: 'analyst@dfip.local', label: 'Analyst', note: 'Analysis, findings' },
  { email: 'viewer@dfip.local', label: 'Viewer', note: 'Read only' },
  { email: 'admin@dfip.local', label: 'Administrator', note: 'Everything + users' },
];
const DEMO_PASSWORD = 'DemoPassword!2026';
const MIN_PASSWORD = 12;

type Mode = 'signin' | 'register';

export function LoginPage() {
  const { login, signedOut } = useAuth();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const requested: Mode = params.get('mode') === 'register' ? 'register' : 'signin';
  const setMode = (m: Mode) => {
    setError('');
    setParams(m === 'register' ? { mode: 'register' } : {}, { replace: true });
  };

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState(signedOut ? 'You have signed out.' : '');
  const [busy, setBusy] = useState(false);
  const [server, setServer] = useState(serverUrl());
  const [showServer, setShowServer] = useState(false);
  const [status, setStatus] = useState<{ state: 'checking' | 'ok' | 'down'; info?: Health; error?: string }>({ state: 'checking' });

  const check = (base: string) => {
    setStatus({ state: 'checking' });
    health(base)
      .then((info) => setStatus({ state: info.status === 'ok' ? 'ok' : 'down', info, error: info.status === 'ok' ? undefined : 'Database unavailable' }))
      .catch((e) => setStatus({ state: 'down', error: e.name === 'AbortError' ? 'No response' : e.message }));
  };

  useEffect(() => {
    check(serverUrl());
  }, []);

  const registration = status.info?.registration_mode;
  const canRegister = registration === 'approval' || registration === 'open';
  // A link to ?mode=register falls back to sign-in on servers with registration turned off.
  const mode: Mode = requested === 'register' && (!status.info || canRegister) ? 'register' : 'signin';

  async function signIn(e: FormEvent) {
    e.preventDefault();
    setError('');
    setNotice('');
    setBusy(true);
    try {
      await login(email, password);
      navigate('/app', { replace: true });
    } catch (err: any) {
      setError(err.status === 401 ? 'Email or password is incorrect.' : err.message);
    } finally {
      setBusy(false);
    }
  }

  const passwordProblem =
    password && password.length < MIN_PASSWORD ? `Use at least ${MIN_PASSWORD} characters.` : confirm && confirm !== password ? 'The passwords do not match.' : '';

  async function register(e: FormEvent) {
    e.preventDefault();
    setError('');
    setNotice('');
    if (passwordProblem || password !== confirm) {
      setError(passwordProblem || 'The passwords do not match.');
      return;
    }
    setBusy(true);
    try {
      const r = await post<{ status: string; message: string }>('/auth/register', { name: name.trim(), email: email.trim(), password });
      if (r.status === 'ACTIVE') {
        await login(email, password);
        navigate('/app', { replace: true });
        return;
      }
      setNotice(r.message);
      setPassword('');
      setConfirm('');
      setMode('signin');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function saveServer() {
    setServerUrl(server);
    setServer(serverUrl());
    check(serverUrl());
  }

  return (
    <div className="login-page">
      <div className="login-art">
        <Logo />
        <div>
          <h1>Analyze disk images and investigate cybercrime evidence.</h1>
          <p>Every image is hashed on arrival, stored read-only and re-verified before each analysis. Every action is recorded in a tamper-evident audit chain.</p>
          <ul>
            <li><FileX size={17} /> Deleted file recovery with Sleuth Kit</li>
            <li><Clock size={17} /> Timeline analysis of file, browser and USB activity</li>
            <li><Globe size={17} /> Browser history and downloads</li>
            <li><Usb size={17} /> USB device detection from the Windows registry</li>
            <li><FileText size={17} /> Hash-sealed PDF evidence reports</li>
          </ul>
        </div>
        <div className="small" style={{ color: '#7d8ba3' }}>
          {IS_DESKTOP ? 'DFIP Investigator desktop' : <Link to="/" style={{ color: '#9fb6e0' }}>← Back to the DFIP website</Link>}
        </div>
      </div>

      <div className="login-panel">
        <div className="login-box">
          <div>
            <h2>{mode === 'register' ? 'Create your account' : 'Sign in'}</h2>
            <p className="muted mt-0" style={{ marginTop: 4 }}>
              {mode === 'register'
                ? registration === 'approval'
                  ? 'An administrator approves new accounts before they can sign in.'
                  : 'Your account is ready as soon as it is created.'
                : 'Sign in with your DFIP account to continue.'}
            </p>
          </div>

          {canRegister && (
            <div className="segmented" role="tablist" aria-label="Sign in or create account">
              <button type="button" role="tab" aria-selected={mode === 'signin'} className={mode === 'signin' ? 'active' : ''} onClick={() => setMode('signin')}>
                Sign in
              </button>
              <button type="button" role="tab" aria-selected={mode === 'register'} className={mode === 'register' ? 'active' : ''} onClick={() => setMode('register')}>
                Create account
              </button>
            </div>
          )}

          <div className="row small">
            <span className={`dot ${status.state === 'ok' ? 'ok' : status.state === 'down' ? 'danger' : 'warn'}`} />
            {status.state === 'checking' && <span className="muted">Connecting to server…</span>}
            {status.state === 'ok' && <span className="muted">Server online{status.info?.version ? ` · v${status.info.version}` : ''}</span>}
            {status.state === 'down' && <span style={{ color: 'var(--danger)' }}>Server unreachable ({status.error})</span>}
            {IS_DESKTOP && (
              <button type="button" className="btn ghost sm" style={{ marginLeft: 'auto' }} onClick={() => setShowServer((s) => !s)}>
                <Settings2 size={14} /> Server
              </button>
            )}
          </div>

          {IS_DESKTOP && showServer && (
            <div className="card" style={{ padding: 14, display: 'grid', gap: 10 }}>
              <Field label="DFIP server address" hint="The address of your DFIP server, e.g. http://localhost:8000 or https://dfip.example.org">
                <input className="input" value={server} onChange={(e) => setServer(e.target.value)} placeholder="http://localhost:8000" />
              </Field>
              <Button onClick={saveServer} icon={<CheckCircle2 size={15} />}>Save and test connection</Button>
            </div>
          )}

          {notice && <Banner tone="ok"><CheckCircle2 size={16} style={{ flex: 'none' }} /> {notice}</Banner>}

          {mode === 'signin' ? (
            <form className="stack" style={{ gap: 14 }} onSubmit={signIn}>
              <Field label="Email">
                <input className="input" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
              </Field>
              <Field label="Password">
                <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </Field>
              {error && <Banner tone="danger">{error}</Banner>}
              <Button type="submit" variant="primary" size="lg" block busy={busy} icon={<ShieldCheck size={17} />}>
                Sign in
              </Button>
              {canRegister && (
                <p className="small muted" style={{ margin: 0, textAlign: 'center' }}>
                  New to DFIP? <button type="button" className="link-btn" onClick={() => setMode('register')}>Create an account</button>
                </p>
              )}
            </form>
          ) : (
            <form className="stack" style={{ gap: 14 }} onSubmit={register}>
              <Field label="Full name">
                <input className="input" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} required minLength={2} autoFocus />
              </Field>
              <Field label="Work email">
                <input className="input" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
              </Field>
              <Field label="Password" hint={`At least ${MIN_PASSWORD} characters.`}>
                <input className="input" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={MIN_PASSWORD} />
              </Field>
              <Field label="Confirm password">
                <input className="input" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
              </Field>
              {(error || (confirm && passwordProblem)) && <Banner tone={error ? 'danger' : 'warn'}>{error || passwordProblem}</Banner>}
              <Button type="submit" variant="primary" size="lg" block busy={busy} disabled={!!passwordProblem || !confirm} icon={<UserPlus size={17} />}>
                Create account
              </Button>
              <p className="small muted" style={{ margin: 0, textAlign: 'center' }}>
                Already have an account? <button type="button" className="link-btn" onClick={() => setMode('signin')}>Sign in</button>
              </p>
            </form>
          )}

          {mode === 'signin' && status.info?.demo_mode && (
            <div>
              <div className="small muted strong" style={{ marginBottom: 8 }}>Demo accounts (demo mode only)</div>
              <div className="demo-accounts">
                {DEMO_ACCOUNTS.map((a) => (
                  <button
                    type="button"
                    key={a.email}
                    onClick={() => {
                      setEmail(a.email);
                      setPassword(DEMO_PASSWORD);
                    }}
                  >
                    <b>{a.label}</b>
                    <span className="muted">{a.note}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          <DesktopDownload variant="login" />
        </div>
      </div>
    </div>
  );
}

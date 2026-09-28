import React,{useEffect,useState} from 'react';import {createRoot} from 'react-dom/client';import {BrowserRouter} from 'react-router-dom';import './index.css';import App from './App';import {api} from './services/api';
export const AuthContext=React.createContext<any>(null);
function Root() {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api('/auth/me')
      .then(setUser)
      .catch(async () => {
        // In desktop workstation, automatically authenticate as investigator
        try {
          const res: any = await api('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email: 'investigator@dfip.local', password: 'DemoPassword!2026' })
          });
          if (res?.access_token) {
            localStorage.setItem('dfip_token', res.access_token);
            if (res.refresh_token) localStorage.setItem('dfip_refresh', res.refresh_token);
            setUser(res.user);
          }
        } catch {
          // Air-gapped fallback offline investigator
          setUser({
            _id: 'desktop-offline-investigator',
            name: 'Workstation Investigator',
            email: 'investigator@dfip.local',
            role: 'INVESTIGATOR',
            status: 'ACTIVE'
          });
        }
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="boot"><div className="boot-orb"/><b style={{ color: 'var(--red)' }}>DFIP</b><span>Initializing forensic workstation…</span></div>;
  return <AuthContext.Provider value={{ user, setUser }}><App/></AuthContext.Provider>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><Root/></BrowserRouter></React.StrictMode>);

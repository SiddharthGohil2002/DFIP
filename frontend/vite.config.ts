import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';

// One UI, two targets:
//   web     (default): public website + login + workspace, served by nginx      -> dist/
//   desktop (--mode desktop): login + workspace only, loaded by the Tauri shell -> dist-desktop/
// The target reaches the code as import.meta.env.VITE_TARGET (see .env.desktop).

/** Desktop builds never show the public website, so swap it for an empty module and keep its screenshots out of the app. */
const withoutWebsite = (): Plugin => ({
  name: 'dfip-without-website',
  enforce: 'pre',
  resolveId: (id) => (id.endsWith('/site/Landing') ? '\0dfip-landing-stub' : null),
  load: (id) => (id === '\0dfip-landing-stub' ? 'export const Landing = () => null;' : null),
});

export default defineConfig(({ mode }) => {
  const desktop = mode === 'desktop';
  const backend = 'http://127.0.0.1:8000';
  return {
    plugins: desktop ? [react(), withoutWebsite()] : [react()],
    base: desktop ? './' : '/',
    build: { outDir: desktop ? 'dist-desktop' : 'dist', emptyOutDir: true },
    server: {
      port: desktop ? 1420 : 5173,
      strictPort: desktop,
      host: '127.0.0.1',
      proxy: desktop
        ? undefined
        : {
            '/api': { target: backend, changeOrigin: true },
            '/health': { target: backend, changeOrigin: true },
          },
    },
    clearScreen: false,
  };
});

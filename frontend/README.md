# DFIP UI

One React + TypeScript + Vite codebase for both the web portal and the desktop app.

| Command | Result |
|---|---|
| `npm run dev` | Web portal on http://127.0.0.1:5173 (proxies `/api` and `/health` to the API on port 8000) |
| `npm run dev:desktop` | Desktop UI in a browser on http://127.0.0.1:1420 (server set on the sign-in page) |
| `npm run build` | Web build in `dist/` (served by nginx, see `Dockerfile`) |
| `npm run build:desktop` | Desktop build in `dist-desktop/` (loaded by the Tauri shell in `../desktop`) |

The target comes from `import.meta.env.VITE_TARGET` (`.env.desktop` sets it for `--mode desktop`).

Layout:

- `src/lib/` — API client, auth, active case, platform (web vs desktop, native commands), formatting
- `src/ui/` — shared components
- `src/app/` — routing, workspace shell, navigation (`nav.ts` drives both the sidebar and the case desktop tiles)
- `src/pages/` — one file per workspace page; `pages/admin/` for administration
- `src/site/` — public website (web build only)

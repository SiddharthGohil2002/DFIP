# DFIP Public Website

DFIP's public marketing/informational website is served by the same Vite/React
app as the authenticated web console (`frontend/`), split by route. This is
intentional — one deployable frontend, one nginx container, no separate
website codebase to keep in sync.

Public (unauthenticated) routes:
- `/` — landing page
- `/download` — Windows desktop download center
- `/features`
- `/technology`
- `/security`
- `/about`
- `/login` — entry point into the authenticated web console

DFIP currently ships two products: the **Windows desktop investigator app**
(`desktop/`) and the **web console** (this frontend, both public site and
authenticated app). There is no separate mobile app or macOS/Linux desktop
build at this time.

The download center deliberately reports the Windows installer as
**COMING SOON** rather than exposing a fake download link. Once a signed
build pipeline (see `desktop/scripts/build-windows.ps1`) produces a real
installer with a SHA-256 checksum, wire `DFIP_DOWNLOAD_WINDOWS_URL` and the
release manifest, then flip the status in `frontend/src/pages/Public.tsx`.

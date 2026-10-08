# DFIP public website

The website is part of the web build of the shared UI (`frontend/src/site/Landing.tsx`), served by the same nginx container as the workspace. It is a single page at `/` with sections for the five analysis features, the investigation workflow, evidence-integrity safeguards and the desktop app, plus a link to `/login`.

The Desktop app section lists installers only when real builds exist in the server's `storage/downloads` (see `desktop/INSTALL.md`, `-Publish`); otherwise it says none has been published. The desktop build of the UI does not include the website.

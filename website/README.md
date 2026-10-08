# DFIP public website

The website is part of the web build of the shared UI (`frontend/src/site/`), served by the same nginx container as the workspace. It is a single page at `/`:

- hero with the product screenshot, "Get started" (opens Create account) and "Download for Windows" when an installer is published
- the open-source tools DFIP is built on, and four key facts
- one section per analysis feature (deleted files, timeline, browser history, USB, reports), each with a screenshot
- the six-step investigation workflow, the evidence-integrity safeguards, platforms (web portal and Windows app), FAQ and a closing call to action

`Landing.tsx` holds the content and `site.css` the styles (`.lp-*` classes, using the design tokens from `src/styles.css`). The page works down to phone width with a menu button in place of the navigation links.

## Screenshots

The images in `frontend/src/site/assets/` are real screenshots of the workspace, taken at 1440×900 with a 2× pixel ratio from a sample case built from `storage/test-images/dfip-test-disk.dd`, and saved as WebP. The report image is the top of page 1 of that case's PDF report. `frontend/public/og-image.png` (1200×630) is the link preview image; some sites (LinkedIn, Facebook) only show it when `og:image` in `frontend/index.html` is an absolute URL, so set it to your public address when you deploy. Retake them after visible UI changes, so the website shows the product as it is.

## Desktop downloads

The Platforms section and the hero button list installers only when real builds exist in the server's `storage/downloads` (see `desktop/INSTALL.md`, `-Publish`, or `sh desktop/scripts/build-windows-docker.sh`), with the file name, size and SHA-256 computed from the file. Otherwise the section says none has been published.

The desktop build of the UI does not include the website or its images (`vite.config.ts` swaps `site/Landing` for an empty module in desktop mode).

"""Builds docs/user-guide.html from docs/USER_GUIDE.md, so the web page and the Markdown guide always say the same.

The page is self-contained (styles inline, no scripts or fonts from the internet) and shows the screenshots in
docs/guide/images/ by relative path, so it works when opened straight from the folder.

From the repository root:

    docker run --rm -v "${PWD}:/repo" -w /repo python:3.11-slim sh -c "pip install -q markdown==3.7 && python scripts/docs/build_user_guide.py"
"""
import html
import re
from pathlib import Path

import markdown

DOCS = Path(__file__).resolve().parents[2] / 'docs'
SOURCE, TARGET = DOCS / 'USER_GUIDE.md', DOCS / 'user-guide.html'
# The Markdown's pointer to this page, and its own contents list (the page has a sidebar instead).
SELF_LINK = ' The same guide is available as a web page: open [user-guide.html](user-guide.html) in a browser.'

STYLE = """
:root { --bg: #f6f8fb; --surface: #ffffff; --text: #0f172a; --muted: #5b6b82; --border: #dde3ea; --accent: #1d4ed8;
  --accent-soft: #e8efff; --code: #eef2f7; --shadow: 0 1px 2px rgba(15, 23, 42, .06), 0 8px 24px rgba(15, 23, 42, .06); }
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) { --bg: #0b1220; --surface: #111a2e; --text: #e5ecf6; --muted: #9aaac2; --border: #22314d;
    --accent: #7aa2ff; --accent-soft: #1a2747; --code: #17223a; --shadow: none; }
}
:root[data-theme="dark"] { --bg: #0b1220; --surface: #111a2e; --text: #e5ecf6; --muted: #9aaac2; --border: #22314d;
  --accent: #7aa2ff; --accent-soft: #1a2747; --code: #17223a; --shadow: none; }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 16px; }
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
body { margin: 0; background: var(--bg); color: var(--text); font: 15.5px/1.65 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
strong, b { font-weight: 700; }
a { color: var(--accent); }
.layout { display: grid; grid-template-columns: 290px minmax(0, 1fr); min-height: 100vh; }
nav.toc { position: sticky; top: 0; height: 100vh; overflow-y: auto; padding: 22px 18px 40px; background: var(--surface);
  border-right: 1px solid var(--border); font-size: 13.5px; }
nav.toc .brand { font-weight: 800; font-size: 17px; margin-bottom: 2px; }
nav.toc .tag { color: var(--muted); font-size: 12.5px; margin-bottom: 16px; }
nav.toc ul { list-style: none; margin: 0; padding: 0; }
nav.toc li { margin: 1px 0; }
nav.toc > ul > li > a { font-weight: 650; }
nav.toc ul ul { padding-left: 12px; margin: 2px 0 8px; border-left: 2px solid var(--border); }
nav.toc a { display: block; padding: 3px 8px; border-radius: 6px; color: var(--text); text-decoration: none; }
nav.toc a:hover { background: var(--accent-soft); color: var(--accent); }
main { padding: 36px 48px 80px; max-width: 980px; }
h1 { font-size: 32px; line-height: 1.2; margin: 0 0 12px; }
h2 { font-size: 24px; margin: 48px 0 12px; padding-top: 12px; border-top: 1px solid var(--border); }
h3 { font-size: 18.5px; margin: 32px 0 8px; }
p, li { max-width: 78ch; }
img { display: block; max-width: 100%; height: auto; margin: 14px 0 20px; border: 1px solid var(--border); border-radius: 10px;
  box-shadow: var(--shadow); background: var(--surface); }
table { border-collapse: collapse; width: 100%; margin: 12px 0 20px; background: var(--surface); font-size: 14px;
  border: 1px solid var(--border); border-radius: 10px; overflow: hidden; display: block; overflow-x: auto; }
th, td { text-align: left; vertical-align: top; padding: 8px 12px; border-bottom: 1px solid var(--border); }
th { background: var(--accent-soft); font-weight: 650; white-space: nowrap; }
tr:last-child td { border-bottom: 0; }
code { font: 13px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; background: var(--code); padding: 1px 5px; border-radius: 5px; }
pre { background: var(--code); padding: 12px 14px; border-radius: 10px; overflow-x: auto; border: 1px solid var(--border); }
pre code { background: none; padding: 0; white-space: pre; }
blockquote { margin: 14px 0; padding: 10px 16px; border-left: 4px solid var(--accent); background: var(--accent-soft); border-radius: 0 10px 10px 0; }
blockquote p { margin: 4px 0; }
hr { border: 0; border-top: 1px solid var(--border); margin: 28px 0; }
.theme { margin: 8px 0 18px; display: flex; gap: 6px; }
.theme button { font: inherit; font-size: 12px; padding: 3px 9px; border-radius: 999px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text); cursor: pointer; }
@media (max-width: 900px) {
  .layout { display: block; }
  nav.toc { position: static; height: auto; max-height: 50vh; border-right: 0; border-bottom: 1px solid var(--border); }
  main { padding: 20px 16px 60px; }
  h1 { font-size: 26px; }
}
@media print {
  nav.toc { display: none; }
  .layout { display: block; }
  main { max-width: none; padding: 0; }
  img { box-shadow: none; break-inside: avoid; }
  h2 { break-before: page; }
}
"""

THEME_SCRIPT = """
document.querySelectorAll('.theme button').forEach(function (b) {
  b.addEventListener('click', function () {
    var t = b.getAttribute('data-set');
    if (t === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('dfip-guide-theme', t); } catch (e) {}
  });
});
try { var s = localStorage.getItem('dfip-guide-theme'); if (s && s !== 'auto') document.documentElement.setAttribute('data-theme', s); } catch (e) {}
"""


def main():
    text = SOURCE.read_text(encoding='utf-8').replace(SELF_LINK, '')
    # The contents list at the top of the Markdown is replaced by the sidebar.
    text = re.sub(r'\n\*\*Contents\*\*\n\n(?:\d+\. \[.*\]\(#.*\)\n)+', '\n', text)
    md = markdown.Markdown(extensions=['tables', 'fenced_code', 'toc', 'sane_lists'], extension_configs={'toc': {'toc_depth': '2-3'}})
    body = md.convert(text)
    title = 'DFIP User Guide'
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="How to use every function of DFIP, the Digital Forensics Investigation Platform, step by step.">
<style>{STYLE}</style>
</head>
<body>
<div class="layout">
<nav class="toc" aria-label="Contents">
<div class="brand">DFIP User Guide</div>
<div class="tag">Digital Forensics Investigation Platform</div>
<div class="theme" aria-label="Colour theme"><button type="button" data-set="auto">Auto</button><button type="button" data-set="light">Light</button><button type="button" data-set="dark">Dark</button></div>
{md.toc}
</nav>
<main>
{body}
</main>
</div>
<script>{THEME_SCRIPT}</script>
</body>
</html>
"""
    TARGET.write_text(page, encoding='utf-8', newline='\n')
    print(f'Wrote {TARGET.relative_to(DOCS.parent)} ({len(page):,} bytes)')


if __name__ == '__main__':
    main()

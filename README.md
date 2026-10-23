# bunnyho1e

Public interface: **https://bunnyho1e.github.io/**

Think like an attacker. Build like an engineer. Automate the rest.

A dark, terminal-inspired static portfolio covering offensive security, practical tooling, curated sources, AI agents, and automation. Selected public work links to [RedTeaming](https://github.com/bunnyho1e/RedTeaming) and [BlueTeaming](https://github.com/bunnyho1e/BlueTeaming). These are source collections with upstream attribution, not claims of authorship of the underlying tools. Catalog counts are a dated 23 October 2026 snapshot.

## Publishing

GitHub Settings → Pages → Deploy from a branch → `main` → `/ (root)`.

The site uses plain HTML, CSS, and JavaScript. No build step, package installation, API key, or backend is required. `.nojekyll` keeps the published files unchanged.

## Files

- `index.html`: content, metadata, and accessible page structure.
- `site.css`: responsive layout and visual styling.
- `site.js`: accessible mobile navigation, keyboard-operated collection tabs, and command copying.
- `*.woff2` and `*-OFL.txt`: self-hosted Google Fonts with their SIL Open Font License notices.
- `404.html`, `robots.txt`, `sitemap.xml`: navigation fallback and crawler metadata.

## Local preview

```bash
python3 -m http.server 8080
```

Open `http://localhost:8080/`. This is a local preview command, not a production server.

## Editing

Edit copy and links in `index.html`. When collection counts change, update both the dated project-card snapshot and the matching entries in `site.js`.

No analytics, trackers, remote JavaScript, cookies, or contact-data collection are included. Font files are served by the site; the page does not contact Google Fonts at runtime.

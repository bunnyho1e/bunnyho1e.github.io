# bunnyho1e

Public interface: **https://bunnyho1e.github.io/**

Think like an attacker. Build like an engineer. Automate the rest.

A dark, terminal-inspired static portfolio covering offensive security, practical tooling, curated sources, AI agents, and automation. Selected public work links to [RedTeaming](https://github.com/bunnyho1e/RedTeaming) and [BlueTeaming](https://github.com/bunnyho1e/BlueTeaming). These are source collections with upstream attribution, not claims of authorship of the underlying tools. Catalog counts are a dated 23 October 2026 snapshot.

## Publishing

GitHub Settings → Pages → **GitHub Actions**. The `Security feed and Pages` workflow deploys on pushes to `main`, manual runs, and approximately hourly at minute 17 UTC. Scheduled runs can be delayed by GitHub.

The site uses plain HTML, CSS, and JavaScript. The page has no package dependencies or API keys. The workflow uses Python standard-library code to fetch public headline metadata, then deploys a static Pages artifact.

## Files

- `index.html`: content, metadata, and accessible page structure.
- `terminal-v2.css`: responsive layout and visual styling.
- `site.js`: accessible mobile navigation, keyboard-operated collection tabs, and command copying.
- `signal-feed.css`, `signal-feed.js`: security news cards, source filters, CVE/topic search, freshness indicators, and published-snapshot refresh.
- `update_news.py`, `test_update_news.py`: bounded feed retrieval, metadata normalization, cached fallback, and parser tests.
- `security-feed.json`: initial public snapshot; scheduled deployments generate a fresh copy without writing commits.
- `.github/workflows/security-feed.yml`: scheduled source refresh and GitHub Pages deployment.
- `*.woff2` and `*-OFL.txt`: self-hosted Google Fonts with their SIL Open Font License notices.
- `404.html`, `robots.txt`, `sitemap.xml`: navigation fallback and crawler metadata.

## Local preview

```bash
python3 update_news.py
python3 -m http.server 8080
```

Open `http://localhost:8080/`. This is a local preview command, not a production server.

## Editing

Edit copy and links in `index.html`. When collection counts change, update both the dated project-card snapshot and the matching entries in `site.js`.

No analytics, trackers, remote JavaScript, cookies, or contact-data collection are included. Font files are served by the site; the page does not contact Google Fonts at runtime.

## Public security feed

- The Hacker News: https://feeds.feedburner.com/TheHackersNews
- Exploit-DB: https://www.exploit-db.com/rss.xml
- CISA KEV: the [official CISA mirror](https://github.com/cisagov/kev-data), linked to the original [catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Aikido Blog: https://www.aikido.dev/blog/rss.xml
- Reddit r/netsec: https://www.reddit.com/r/netsec/new/.rss?limit=25
- DEV Community: https://dev.to/feed (the main feed, including general development topics).
- Wiz Blog: https://www.wiz.io/feed/rss.xml
- SecurityWeek: https://www.securityweek.com/feed/
- BleepingComputer: https://www.bleepingcomputer.com/feed/
- WIRED Security: https://www.wired.com/feed/category/security/latest/rss
- Sophos Blog: https://www.sophos.com/en-us/blog/feed?id=blt6f15f4f7deaf4242
- Check Point Blog: https://blog.checkpoint.com/feed/

r/netsec uses the public Atom feed of new posts; card links open the Reddit discussion. Publication dates use the original post timestamp, with the feed's update time as a fallback.

Only headline metadata, dates, CVE identifiers, and original links are displayed. CISA dates refer to `dateAdded`, not initial vulnerability disclosure. Exploit-DB entries are catalog references. Upstream authors retain ownership of their reporting and tools. No exploit payload is fetched or executed.

The browser reads a same-origin JSON snapshot. It checks for the latest published snapshot every ten minutes while visible; Refresh does the same on demand. It does not contact a public CORS proxy or the news providers from the visitor’s browser. The background workflow fetches the sources approximately hourly, including while the website is closed. It uses pinned official GitHub Actions, read-only source access, and deployment permissions limited to Pages. No PAT is stored and no content-write permission is requested.

If a source is unavailable, its previous records and actual last-success timestamp are retained and marked cached. If no usable current or cached data is available, the deployment fails rather than replacing the working site with an empty feed.

Run the parser checks with `python3 -m unittest test_update_news -v`. The public deployment is assembled from an explicit static-file allowlist; Git data, scripts, tests, and workflow files are excluded from the published artifact.

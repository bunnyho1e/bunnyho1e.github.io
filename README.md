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
- `source-catalog.json`: canonical source names, groups, original links, and optional feed/parser settings. It generates the source selector and directory during the build.
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

The Sources directory contains **41 original sources** in six groups: servers and infrastructure, operating systems, languages and runtimes, frameworks, vulnerability databases, and news and research. It includes every Apache, Windows, Linux, PHP, Python, Node.js, Java, .NET, Go, Rust, Ruby, framework, and vulnerability database link in the requested collection. Existing sources are preserved and CISA KEV is included once.

**33 sources have configured automated collection.** The source selector contains these feeds, grouped by technology. The directory also includes eight reference destinations: all Apache projects, Tomcat, NGINX, OpenSSL, Red Hat, Oracle/Java, OSV, and NVD. These are clearly labelled Reference and do not inflate the synchronized-feed count. Availability is reported separately under Feed status; a configured feed is not a guarantee of a successful current fetch.

Additional automated sources include Apache HTTP Server, Microsoft MSRC, Linux kernel CVE announcements, Ubuntu, Debian, PHP releases, Python security announcements, PyPA database updates, Node.js security releases, .NET security announcements, Go, RustSec, Ruby, Next.js, Django, Spring, Laravel, Symfony, and the GitHub Advisory Database. See `source-catalog.json` for their exact endpoints.

Apache HTTP Server cards use the vendor's public fix release date and retain distinct CVE anchor links. Debian RSS 1.0 dates retain day precision. PHP release cards link to release notes, never downloadable archives. PHP's feed includes release notices, not exclusively security releases. Ruby and Django feeds are filtered for security-related metadata. Symfony cards use dated entries from its dedicated security category. PyPA cards are explicitly labelled database updates; their dates refer to repository changes, not vulnerability disclosure. Go retrieves at most 18 recently modified OSV records with four concurrent detail requests and displays their original publication dates. GitHub advisories exclude withdrawn records and retain original publication dates. .NET entries use the creation date of security-labelled announcement issues.

The source selector and directory are generated from the catalog when assembling the public directory. The checked-in HTML includes the same directory for local preview and no-JavaScript access. Keep its catalog markers when editing the page.

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
- Dark Web Informer: https://darkwebinformer.com/rss/
- SentinelOne Vulnerability Database: https://www.sentinelone.com/vulnerability-database/

SentinelOne uses the public **Latest CVEs** table rather than an RSS feed. Cards show CVE identifiers, technology, and severity/CVSS when provided, with the publication date displayed by SentinelOne. Only the latest table is collected; the separate high-profile and top-score lists are excluded.

r/netsec uses the public Atom feed of new posts; card links open the Reddit discussion. Publication dates use the original post timestamp, with the feed's update time as a fallback.

Entries published within the last 24 hours have a red `NEW` badge and border. CISA uses the KEV date added. Highlighting follows the entry date, not the snapshot refresh time, and updates every minute while the page is visible. Future-dated entries are not marked new.

Only headline metadata, dates, CVE identifiers, and original links are displayed. CISA dates refer to `dateAdded`, not initial vulnerability disclosure. Exploit-DB entries are catalog references. Upstream authors retain ownership of their reporting and tools. No exploit payload is fetched or executed.

The browser reads a same-origin JSON snapshot. It checks for the latest published snapshot every ten minutes while visible; Refresh does the same on demand. It does not contact a public CORS proxy or the news providers from the visitor’s browser. The background workflow fetches the sources approximately hourly, including while the website is closed. It uses pinned official GitHub Actions, read-only source access, and deployment permissions limited to Pages. No PAT is stored and no content-write permission is requested.

If a source is unavailable, its previous records and actual last-success timestamp are retained and marked cached. If no usable current or cached data is available, the deployment fails rather than replacing the working site with an empty feed.

Run the parser checks with `python3 -m unittest test_update_news -v`. The public deployment is assembled from an explicit static-file allowlist; Git data, scripts, tests, and workflow files are excluded from the published artifact.

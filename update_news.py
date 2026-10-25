#!/usr/bin/env python3
"""Collect public headline metadata; never retrieve or execute exploit payloads."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
from html import escape, unescape
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import shutil
import urllib.request
from urllib.parse import urljoin, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 5_000_000
LIMIT = 18
CATALOG = json.loads((ROOT / "source-catalog.json").read_text())
SOURCES = [source for source in CATALOG if source.get("feed")]


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def plain(value, limit=220):
    parser = TextOnly()
    parser.feed(unescape(str(value or "")))
    return " ".join(" ".join(parser.parts).split())[:limit]


def safe_url(value):
    try:
        parts = urlsplit(str(value or "").strip())
        host = (parts.hostname or "").lower()
        if parts.scheme not in {"http", "https"} or parts.username or parts.password:
            return None
        if not host or host == "localhost" or host.endswith((".localhost", ".local")):
            return None
        try:
            if not ipaddress.ip_address(host).is_global:
                return None
        except ValueError:
            pass
        if len(value) > 1800 or any(ord(c) < 32 for c in value):
            return None
        if parts.scheme == "http" and host not in {"thehackernews.com", "www.exploit-db.com", "exploit-db.com", "php.net", "www.php.net"}:
            return None
        fragment = parts.fragment if re.fullmatch(r"CVE-\d{4}-\d{4,10}", parts.fragment) else ""
        return urlunsplit(("https", parts.netloc, parts.path, parts.query, fragment))
    except (TypeError, ValueError):
        return None


def utc_stamp(value=None):
    value = value or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_date(value):
    try:
        result = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return utc_stamp(result)


def fetch_bytes(url):
    request = urllib.request.Request(url, headers={"User-Agent": "bunnyho1e-security-feed/1.0 (+https://bunnyho1e.github.io/)", "Accept": "application/json, application/atom+xml, application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.5"})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Source exceeds the size limit")
    return data


def item(source, title, url, date, **fields):
    title = plain(title)
    url = safe_url(url)
    date = parse_date(date)
    if not title or not url or not date:
        return None
    cves = sorted({c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,10}", title + " " + str(fields.pop("cve_text", "")), re.I)})[:8]
    return {"id": hashlib.sha256((source["id"] + url).encode()).hexdigest()[:20], "source": source["id"], "category": source["category"], "title": title, "url": url, "published_at": date, "cves": [c.upper() for c in cves], **fields}


def parse_rss(data, source):
    """Read headline metadata from RSS 2.0, RSS 1.0/RDF, or Atom feeds."""
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("XML entities are not accepted")
    root = ET.fromstring(data)
    parsed = []
    rdf = "{http://purl.org/rss/1.0/}"
    dc = "{http://purl.org/dc/elements/1.1/}"
    for entry in (root.findall(".//item") + root.findall(".//" + rdf + "item"))[:100]:
        title = entry.findtext("title") or entry.findtext(rdf + "title")
        description = entry.findtext("description") or entry.findtext(rdf + "description") or ""
        if source.get("match") and not re.search(source["match"], str(title) + " " + description, re.I):
            continue
        url = entry.findtext("{http://rssnamespace.org/feedburner/ext/1.0}origLink") or entry.findtext("link") or entry.findtext(rdf + "link")
        date = entry.findtext("pubDate") or entry.findtext(dc + "date")
        record = item(source, title, url, date, date_precision="day" if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(date)) else "time", cve_text=description)
        if record:
            parsed.append(record)
    atom = "{http://www.w3.org/2005/Atom}"
    for entry in root.findall(atom + "entry")[:100]:
        title = entry.findtext(atom + "title")
        description = entry.findtext(atom + "summary") or entry.findtext(atom + "content") or ""
        if source.get("match") and not re.search(source["match"], str(title) + " " + description, re.I):
            continue
        url = next((link.get("href") for link in entry.findall(atom + "link") if link.get("rel", "alternate") == "alternate"), None) or entry.findtext(atom + "id")
        record = item(source, title, url, entry.findtext(atom + "published") or entry.findtext(atom + "updated"), date_precision="time", cve_text=description)
        if record:
            parsed.append(record)
    return parsed


def parse_github(data, source):
    """Read published advisories or security-labelled announcement issues."""
    entries = json.loads(data)
    if not isinstance(entries, list):
        raise ValueError("Expected a GitHub result list")
    records = []
    for entry in entries[:100]:
        if not isinstance(entry, dict) or entry.get("withdrawn_at") or entry.get("pull_request"):
            continue
        advisory = source.get("parser") == "github_advisories"
        title = entry.get("summary") if advisory else entry.get("title")
        identifier = entry.get("cve_id") or entry.get("ghsa_id")
        if advisory and identifier:
            title = str(identifier) + " · " + str(title or "")
        record = item(source, title, entry.get("html_url"), entry.get("published_at") if advisory else entry.get("created_at"), date_precision="time", cve_text=entry.get("description") or entry.get("body") or "")
        if record:
            records.append(record)
    return records


def parse_httpd(data, source):
    """Use the vendor's update release date, never the private report date."""
    document = data.decode("utf-8", errors="replace")
    records = []
    pattern = r'<h3\b[^>]*\bid="(CVE-\d{4}-\d{4,10})"[^>]*>(.*?)</h3>\s*</dt>\s*<dd>(.*?)</dd>'
    for cve, heading, details in re.findall(pattern, document, flags=re.S | re.I):
        released = None
        for row in re.findall(r'<tr\b[^>]*>(.*?)</tr>', details, flags=re.S | re.I):
            cells = [plain(cell) for cell in re.findall(r'<td\b[^>]*>(.*?)</td>', row, flags=re.S | re.I)]
            if len(cells) == 2 and cells[0].startswith("Update ") and "released" in cells[0]:
                released = cells[1]
                break
        record = item(source, plain(heading).rstrip(" ¶"), source["website"] + "#" + cve.upper(), released, date_precision="day", product="Apache HTTP Server")
        if record:
            records.append(record)
    return records


def parse_go(data, source, fetcher):
    """Fetch a bounded set of official OSV records; preserve disclosure dates."""
    index = json.loads(data)
    if not isinstance(index, list):
        raise ValueError("Expected the Go vulnerability index")
    entries = [entry for entry in index if isinstance(entry, dict) and re.fullmatch(r"GO-\d{4}-\d{4,10}", str(entry.get("id", ""))) and parse_date(entry.get("modified"))]
    entries.sort(key=lambda entry: parse_date(entry["modified"]), reverse=True)

    def read_record(entry):
        try:
            document = json.loads(fetcher("https://vuln.go.dev/ID/" + entry["id"] + ".json"))
            if document.get("withdrawn") or document.get("id") != entry["id"]:
                return None
            title = document["id"] + " · " + str(document.get("summary") or "Go vulnerability advisory")
            return item(source, title, "https://pkg.go.dev/vuln/" + document["id"], document.get("published"), date_precision="time", cve_text=" ".join(str(alias) for alias in document.get("aliases", [])))
        except (OSError, ValueError, TypeError, KeyError):
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        return [record for record in executor.map(read_record, entries[:LIMIT]) if record]


def parse_symfony(data, source):
    """Read dated posts from the vendor's dedicated security category."""
    document = data.decode("utf-8", errors="replace")
    records = []
    for heading, details in re.findall(r'<h2\b[^>]*>(.*?)</h2>(.*?)(?=<h2\b|</main>)', document, flags=re.S | re.I):
        link = re.search(r'<a\b[^>]*href="([^"]+)"', heading, flags=re.I)
        date = re.search(r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}\b', plain(details, 5000))
        if not link or not date:
            continue
        url = safe_url(urljoin(source["website"], unescape(link[1])))
        if not url or urlsplit(url).hostname != "symfony.com" or not urlsplit(url).path.startswith("/blog/cve-"):
            continue
        published = datetime.strptime(date[0], "%B %d, %Y").replace(tzinfo=timezone.utc)
        record = item(source, heading, url, utc_stamp(published), date_precision="day")
        if record:
            records.append(record)
    return records


def parse_kev(data, source):
    document = json.loads(data)
    parsed = []
    for entry in document.get("vulnerabilities", []):
        cve = entry.get("cveID", "")
        if not re.fullmatch(r"CVE-\d{4}-\d{4,10}", cve):
            continue
        record = item(source, cve + " · " + entry.get("vulnerabilityName", ""), "https://nvd.nist.gov/vuln/detail/" + cve, entry.get("dateAdded"), date_precision="day", vendor=plain(entry.get("vendorProject"), 80), product=plain(entry.get("product"), 100), ransomware=entry.get("knownRansomwareCampaignUse") == "Known")
        if record:
            parsed.append(record)
    return parsed


class SentinelListing(HTMLParser):
    """Read only the first results table under SentinelOne's Latest CVEs heading."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.heading = None
        self.latest = False
        self.in_table = False
        self.complete = False
        self.cell = None
        self.row = []
        self.link = None
        self.rows = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "h2":
            self.heading = []
        if tag == "table" and self.latest and not self.complete and attrs.get("id") == "vulndb-results-table":
            self.in_table = True
        if not self.in_table:
            return
        if tag == "tr":
            self.row, self.link = [], None
        elif tag in {"td", "th"}:
            self.cell = []
        elif tag == "a" and not self.row and self.cell is not None:
            self.link = attrs.get("href")

    def handle_data(self, data):
        if self.heading is not None:
            self.heading.append(data)
        if self.in_table and self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == "h2" and self.heading is not None:
            self.latest = "latest cves" in " ".join(self.heading).lower()
            self.heading = None
        if not self.in_table:
            return
        if tag in {"td", "th"} and self.cell is not None:
            self.row.append(plain(" ".join(self.cell), 300))
            self.cell = None
        elif tag == "tr" and self.row:
            self.rows.append((self.row, self.link))
        elif tag == "table":
            self.in_table, self.complete = False, True


def parse_sentinel(data, source):
    parser = SentinelListing()
    parser.feed(data.decode("utf-8", errors="replace"))
    if not parser.rows:
        raise ValueError("Latest CVE table unavailable")
    columns = [name.lower() for name in parser.rows[0][0]]
    if not {"id", "severity", "score", "technology", "published"}.issubset(columns):
        raise ValueError("Unexpected CVE table columns")
    parsed = []
    for cells, href in parser.rows[1:101]:
        if len(cells) != len(columns) or not href:
            continue
        entry = dict(zip(columns, cells))
        cve = entry["id"].upper()
        url = safe_url(urljoin(source["website"], href))
        if not re.fullmatch(r"CVE-\d{4}-\d{4,10}", cve) or not url:
            continue
        parts = urlsplit(url)
        if parts.netloc != "www.sentinelone.com" or parts.path.rstrip("/") != "/vulnerability-database/" + cve.lower() or parts.query:
            continue
        try:
            published = datetime.strptime(entry["published"], "%b %d, %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        title = cve + " · " + entry["technology"]
        severity = entry["severity"].upper()
        if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            title += " · " + severity
        score = entry["score"]
        if re.fullmatch(r"(?:10(?:\.0)?|[0-9](?:\.[0-9])?)", score):
            title += " · CVSS " + score
        record = item(source, title, url, utc_stamp(published), date_precision="day", product=entry["technology"])
        if record:
            parsed.append(record)
    return parsed


def normalized_previous(previous, source):
    """Revalidate a previous snapshot instead of trusting arbitrary cached fields."""
    records = []
    for entry in previous.get("items", []):
        if not isinstance(entry, dict) or entry.get("source") != source["id"]:
            continue
        record = item(source, entry.get("title"), entry.get("url"), entry.get("published_at"), date_precision="day" if entry.get("date_precision") == "day" else "time", vendor=plain(entry.get("vendor"), 80), product=plain(entry.get("product"), 100), ransomware=entry.get("ransomware") is True)
        if record:
            records.append(record)
    return sorted({r["id"]: r for r in records}.values(), key=lambda r: (r["published_at"], r["title"]), reverse=True)[:LIMIT]


def collect_source(source, previous, now, fetcher=fetch_bytes):
    metadata = {**source, "last_attempt_at": now}
    try:
        data = fetcher(source["feed"])
        if source["id"] == "kev":
            records = parse_kev(data, source)
        elif source["id"] == "sentinelone":
            records = parse_sentinel(data, source)
        elif source.get("parser") in {"github_advisories", "github_issues"}:
            records = parse_github(data, source)
        elif source.get("parser") == "go":
            records = parse_go(data, source, fetcher)
        elif source.get("parser") == "httpd":
            records = parse_httpd(data, source)
        elif source.get("parser") == "symfony":
            records = parse_symfony(data, source)
        else:
            records = parse_rss(data, source)
        records = sorted({r["id"]: r for r in records}.values(), key=lambda r: (r["published_at"], r["title"]), reverse=True)[:LIMIT]
        if not records:
            raise ValueError("Source returned no usable entries")
        metadata.update(status="ok", last_success_at=now, count=len(records))
    except Exception:
        records = normalized_previous(previous, source)
        old = next((s for s in previous.get("sources", []) if isinstance(s, dict) and s.get("id") == source["id"]), {})
        metadata.update(status="stale" if records else "unavailable", last_success_at=parse_date(old.get("last_success_at")), count=len(records))
    return metadata, records


def read_previous(path, previous_url=None):
    candidates = []
    if path.exists():
        try:
            candidates.append(json.loads(path.read_text()))
        except (OSError, ValueError):
            pass
    if previous_url:
        try:
            candidate = json.loads(fetch_bytes(previous_url))
            if candidate.get("schema_version") == 1:
                candidates.append(candidate)
        except Exception:
            pass
    valid = [c for c in candidates if isinstance(c, dict) and c.get("schema_version") == 1 and isinstance(c.get("items"), list) and isinstance(c.get("sources"), list)]
    return max(valid, key=lambda c: c.get("generated_at", "")) if valid else {}


def collect(previous):
    now = utc_stamp()
    with ThreadPoolExecutor(max_workers=min(12, len(SOURCES))) as executor:
        results = list(executor.map(lambda source: collect_source(source, previous, now), SOURCES))
    items = sorted([record for _, records in results for record in records], key=lambda r: (r["published_at"], r["id"]), reverse=True)
    if not items:
        raise RuntimeError("All feeds unavailable without cached items; refusing to replace the published site")
    return {"schema_version": 1, "generated_at": now, "refresh_minutes": 60, "sources": [metadata for metadata, _ in results], "items": items}


def render_source_catalog(document):
    """Keep the accessible source directory and feed selector in sync."""
    groups = ["Servers & infrastructure", "Operating systems", "Languages & runtimes", "Frameworks", "Vulnerability databases", "News & research"]
    options = ['<label class="signal-source-select"><span>Filter by source</span><select id="signal-source-select"><option value="all">All sources</option>']
    directory = ['<details class="signal-source-directory" id="sources" open><summary>Sources <span>' + str(len(CATALOG)) + ' sources · ' + str(len(SOURCES)) + ' automated feeds</span></summary><p>Browse the original sources below. Automated feeds contribute headlines; reference links open the full advisory index or search database.</p><div class="signal-directory-grid">']
    for group in groups:
        sources = [source for source in CATALOG if source["group"] == group]
        feeds = [source for source in sources if source.get("feed")]
        if feeds:
            options.append('<optgroup label="' + escape(group, quote=True) + '">')
        directory.append('<section class="signal-directory-group"><h3>' + escape(group) + '</h3>')
        for source in sources:
            name, website, key = escape(source["name"]), escape(source["website"], quote=True), escape(source["id"], quote=True)
            if source.get("feed"):
                options.append('<option value="' + key + '" data-category="' + escape(source["category"], quote=True) + '">' + name + '</option>')
            directory.append('<a data-source-id="' + key + '" href="' + website + '" target="_blank" rel="noopener noreferrer"><span>' + name + ' ↗</span><small>' + ('Automated feed' if source.get("feed") else 'Reference') + '</small></a>')
        directory.append('</section>')
        if feeds:
            options.append('</optgroup>')
    options.append('</select></label>')
    directory.append('</div></details>')
    for name, content in [("SOURCE_FILTERS", "".join(options)), ("SOURCE_DIRECTORY", "".join(directory))]:
        start, end = '<!-- ' + name + '_START -->', '<!-- ' + name + '_END -->'
        document, count = re.subn(re.escape(start) + r'.*?' + re.escape(end), lambda _: start + content + end, document, flags=re.S)
        if count != 1:
            raise ValueError("Missing or duplicate source catalog marker: " + name)
    return document


def build_public_directory(destination):
    destination.mkdir(parents=True, exist_ok=True)
    names = ["index.html", "404.html", "site.js", "terminal-v2.css", "signal-feed.css", "signal-feed.js", "favicon.svg", "robots.txt", "sitemap.xml", ".nojekyll"]
    names += [p.name for p in ROOT.glob("*.woff2")] + [p.name for p in ROOT.glob("*-OFL.txt")]
    for name in names:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Invalid public asset: " + name)
        shutil.copyfile(path, destination / name)
    index = destination / "index.html"
    index.write_text(render_source_catalog(index.read_text()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "security-feed.json")
    parser.add_argument("--previous-url")
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    previous = read_previous(ROOT / "security-feed.json", args.previous_url)
    result = collect(previous)
    output = args.build_dir / "security-feed.json" if args.build_dir else args.output
    if args.build_dir:
        build_public_directory(args.build_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(output)
    print(json.dumps({"generated_at": result["generated_at"], "items": len(result["items"]), "sources": [{"id": s["id"], "status": s["status"], "count": s["count"]} for s in result["sources"]]}))


if __name__ == "__main__":
    main()

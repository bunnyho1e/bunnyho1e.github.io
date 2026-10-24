#!/usr/bin/env python3
"""Collect public headline metadata; never retrieve or execute exploit payloads."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
from html import unescape
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import shutil
import urllib.request
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 5_000_000
LIMIT = 18
SOURCES = [
    {"id": "thn", "name": "The Hacker News", "category": "news", "website": "https://thehackernews.com/", "feed": "https://feeds.feedburner.com/TheHackersNews"},
    {"id": "edb", "name": "Exploit-DB", "category": "exploit", "website": "https://www.exploit-db.com/", "feed": "https://www.exploit-db.com/rss.xml"},
    {"id": "kev", "name": "CISA KEV", "category": "exploited", "website": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "feed": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"},
    {"id": "aikido", "name": "Aikido Blog", "category": "news", "website": "https://www.aikido.dev/blog", "feed": "https://www.aikido.dev/blog/rss.xml"},
    {"id": "netsec", "name": "Reddit r/netsec", "category": "community", "website": "https://www.reddit.com/r/netsec/", "feed": "https://www.reddit.com/r/netsec/new/.rss?limit=25"},
    {"id": "devto", "name": "DEV Community", "category": "development", "website": "https://dev.to/", "feed": "https://dev.to/feed"},
    {"id": "wiz", "name": "Wiz Blog", "category": "news", "website": "https://www.wiz.io/blog", "feed": "https://www.wiz.io/feed/rss.xml"},
    {"id": "securityweek", "name": "SecurityWeek", "category": "news", "website": "https://www.securityweek.com/", "feed": "https://www.securityweek.com/feed/"},
    {"id": "bleeping", "name": "BleepingComputer", "category": "news", "website": "https://www.bleepingcomputer.com/", "feed": "https://www.bleepingcomputer.com/feed/"},
    {"id": "wired", "name": "WIRED Security", "category": "news", "website": "https://www.wired.com/category/security/", "feed": "https://www.wired.com/feed/category/security/latest/rss"},
    {"id": "sophos", "name": "Sophos Blog", "category": "news", "website": "https://www.sophos.com/en-us/blog", "feed": "https://www.sophos.com/en-us/blog/feed?id=blt6f15f4f7deaf4242"},
    {"id": "checkpoint", "name": "Check Point Blog", "category": "news", "website": "https://blog.checkpoint.com/", "feed": "https://blog.checkpoint.com/feed/"},
    {"id": "darkwebinformer", "name": "Dark Web Informer", "category": "news", "website": "https://darkwebinformer.com/", "feed": "https://darkwebinformer.com/rss/"},
]


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
        if parts.scheme == "http" and host not in {"thehackernews.com", "www.exploit-db.com", "exploit-db.com"}:
            return None
        return urlunsplit(("https", parts.netloc, parts.path, parts.query, ""))
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
    """Read headline metadata from RSS 2.0 or Atom 1.0 feeds."""
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("XML entities are not accepted")
    root = ET.fromstring(data)
    parsed = []
    for entry in root.findall(".//item")[:100]:
        url = entry.findtext("{http://rssnamespace.org/feedburner/ext/1.0}origLink") or entry.findtext("link")
        record = item(source, entry.findtext("title"), url, entry.findtext("pubDate"), date_precision="time", cve_text=entry.findtext("description") or "")
        if record:
            parsed.append(record)
    atom = "{http://www.w3.org/2005/Atom}"
    for entry in root.findall(atom + "entry")[:100]:
        url = next((link.get("href") for link in entry.findall(atom + "link") if link.get("rel", "alternate") == "alternate"), None)
        record = item(source, entry.findtext(atom + "title"), url, entry.findtext(atom + "published") or entry.findtext(atom + "updated"), date_precision="time", cve_text=entry.findtext(atom + "summary") or entry.findtext(atom + "content") or "")
        if record:
            parsed.append(record)
    return parsed


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
        records = parse_kev(data, source) if source["id"] == "kev" else parse_rss(data, source)
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
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
        results = list(executor.map(lambda source: collect_source(source, previous, now), SOURCES))
    items = sorted([record for _, records in results for record in records], key=lambda r: (r["published_at"], r["id"]), reverse=True)
    if not items:
        raise RuntimeError("All feeds unavailable without cached items; refusing to replace the published site")
    return {"schema_version": 1, "generated_at": now, "refresh_minutes": 60, "sources": [metadata for metadata, _ in results], "items": items}


def build_public_directory(destination):
    destination.mkdir(parents=True, exist_ok=True)
    names = ["index.html", "404.html", "site.js", "terminal-v2.css", "signal-feed.css", "signal-feed.js", "favicon.svg", "robots.txt", "sitemap.xml", ".nojekyll"]
    names += [p.name for p in ROOT.glob("*.woff2")] + [p.name for p in ROOT.glob("*-OFL.txt")]
    for name in names:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Invalid public asset: " + name)
        shutil.copyfile(path, destination / name)


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

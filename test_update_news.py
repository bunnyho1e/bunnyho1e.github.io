import json
import unittest

import update_news as news


class FeedTests(unittest.TestCase):
    def test_urls_reject_script_userinfo_and_private_hosts(self):
        for url in ["javascript:alert(1)", "data:text/html,test", "https://user:secret@example.com", "https://127.0.0.1/test", "https://localhost/test", "https://192.168.0.1/"]:
            self.assertIsNone(news.safe_url(url), url)
        self.assertEqual(news.safe_url("https://example.com/advisory?cve=1"), "https://example.com/advisory?cve=1")

    def test_rss_strips_markup_deduplicates_cves_and_parses_date(self):
        raw = b'''<rss><channel><item><title>&lt;b&gt;Patch CVE-2026-12345&lt;/b&gt;</title><link>https://example.com/advisory</link><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate><description>CVE-2026-12345</description></item><item><title>Unsafe</title><link>javascript:alert(1)</link><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item></channel></rss>'''
        records = news.parse_rss(raw, news.SOURCES[0])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["title"], "Patch CVE-2026-12345")
        self.assertEqual(records[0]["cves"], ["CVE-2026-12345"])
        self.assertEqual(records[0]["published_at"], "2026-10-23T10:00:00Z")

    def test_xml_entities_are_rejected(self):
        with self.assertRaises(ValueError):
            news.parse_rss(b'<!DOCTYPE rss [<!ENTITY x "test">]><rss/>', news.SOURCES[0])

    def test_atom_uses_discussion_link_and_original_publication_time(self):
        source = next(s for s in news.SOURCES if s["id"] == "netsec")
        raw = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Research on CVE-2026-12345</title><link rel="self" href="https://www.reddit.com/api/post"/><link href="https://www.reddit.com/r/netsec/comments/example/research/"/><published>2026-10-23T10:00:00+00:00</published><updated>2026-10-24T11:00:00+00:00</updated></entry><entry><title>Update-only post</title><link rel="alternate" href="https://www.reddit.com/r/netsec/comments/second/"/><updated>2026-10-23T11:00:00Z</updated></entry><entry><title>Unsafe link</title><link href="javascript:alert(1)"/><updated>2026-10-23T11:00:00Z</updated></entry></feed>'''
        records = news.parse_rss(raw, source)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["url"], "https://www.reddit.com/r/netsec/comments/example/research/")
        self.assertEqual(records[0]["published_at"], "2026-10-23T10:00:00Z")
        self.assertEqual(records[0]["cves"], ["CVE-2026-12345"])
        self.assertEqual(records[1]["published_at"], "2026-10-23T11:00:00Z")

    def test_kev_uses_date_added_and_structured_ransomware_field(self):
        raw = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-12345", "vulnerabilityName": "Example flaw", "dateAdded": "2026-10-23", "vendorProject": "Example", "product": "Server", "knownRansomwareCampaignUse": "Known"}]}).encode()
        record = news.parse_kev(raw, news.SOURCES[2])[0]
        self.assertEqual(record["date_precision"], "day")
        self.assertTrue(record["ransomware"])
        self.assertEqual(record["url"], "https://nvd.nist.gov/vuln/detail/CVE-2026-12345")

    def test_sentinel_uses_only_latest_table_and_published_dates(self):
        source = next(s for s in news.SOURCES if s["id"] == "sentinelone")
        raw = b'''<h2><span>Latest CVEs.</span> Most recently published vulnerabilities.</h2>
        <table id="vulndb-results-table"><thead><tr><th>ID</th><th>Severity</th><th>Score</th><th>Technology</th><th>Published</th></tr></thead><tbody>
        <tr><td><a href="/vulnerability-database/cve-2026-12345/">CVE-2026-12345</a></td><td>HIGH</td><td>8.2</td><td><span>Example &amp; Server</span></td><td>Oct 22, 2026</td></tr>
        <tr><td><a href="https://www.sentinelone.com/vulnerability-database/cve-2026-12346/">CVE-2026-12346</a></td><td>NONE</td><td>--</td><td>Other</td><td>Oct 21, 2026</td></tr>
        </tbody></table><h2>High Profile CVEs.</h2><table id="vulndb-results-table"><tr><td><a href="/vulnerability-database/cve-2026-99999/">CVE-2026-99999</a></td><td>CRITICAL</td><td>10.0</td><td>Older</td><td>Oct 24, 2026</td></tr></table>
        <script>"CVE-2026-99998"</script>'''
        metadata, records = news.collect_source(source, {}, "2026-10-25T10:00:00Z", lambda _: raw)
        self.assertEqual(metadata["status"], "ok")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["title"], "CVE-2026-12345 \u00b7 Example & Server \u00b7 HIGH \u00b7 CVSS 8.2")
        self.assertEqual(records[0]["cves"], ["CVE-2026-12345"])
        self.assertEqual(records[0]["published_at"], "2026-10-22T00:00:00Z")
        self.assertEqual(records[0]["date_precision"], "day")
        self.assertEqual(records[1]["title"], "CVE-2026-12346 \u00b7 Other")

    def test_sentinel_rejects_foreign_links_mismatched_cves_and_invalid_dates(self):
        source = next(s for s in news.SOURCES if s["id"] == "sentinelone")
        header = '<h2>Latest CVEs.</h2><table id="vulndb-results-table"><tr><th>ID</th><th>Severity</th><th>Score</th><th>Technology</th><th>Published</th></tr>'
        rows = [
            ('https://example.com/vulnerability-database/cve-2026-12345/', 'Oct 22, 2026'),
            ('javascript:alert(1)', 'Oct 22, 2026'),
            ('/vulnerability-database/cve-2026-12346/', 'Oct 22, 2026'),
            ('/vulnerability-database/cve-2026-12345/', 'not a date'),
        ]
        raw = header + ''.join(f'<tr><td><a href="{href}">CVE-2026-12345</a></td><td>HIGH</td><td>8.2</td><td>Example</td><td>{date}</td></tr>' for href, date in rows) + '</table>'
        self.assertEqual(news.parse_sentinel(raw.encode(), source), [])
        with self.assertRaises(ValueError):
            news.parse_sentinel(b'<h2>Latest CVEs.</h2><table id="vulndb-results-table"><tr><th>Changed layout</th></tr></table>', source)

    def test_failure_preserves_cached_records_and_actual_success_time(self):
        source = news.SOURCES[0]
        old = "2026-10-23T10:00:00Z"
        record = news.item(source, "An advisory", "https://example.com/advisory", old)
        previous = {"sources": [{"id": "thn", "last_success_at": old}], "items": [record]}
        def fail(_):
            raise OSError("offline")
        metadata, records = news.collect_source(source, previous, "2026-10-24T10:00:00Z", fail)
        self.assertEqual(metadata["status"], "stale")
        self.assertEqual(metadata["last_success_at"], old)
        self.assertEqual(len(records), 1)

    def test_unavailable_source_without_cache_is_explicit(self):
        metadata, records = news.collect_source(news.SOURCES[0], {}, "2026-10-24T10:00:00Z", lambda _: b"<rss/>")
        self.assertEqual(metadata["status"], "unavailable")
        self.assertEqual(records, [])

    def test_rdf_reads_debian_dates_and_preserves_day_precision(self):
        source = next(s for s in news.SOURCES if s["id"] == "debian")
        raw = b'''<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/"><item><title>DSA-1234 security update</title><link>https://lists.debian.org/advisory</link><dc:date>2026-10-24</dc:date><description>CVE-2026-12345</description></item></rdf:RDF>'''
        record = news.parse_rss(raw, source)[0]
        self.assertEqual(record["published_at"], "2026-10-24T00:00:00Z")
        self.assertEqual(record["date_precision"], "day")
        self.assertEqual(record["cves"], ["CVE-2026-12345"])

    def test_php_atom_uses_release_page_instead_of_download(self):
        source = next(s for s in news.SOURCES if s["id"] == "php")
        raw = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>PHP security release</title><id>http://php.net/releases/8_5_12.php</id><published>2026-10-21T00:00:00Z</published><link rel="enclosure" href="https://www.php.net/distributions/php.tar.gz"/></entry></feed>'''
        record = news.parse_rss(raw, source)[0]
        self.assertEqual(record["url"], "https://php.net/releases/8_5_12.php")

    def test_security_feed_filter_excludes_general_framework_news(self):
        source = next(s for s in news.SOURCES if s["id"] == "django")
        raw = b'''<rss><channel><item><title>Community news</title><link>https://www.djangoproject.com/news</link><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item><item><title>Security release</title><link>https://www.djangoproject.com/fix</link><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item></channel></rss>'''
        records = news.parse_rss(raw, source)
        self.assertEqual([r["title"] for r in records], ["Security release"])

    def test_github_advisories_exclude_withdrawn_and_use_disclosure_date(self):
        source = next(s for s in news.SOURCES if s["id"] == "nextjs")
        entry = {"summary": "Example vulnerability", "cve_id": "CVE-2026-12345", "html_url": "https://github.com/vercel/next.js/security/advisories/GHSA-example", "published_at": "2026-10-20T10:00:00Z", "updated_at": "2026-10-25T12:00:00Z"}
        entries = [entry, {**entry, "withdrawn_at": "2026-10-21T00:00:00Z"}, {**entry, "html_url": "javascript:alert(1)"}]
        records = news.parse_github(json.dumps(entries).encode(), source)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["published_at"], entry["published_at"])
        self.assertEqual(records[0]["cves"], ["CVE-2026-12345"])
        with self.assertRaises(ValueError):
            news.parse_github(b'{"message":"API limit"}', source)

    def test_github_announcements_skip_pull_requests_and_use_issue_creation(self):
        source = next(s for s in news.SOURCES if s["id"] == "dotnet")
        entry = {"title": ".NET security update", "html_url": "https://github.com/dotnet/announcements/issues/1", "created_at": "2026-10-20T10:00:00Z", "updated_at": "2026-10-25T12:00:00Z"}
        records = news.parse_github(json.dumps([entry, {**entry, "pull_request": {"url": "https://github.com/example"}}]).encode(), source)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["published_at"], entry["created_at"])

    def test_httpd_keeps_distinct_cve_links_and_public_fix_dates(self):
        source = next(s for s in news.SOURCES if s["id"] == "httpd")
        raw = ''.join('<dt><h3 id="'+cve+'">'+cve+': Example flaw</h3></dt><dd><table><tr><td>Report received</td><td>2026-01-01</td></tr><tr><td>Update 2.4.69 released</td><td>2026-10-01</td></tr></table></dd>' for cve in ['CVE-2026-12345','CVE-2026-12346'])
        records = news.parse_httpd(raw.encode(), source)
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]["id"], records[1]["id"])
        self.assertTrue(records[0]["url"].endswith('#CVE-2026-12345'))
        self.assertEqual(records[0]["published_at"], '2026-10-01T00:00:00Z')
        self.assertEqual(news.parse_httpd(raw.replace('Update 2.4.69 released','Report received').encode(),source), [])

    def test_go_bounds_requests_rejects_invalid_ids_and_keeps_publication_date(self):
        source = next(s for s in news.SOURCES if s["id"] == "go")
        entries = [{"id": "GO-2026-"+str(1000+i), "modified":"2026-10-25T12:00:00Z"} for i in range(100)]
        entries.insert(0,{"id":"../../untrusted","modified":"2026-10-26T12:00:00Z"})
        requested=[]
        def fetch(url):
            requested.append(url)
            key=url.rsplit('/',1)[-1][:-5]
            return json.dumps({"id":key,"published":"2026-01-01T00:00:00Z","summary":"Example advisory","aliases":["CVE-2026-12345"]}).encode()
        records=news.parse_go(json.dumps(entries).encode(),source,fetch)
        self.assertEqual(len(requested),news.LIMIT)
        self.assertEqual(len(records),news.LIMIT)
        self.assertTrue(all(url.startswith('https://vuln.go.dev/ID/GO-2026-') for url in requested))
        self.assertEqual(records[0]["published_at"],'2026-01-01T00:00:00Z')

    def test_symfony_category_uses_dated_vendor_advisories_only(self):
        source = next(s for s in news.SOURCES if s["id"] == "symfony")
        raw = '''<main><h2><a href="/blog/cve-2026-12345-example">CVE-2026-12345 Example flaw</a></h2><div>October 15, 2026</div><h2><a href="https://example.com/blog/cve-2026-12346-foreign">CVE-2026-12346 Foreign</a></h2><div>October 16, 2026</div><h2><a href="/blog/community">Community news</a></h2><div>October 17, 2026</div></main>'''
        records=news.parse_symfony(raw.encode(),source)
        self.assertEqual(len(records),1)
        self.assertEqual(records[0]["published_at"],'2026-10-15T00:00:00Z')
        self.assertEqual(records[0]["date_precision"],'day')


if __name__ == "__main__":
    unittest.main()

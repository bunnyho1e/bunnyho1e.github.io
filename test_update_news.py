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


if __name__ == "__main__":
    unittest.main()

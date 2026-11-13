import datetime
import json
import pathlib
import tempfile
import unittest

import intelligence


class IntelligenceFeedTests(unittest.TestCase):
    def test_low_mobile_record_is_kept_before_alert_policy(self):
        row = intelligence.compact_record({
            "id": "CVE-2001-0001", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Android library input confusion"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1, "vectorString": "CVSS:3.1/AV:L"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True, "criteria": "cpe:2.3:a:vendor:sdk:*:*:*:*:*:*:*:*",
                "versionEndExcluding": "2.0.0",
            }]}]}],
        }, observed_at="2026-11-13T00:00:00+00:00", poc_urls=[])
        self.assertEqual(row["score"], 3.1)
        self.assertIn("Android", row["description"])
        self.assertEqual(row["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"], "2.0.0")

    def test_rejected_record_is_not_intelligence(self):
        self.assertIsNone(intelligence.compact_record(
            {"id": "CVE-2001-0002", "vulnStatus": "Rejected"},
            observed_at="2026-11-13T00:00:00+00:00", poc_urls=[]))

    def test_feed_merge_is_atomic_idempotent_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "feed.json"
            old = {"cve_id": "CVE-2000-0001", "observed_at": "2026-01-01T00:00:00+00:00"}
            path.write_text(json.dumps({"schema_version": 1, "records": {old["cve_id"]: old}}))
            row = {"cve_id": "CVE-2026-0001", "observed_at": "2026-11-13T00:00:00+00:00"}
            first = intelligence.update_feed(path, [row], generated_at=row["observed_at"], cursor_end=row["observed_at"])
            second = intelligence.update_feed(path, [row], generated_at=row["observed_at"], cursor_end=row["observed_at"])
            self.assertEqual(first["records"], second["records"])
            self.assertEqual(list(second["records"]), ["CVE-2026-0001"])
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_first_short_run_bootstraps_full_overnight_window(self):
        now = datetime.datetime(2026, 11, 13, 8, tzinfo=datetime.timezone.utc)
        self.assertEqual(
            intelligence.nvd_window_start(now, 2, ""),
            datetime.datetime(2026, 11, 12, 6, tzinfo=datetime.timezone.utc))

    def test_existing_cursor_resumes_with_overlap(self):
        now = datetime.datetime(2026, 11, 13, 8, tzinfo=datetime.timezone.utc)
        self.assertEqual(
            intelligence.nvd_window_start(now, 2, "2026-11-13T07:00:00+00:00"),
            datetime.datetime(2026, 11, 13, 6, tzinfo=datetime.timezone.utc))


if __name__ == "__main__":
    unittest.main()

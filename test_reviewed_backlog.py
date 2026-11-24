import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import import_reviewed_backlog as importer
import update as u


class ReviewedBacklogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        u.save_json(self.root / "attacks.json", {"updated": "2026-11-18T00:00:00+00:00", "incidents": []})
        u.save_json(self.root / "pending.json", {"https://example.org/story": {
            "id": "source123", "url": "https://example.org/story", "title": "Incident",
            "source": "Example", "date": "2026-11-23"}})
        u.save_json(self.root / "decisions.json", {})
        u.save_json(self.root / "geocache.json", {})

    def record(self):
        from test_selection import record
        r = record(title="Utility intrusion", victim="Utility", date="2026-11-23",
                   what="Confirmed unauthorized access", decision_reason="Verified incident",
                   significance="Essential service was disrupted",
                   severity_evidence={"context":"real_world", "service":"substantial",
                   "reach":"single", "damage":"unknown", "essential":"disrupted",
                   "financial":"unknown", "reason":"Confirmed service interruption"},
                   location_queries=[], geocode_query=None)
        return r

    def test_dry_run_does_not_change_files(self):
        original = (self.root / "pending.json").read_bytes()
        result = importer.import_reviews(self.root, [{"url":"https://example.org/story",
                                                       "records":[self.record()]}])
        self.assertEqual(result["added"], 1)
        self.assertEqual((self.root / "pending.json").read_bytes(), original)
        self.assertEqual(u.load_json(self.root / "attacks.json", {})["incidents"], [])

    def test_apply_preserves_existing_data_and_removes_reviewed_queue_entry(self):
        with patch.object(u, "locate_incident"):
            result = importer.import_reviews(self.root, [{"url":"https://example.org/story",
                                                           "records":[self.record()]}], dry_run=False)
        self.assertEqual(result["added"], 1)
        self.assertEqual(len(u.load_json(self.root / "attacks.json", {})["incidents"]), 1)
        self.assertEqual(u.load_json(self.root / "pending.json", {}), {})

    def test_reapplying_same_batch_does_not_duplicate_incidents(self):
        batch = [{"url":"https://example.org/story", "records":[self.record()]}]
        with patch.object(u, "locate_incident"):
            importer.import_reviews(self.root, batch, dry_run=False)
            result = importer.import_reviews(self.root, batch, dry_run=False)
        self.assertEqual(result["already_imported"], 1)
        self.assertEqual(result["added"], 0)
        self.assertEqual(len(u.load_json(self.root / "attacks.json", {})["incidents"]), 1)

    def test_unknown_source_is_rejected_without_changes(self):
        with self.assertRaises(ValueError):
            importer.import_reviews(self.root, [{"url":"https://example.org/other",
                                                 "records":[self.record()]}], dry_run=False)
        self.assertEqual(len(u.load_json(self.root / "pending.json", {})), 1)


if __name__ == "__main__":
    unittest.main()

import unittest, json, csv, io
from privacy_redaction_toolkit.core import audit


class FeatureTests(unittest.TestCase):
    def test_audit_counts_without_echoing_values(self):
        result = audit(
            {"password": "sensitive-private-value", "message": "demo@example.com"}
        )
        self.assertEqual(result["recognized_exposures"], 2)
        self.assertNotIn("sensitive-private-value", json.dumps(result))
        self.assertNotIn("demo@example.com", json.dumps(result))

    def test_audit_clean_document(self):
        self.assertEqual(audit({"event": "started"})["recognized_exposures"], 0)

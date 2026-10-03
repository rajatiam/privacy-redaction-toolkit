import copy, tempfile, unittest
from pathlib import Path
from privacy_redaction_toolkit.core import redact, write_redacted


class RedactionTests(unittest.TestCase):
    def test_nested_sensitive_keys(self):
        result = redact({"records": [{"password": "hidden", "Api-Key": "secret"}]})
        self.assertEqual(result["document"]["records"][0]["password"], "[SENSITIVE]")
        self.assertEqual(result["replacements"]["sensitive"], 2)

    def test_email_and_ipv4(self):
        result = redact("Contact demo@example.com from 10.0.0.1")
        self.assertNotIn("demo@example.com", result["document"])
        self.assertEqual(result["replacements"], {"email": 1, "ipv4": 1})

    def test_bad_ipv4_is_not_redacted(self):
        self.assertEqual(redact("999.1.1.1")["document"], "999.1.1.1")

    def test_bearer_and_token(self):
        self.assertEqual(redact("Bearer abcdef123456")["document"], "[BEARER]")
        self.assertEqual(redact("ghp_abcdefghijklmnop")["document"], "[TOKEN]")

    def test_correlation_and_salt_isolation(self):
        first = redact("demo@example.com", b"x" * 16)
        self.assertEqual(first, redact("demo@example.com", b"x" * 16))
        self.assertNotEqual(first, redact("demo@example.com", b"y" * 16))

    def test_input_not_mutated(self):
        data = {"email": "demo@example.com", "count": 3}
        original = copy.deepcopy(data)
        redact(data)
        self.assertEqual(data, original)

    def test_short_salt_rejected(self):
        with self.assertRaises(ValueError):
            redact("text", b"short")

    def test_source_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "in.json"
            source.write_text("{}")
            with self.assertRaises(ValueError):
                write_redacted(source, source)

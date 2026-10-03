"""Exercise the shipped examples through the real process entrypoint."""

import json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def test_help_entrypoint(self):
        result = subprocess.run(
            [sys.executable, "-m", "privacy_redaction_toolkit", "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)

    def test_documented_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            clone = Path(folder)
            shutil.copytree(
                ROOT / "privacy_redaction_toolkit", clone / "privacy_redaction_toolkit"
            )
            shutil.copytree(ROOT / "examples", clone / "examples")
            for command in ["redact examples/events.json examples/redacted.json"]:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "privacy_redaction_toolkit",
                        *command.split(),
                    ],
                    cwd=clone,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
            self.assertEqual(payload["replacements"]["sensitive"], 2)
            self.assertNotIn(
                "demo@example.com", (clone / "examples/redacted.json").read_text()
            )

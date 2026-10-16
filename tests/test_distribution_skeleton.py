"""Checks for the cyber-au distribution skeleton. No network and no Hermes install."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

OWNED = [
    "distribution.yaml",
    "SOUL.md",
    "config.yaml",
    ".env.template",
    "skills",
    "cron/jobs.json",
    "scripts",
    "plugins/cyber-au",
    "mcp",
    "feeds",
    "playbooks",
]

ENV_NAMES = [
    "ABUSECH_AUTH_KEY",
    "NVD_API_KEY",
    "OTX_API_KEY",
    "CLOUDFLARE_RADAR_API_TOKEN",
    "GREYNOISE_API_KEY",
]

# Phrases the Hermes context-file scanner treats as injection or secret access.
BANNED_SOUL = [
    "ignore previous",
    "ignore all",
    "ignore prior",
    "disregard",
    "you are now",
    "pretend",
    "system prompt",
    ".env",
    "credentials",
    ".netrc",
    "curl ",
    "wget ",
]


class DistributionSkeletonTest(unittest.TestCase):
    def test_owned_paths_exist(self):
        missing = [rel for rel in OWNED if not (ROOT / rel).exists()]
        self.assertEqual(missing, [])

    def test_manifest_declares_name_version_and_optional_keys(self):
        text = (ROOT / "distribution.yaml").read_text(encoding="utf-8")
        self.assertIn("name: cyber-au\n", text)
        self.assertIn('version: 0.1.0\n', text)
        self.assertIn('hermes_requires: ">=0.22.2"\n', text)
        self.assertIn("license: \"Apache-2.0\"\n", text)
        for rel in OWNED:
            self.assertIn(f"  - {rel}\n", text)
        for name in ENV_NAMES:
            self.assertIn(f"  - name: {name}\n", text)
            self.assertIn("required: false\n", text)
        self.assertNotIn("required: true", text)

    def test_env_template_has_no_values(self):
        text = (ROOT / ".env.template").read_text(encoding="utf-8")
        for name in ENV_NAMES:
            self.assertIn(name, text)
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            self.fail(f"env template has a live assignment: {stripped}")

    def test_config_is_sydney_and_does_not_name_a_model(self):
        text = (ROOT / "config.yaml").read_text(encoding="utf-8")
        self.assertIn("timezone: Australia/Sydney\n", text)
        self.assertIn("allow_private_urls: false\n", text)
        lowered = text.lower()
        for token in ("openai", "anthropic", "gpt-", "claude"):
            self.assertNotIn(token, lowered)

    def test_soul_states_the_rules_and_avoids_scanner_phrases(self):
        text = (ROOT / "SOUL.md").read_text(encoding="utf-8")
        self.assertIn("I don't know", text)
        self.assertIn("Essential Eight", text)
        self.assertIn("explicit approval", text)
        lowered = text.lower()
        for phrase in BANNED_SOUL:
            self.assertNotIn(phrase, lowered, phrase)
        self.assertNotIn("\u2014", text)
        self.assertNotIn("\u200b", text)

    def test_jobs_file_is_an_empty_list(self):
        text = (ROOT / "cron/jobs.json").read_text(encoding="utf-8")
        self.assertIn('"jobs"', text)
        self.assertIn("[]", text)

    def test_git_index_has_no_secret_files(self):
        tracked = subprocess.check_output(
            ["git", "ls-files"], cwd=ROOT, text=True
        ).splitlines()
        banned_names = {".env", "auth.json", "credentials.json", ".env.EXAMPLE"}
        bad = [
            path
            for path in tracked
            if Path(path).name in banned_names
            or path.endswith(".pem")
            or path.endswith(".key")
            or path.startswith("memories/")
            or path.startswith("sessions/")
            or path.startswith("state.db")
        ]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()

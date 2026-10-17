"""Tests for tools/ci/validate_repo.py. No network."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "tools" / "ci" / "validate_repo.py"
    spec = importlib.util.spec_from_file_location("cyberau_ci_validate_repo", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ValidateRepoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load()

    def test_repository_passes(self):
        self.assertEqual(self.mod.validate(ROOT), [])

    def test_main_on_repository(self):
        self.assertEqual(self.mod.main(["--root", str(ROOT)]), 0)

    def test_workflow_pins_actions_and_has_no_secret(self):
        text = (ROOT / "ci" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7", text
        )
        self.assertIn(
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7",
            text,
        )
        self.assertIn(
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4",
            text,
        )
        self.assertNotIn("secrets.", text)
        self.assertIn("tools/ci/validate_repo.py", text)
        self.assertIn("tools/ci/style_check.py", text)
        self.assertNotIn("\u2014", text)

    def test_distribution_rejects_a_missing_owned_path(self):
        with self._tree() as root:
            self._write_distribution(root, owned=["missing.txt"])
            findings = self.mod.check_distribution(root)
        self.assertTrue(any("missing.txt" in item for item in findings))

    def test_distribution_rejects_a_lowercase_env_name(self):
        with self._tree() as root:
            (root / "README.md").write_text("hello\n", encoding="utf-8")
            text = (
                "name: cyber-au\n"
                "version: 0.1.0\n"
                "description: A distribution.\n"
                'hermes_requires: ">=0.22.2"\n'
                "author: Tester\n"
                "license: Apache-2.0\n"
                "distribution_owned:\n"
                "  - README.md\n"
                "env_requires:\n"
                "  - name: nvd_api_key\n"
                "    description: A key.\n"
                "    required: false\n"
            )
            (root / "distribution.yaml").write_text(text, encoding="utf-8")
            findings = self.mod.check_distribution(root)
        self.assertTrue(any("uppercase" in item for item in findings))

    def test_skill_frontmatter_accepts_a_complete_skill(self):
        with self._tree() as root:
            self._write_skill(root, "incident-triage")
            self.assertEqual(self.mod.check_skills(root), [])

    def test_skill_frontmatter_rejects_a_name_mismatch(self):
        with self._tree() as root:
            self._write_skill(root, "incident-triage", name="other-skill")
            findings = self.mod.check_skills(root)
        self.assertTrue(any("does not match directory" in item for item in findings))

    def test_catalogue_accepts_a_feed_for_a_known_connector(self):
        with self._tree() as root:
            self._write_catalogue(root, connector="cisa-kev", feed_format="json")
            self.assertEqual(self.mod.check_catalogue(root), [])

    def test_catalogue_rejects_an_unknown_format(self):
        with self._tree() as root:
            self._write_catalogue(root, connector="cisa-kev", feed_format="xml")
            findings = self.mod.check_catalogue(root)
        self.assertTrue(any("xml" in item for item in findings))

    def test_missing_catalogue_is_not_an_error(self):
        with self._tree() as root:
            (root / "feeds").mkdir()
            self.assertEqual(self.mod.check_catalogue(root), [])

    def test_allowlist_matches_source_notes_and_code(self):
        with self._tree() as root:
            self._write_connector(root, "cisa-kev", ["www.cisa.gov"])
            self.assertEqual(self.mod.check_allowlist(root), [])

    def test_allowlist_drift_when_code_uses_another_host(self):
        with self._tree() as root:
            self._write_connector(
                root, "cisa-kev", ["www.cisa.gov"], code_hosts=["evil.example"]
            )
            findings = self.mod.check_allowlist(root)
        self.assertTrue(any("evil.example" in item for item in findings))

    def test_stub_allowlist_entry_does_not_need_a_package(self):
        with self._tree() as root:
            mcp = root / "mcp"
            mcp.mkdir()
            (mcp / "egress-allowlist.yaml").write_text(
                "connectors:\n"
                "  stub:\n"
                "    hosts:\n"
                "    - example.com\n"
                "    allow_ip_literals: false\n"
                "    allow_http_loopback: false\n",
                encoding="utf-8",
            )
            self.assertEqual(self.mod.check_allowlist(root), [])

    def _tree(self):
        return _TempTree()

    def _write_distribution(self, root: Path, owned: list[str]) -> None:
        lines = [
            "name: cyber-au",
            "version: 0.1.0",
            "description: A distribution.",
            'hermes_requires: ">=0.22.2"',
            "author: Tester",
            "license: Apache-2.0",
            "distribution_owned:",
        ]
        lines.extend(f"  - {item}" for item in owned)
        (root / "distribution.yaml").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )

    def _write_skill(self, root: Path, directory: str, name: str | None = None) -> None:
        skill = root / "skills" / directory
        skill.mkdir(parents=True)
        chosen = directory if name is None else name
        text = (
            "---\n"
            f"name: {chosen}\n"
            "description: Triage an incident with Australian context.\n"
            "version: 0.1.0\n"
            "author: Tester\n"
            "license: Apache-2.0\n"
            "platforms:\n"
            "  - macos\n"
            "  - linux\n"
            "---\n"
            "\n"
            "# Incident triage\n"
        )
        (skill / "SKILL.md").write_text(text, encoding="utf-8")

    def _write_catalogue(self, root: Path, connector: str, feed_format: str) -> None:
        feeds = root / "feeds"
        feeds.mkdir()
        mcp = root / "mcp"
        mcp.mkdir()
        (mcp / "servers.yaml").write_text(
            f"servers:\n  kev:\n    connector: {connector}\n",
            encoding="utf-8",
        )
        (feeds / "catalogue.yaml").write_text(
            "version: 1\n"
            "feeds:\n"
            "  - id: kev\n"
            f"    connector: {connector}\n"
            "    url: https://www.cisa.gov/sites/default/files/feeds/known.json\n"
            f"    format: {feed_format}\n"
            "    auth:\n"
            "      type: none\n"
            "    poll: PT6H\n"
            "    licence: US Government work\n"
            "    region: global\n",
            encoding="utf-8",
        )

    def _write_connector(
        self,
        root: Path,
        key: str,
        hosts: list[str],
        code_hosts: list[str] | None = None,
    ) -> None:
        package = root / "mcp" / key
        src = package / "src"
        src.mkdir(parents=True)
        host_line = ", ".join(hosts)
        (package / "SOURCE.md").write_text(
            f"# {key}\n\n- Egress hosts: {host_line}\n",
            encoding="utf-8",
        )
        used = hosts if code_hosts is None else code_hosts
        body = "\n".join(
            f'URL_{index} = "https://{host}/feed"' for index, host in enumerate(used)
        )
        (src / "source.py").write_text(body + "\n", encoding="utf-8")
        lines = ["connectors:", f"  {key}:", "    hosts:"]
        lines.extend(f"    - {host}" for host in hosts)
        lines.extend(["    allow_ip_literals: false", "    allow_http_loopback: false"])
        (root / "mcp" / "egress-allowlist.yaml").write_text(
            "\n".join(lines) + "\n",
            encoding="utf-8",
        )


class _TempTree:
    def __enter__(self) -> Path:
        import tempfile

        self._manager = tempfile.TemporaryDirectory()
        return Path(self._manager.__enter__())

    def __exit__(self, exc_type, exc, tb) -> None:
        self._manager.__exit__(exc_type, exc, tb)


if __name__ == "__main__":
    unittest.main()

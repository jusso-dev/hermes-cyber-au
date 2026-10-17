"""Generated connector pages and the README table match this checkout."""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- connectors:start -->"
END = "<!-- connectors:end -->"
HEADINGS = (
    "## Authentication",
    "## Environment variables",
    "## Rate limits",
    "## Cache",
    "## Tools",
    "## Feeds",
    "## Terms and attribution",
)
CHECKOUT_KEYS = ("asd-acsc", "asd-ism", "cisa-kev", "first-epss", "nvd")


def load_builder():
    path = ROOT / "tools" / "build_connector_docs.py"
    spec = importlib.util.spec_from_file_location("build_connector_docs", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    # Dataclasses look the module up in sys.modules while the class body runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ConnectorDocsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = load_builder()
        cls.files = cls.docs.build(ROOT)

    def test_generated_files_match_checkout(self):
        problems = self.docs.stale_files(ROOT, self.files)
        self.assertEqual(
            problems,
            [],
            "regenerate with: uv run --project mcp python tools/build_connector_docs.py",
        )

    def test_pages_include_required_sections(self):
        for key in CHECKOUT_KEYS:
            page = self.files[f"docs/connectors/{key}.md"]
            for heading in HEADINGS:
                self.assertIn(heading, page, key)
            self.assertNotIn("\u2014", page, key)
            self.assertNotIn("\U0001f600", page, key)

    def test_readme_lists_only_checkout_connectors(self):
        region = self.files["README.md"].split(START, 1)[1].split(END, 1)[0]
        links = re.findall(r"\]\(docs/connectors/([a-z0-9-]+)\.md\)", region)
        self.assertEqual(sorted(links), sorted(CHECKOUT_KEYS))
        rows = [
            line
            for line in region.splitlines()
            if line.startswith("| ")
            and not line.startswith("| Connector")
            and not line.startswith("|---")
        ]
        self.assertEqual(len(rows), len(CHECKOUT_KEYS))
        for absent in (
            "osv",
            "abusech",
            "auscert",
            "recordedfuture",
            "cloudflare_radar",
            "virustotal",
        ):
            self.assertNotIn(absent, region)
        self.assertNotIn("https://", region)

    def test_tools_schemas_and_attribution_come_from_checkout(self):
        pages = {key: self.files[f"docs/connectors/{key}.md"] for key in CHECKOUT_KEYS}
        self.assertIn("### `asd_list_items`", pages["asd-acsc"])
        self.assertIn("### `ism_get_control`", pages["asd-ism"])
        self.assertIn("`control_id`", pages["asd-ism"])
        self.assertIn("### `kev_lookup`", pages["cisa-kev"])
        self.assertIn("### `epss_scores`", pages["first-epss"])
        self.assertIn("Response schema", pages["first-epss"])
        self.assertIn("### `nvd_get_cve`", pages["nvd"])
        self.assertIn("not endorsed by ASD", pages["asd-acsc"])
        self.assertIn("not endorsed by ASD", pages["asd-ism"])
        self.assertIn("US Government work", pages["cisa-kev"])
        self.assertIn("Cite the model version and the score date.", pages["first-epss"])
        self.assertIn("not endorsed or certified by the NVD", pages["nvd"])
        self.assertIn("`NVD_API_KEY`", pages["nvd"])
        self.assertIn("`required_env`", pages["nvd"])
        self.assertIn("`GITHUB_TOKEN`", pages["asd-ism"])
        self.assertIn("`6 * 3600`", pages["cisa-kev"])
        self.assertIn("`24 * 3600`", pages["nvd"])
        self.assertIn("`1000 / 60`", pages["first-epss"])
        self.assertIn("`15 * 60`", pages["asd-acsc"])
        self.assertIn("`7 * 86400`", pages["asd-acsc"])

    def test_missing_catalogue_does_not_invent_feeds(self):
        if (ROOT / "feeds" / "catalogue.yaml").exists():
            return
        for key in CHECKOUT_KEYS:
            page = self.files[f"docs/connectors/{key}.md"]
            self.assertIn(
                "`feeds/catalogue.yaml` is not in this checkout, so no feeds are listed.",
                page,
            )
            banner = page.split("Do not edit by hand.", 1)[0]
            self.assertNotIn("feeds/catalogue.yaml", banner)

    def test_unknown_catalogue_connector_is_not_a_row(self):
        feeds = [
            {
                "id": "kev-json",
                "connector": "cisa-kev",
                "url": "https://www.cisa.gov/example.json",
                "format": "json",
                "auth": {"type": "none"},
                "poll": "PT6H",
                "licence": "US Government work",
                "region": "global",
            },
            {
                "id": "ghost",
                "connector": "not-a-connector",
                "url": "https://example.com/ghost",
                "format": "json",
                "auth": {"type": "header", "env": "not-a-name"},
                "poll": "PT1H",
                "licence": "private",
                "region": "global",
            },
        ]
        kept = self.docs.feeds_for_connector(feeds, "cisa-kev")
        section = self.docs.render_feed_section(kept)
        self.assertIn("https://www.cisa.gov/example.json", section)
        self.assertNotIn("not-a-connector", section)
        self.assertNotIn("https://example.com/ghost", section)
        hidden = self.docs.render_feed_section(
            self.docs.feeds_for_connector(feeds, "not-a-connector")
        )
        self.assertNotIn("not-a-name", hidden)
        self.assertIn("env name omitted", hidden)

    def test_catalogue_env_placeholder_is_not_a_secret(self):
        section = self.docs.render_feed_section(
            [
                {
                    "id": "nvd",
                    "connector": "nvd",
                    "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    "format": "json",
                    "auth": {
                        "type": "header",
                        "env": "NVD_API_KEY",
                        "header": "apiKey",
                    },
                    "poll": "PT1H",
                    "licence": "NVD",
                    "region": "global",
                }
            ]
        )
        self.assertIn("${NVD_API_KEY}", section)
        self.assertIn("header `apiKey`", section)
        self.assertNotIn("apiKey=", section)

    def test_secret_guard_catches_prefixed_names(self):
        for text in (
            "NVD_API_KEY=abcdefghijklmnop1234",
            "access_token=abcdefghijklmnop1234",
            "GITHUB_TOKEN: ghp_abcdefghijklmnop1234",
            '"client_secret": "abcdefghijklmnop1234"',
        ):
            with self.assertRaises(SystemExit, msg=text):
                self.docs.assert_house_style(text, "page")
        self.docs.assert_house_style("`NVD_API_KEY=${NVD_API_KEY}`", "page")

    def test_manifest_env_must_be_a_placeholder(self):
        specs = [("nvd", {"env": ["NVD_API_KEY=abcdefghijklmnop1234"]})]
        with self.assertRaises(SystemExit):
            self.docs._apply_manifest({}, specs)
        specs = [("nvd", {"env": ["NVD_API_KEY=${NVD_API_KEY}"]})]
        uses: dict = {}
        self.assertEqual(
            self.docs._apply_manifest(uses, specs), (["NVD_API_KEY=${NVD_API_KEY}"], [])
        )

    def test_auth_cell_ignores_plain_capitals(self):
        self.assertEqual(
            self.docs.auth_cell("none. Served over TLS, JSON only."), "none"
        )
        self.assertEqual(
            self.docs.auth_cell("none. Optional GITHUB_TOKEN for releases."),
            "`GITHUB_TOKEN` (optional)",
        )

    def test_prose_ends_with_a_full_stop(self):
        self.assertEqual(
            self.docs.prose("one download a day", "x"), "One download a day."
        )
        self.assertEqual(self.docs.prose("Already done.", "x"), "Already done.")

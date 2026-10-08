"""Unit tests. No network and no writes under the real Hermes home."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from hermes_cyber_au.answer import answer_nist_trap, answer_question
from hermes_cyber_au.common import EMAIL_RE, scrub_public
from hermes_cyber_au.corpus import Corpus
from hermes_cyber_au.evalscore import sync_material_questions
from hermes_cyber_au.common import extract_control_ids, strip_emails
from hermes_cyber_au.corpus import Corpus
from hermes_cyber_au.evalscore import build_questions, score_pair
from hermes_cyber_au.fetch import FetchError, fetch_url
from hermes_cyber_au.gates import answer_gate, open_response_gate
from hermes_cyber_au.oscal import parse_catalog
from hermes_cyber_au.querycheck import check_query


def _chunk(control_id: str, text: str, version: str, published: str, valid_to: str | None, **extra) -> dict:
    return {
        "chunk_id": f"asd-ism-oscal:{version}:{control_id}",
        "source_id": "asd-ism-oscal",
        "publisher": "Australian Signals Directorate",
        "title": control_id,
        "control_id": control_id,
        "text": text,
        "version": version,
        "published": published,
        "url": "https://www.cyber.gov.au/ism",
        "valid_from": published,
        "valid_to": valid_to,
        "applicability": extra.get("applicability") or [],
        "essential_eight": extra.get("essential_eight") or [],
        "content_sha256": "abc",
    }


class FetchTests(unittest.TestCase):
    def test_http_rejected(self) -> None:
        with self.assertRaises(FetchError) as caught:
            fetch_url("http://example.com/ism", {"example.com"})
        self.assertEqual(caught.exception.code, "tls_required")

    def test_host_rejected(self) -> None:
        with self.assertRaises(FetchError) as caught:
            fetch_url("https://example.com/ism", {"www.cyber.gov.au"})
        self.assertEqual(caught.exception.code, "host_not_allowlisted")


class OscallTests(unittest.TestCase):
    def test_email_stripped_and_id_kept(self) -> None:
        document = {
            "catalog": {
                "metadata": {"version": "2026.09.4", "published": "2026-09-03T00:00:00Z"},
                "groups": [
                    {
                        "title": "Guidelines",
                        "controls": [
                            {
                                "id": "ism-1654",
                                "title": "Browser",
                                "props": [
                                    {"name": "applicability", "value": "NC"},
                                    {"name": "essential-eight-applicability", "value": "ML1"},
                                ],
                                "parts": [
                                    {
                                        "name": "statement",
                                        "prose": "Internet Explorer 11 is disabled or removed. Contact person"
                                        + chr(64)
                                        + "example.com.",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        }
        chunks, header = parse_catalog(
            document,
            git_sha="abc123",
            mirror_url="https://example.invalid/catalog",
            canonical_url="https://www.cyber.gov.au/ism",
        )
        self.assertEqual(chunks[0]["control_id"], "ism-1654")
        self.assertNotIn(chr(64), chunks[0]["text"])
        self.assertIn("[redacted-email]", chunks[0]["text"])
        self.assertEqual(header["version"], "2026.09.4")
        sample = "a" + chr(64) + "b.com"
        self.assertEqual(strip_emails(sample), "[redacted-email]")


class AnswerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = Corpus(
            [
                _chunk("ism-1654", "Internet Explorer 11 is disabled or removed.", "2026.06.1", "2026-06-01", "2026-09-02"),
                _chunk("ism-1654", "Internet Explorer 11 is disabled or removed.", "2026.09.4", "2026-09-03", None, applicability=["NC"], essential_eight=["ML1"]),
            ]
        )

    def test_unknown(self) -> None:
        answer = answer_question({"kind": "unknown_id", "question": "What does control ism-99999 require?"}, self.corpus)
        self.assertIn("I don't know.", answer)
        self.assertNotIn("ism-99999", answer.lower())

    def test_as_of_selects_earlier_version(self) -> None:
        answer = answer_question(
            {"kind": "as_of", "control_id": "ism-1654", "as_of": "2026-06-30", "question": "June"},
            self.corpus,
        )
        self.assertIn("2026.06.1", answer)
        self.assertNotIn("2026.09.4", answer)

    def test_nist_trap_has_no_catalogue_id(self) -> None:
        answer = answer_nist_trap()
        self.assertIn("I don't know.", answer)
        self.assertEqual(extract_control_ids(answer), [])
        catalogue = self.corpus.catalogue_ids()
        scored = score_pair(
            {"kind": "nist_trap", "question": "Which NIST ID?", "must_say_unknown": True, "forbid_any_catalogue_id": True},
            answer,
            catalogue,
        )
        self.assertTrue(scored["ok"])
        invented = score_pair(
            {"kind": "control_lookup", "question": "What does the backup control require?", "expected_ids": []},
            "Use ism-1655 for backups.",
            catalogue,
        )
        self.assertIn("ism-1655", invented["invented"])

    def test_generator_includes_query_checks(self) -> None:
        questions = build_questions(self.corpus)
        kinds = {row["kind"] for row in questions}
        self.assertIn("query_check", kinds)
        self.assertIn("unknown_id", kinds)
        self.assertGreaterEqual(len(questions), 20)


class GateTests(unittest.TestCase):
    def test_approval_does_not_execute(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            opened = open_response_gate("isolate-host", "workstation", "Propose isolation. Do not run it.", home)
            self.assertFalse(opened["executed"])
            if opened.get("backend") == "omh":
                return
            answered = answer_gate(opened["gate_id"], "approve", "tester", home)
            self.assertFalse(answered["executed"])
            self.assertIn("Propose isolation", answered["proposal"])
            with self.assertRaises(ValueError):
                answer_gate(opened["gate_id"], "approve", "tester", home)


class QueryTests(unittest.TestCase):
    def test_ready_and_refused(self) -> None:
        good = check_query("kql", 'DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n| project DeviceName')
        self.assertTrue(good["ready"], good)
        bad = check_query("kql", ".drop table DeviceProcessEvents")
        self.assertFalse(bad["ready"])
        write = check_query("sql", "-- cyber-au-schema: cloudtrail_lake\nINSERT INTO t SELECT eventname FROM events")
        self.assertFalse(write["ready"])
        sql = check_query("sql", "-- cyber-au-schema: cloudtrail_lake\nSELECT eventname, useridentity.arn FROM events")
        self.assertTrue(sql["ready"], sql)


class RegisterTests(unittest.TestCase):
    def test_register_records_tools(self) -> None:
        from hermes_cyber_au.plugin import register

        calls = {"tools": [], "skills": [], "cli": []}

        class Ctx:
            def register_tool(self, **kwargs):
                calls["tools"].append(kwargs["name"])

            def register_skill(self, name, path, description=""):
                calls["skills"].append(name)

            def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
                calls["cli"].append(name)

        register(Ctx())
        self.assertIn("cyber_au_control", calls["tools"])
        self.assertIn("ism-control-lookup", calls["skills"])
        self.assertEqual(calls["cli"], ["cyber-au"])


class PersonaTests(unittest.TestCase):
    def test_splice_keeps_existing_text(self) -> None:
        from hermes_cyber_au.cli import apply_persona

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "SOUL.md"
            path.write_text("Keep this line.\n", encoding="utf-8")
            apply_persona(path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("Keep this line.", text)
            self.assertIn("hermes-cyber-au:start", text)
            apply_persona(path)
            self.assertEqual(text.count("hermes-cyber-au:start"), 1)


class HygieneTests(unittest.TestCase):
    def test_repo_has_no_banned_literals(self) -> None:
        root = Path(__file__).resolve().parents[1]
        banned = ("yu" + "ma", "esa" + "fety", "ac" + "ma", "/Volumes/Mac" + "Mini", "tail" + "scale")
        skip = {".git", "__pycache__", "index.sqlite"}
        hits = []
        for path in root.rglob("*"):
            if not path.is_file() or any(part in skip for part in path.parts):
                continue
            if path.suffix.lower() in {".png", ".jpg", ".sqlite"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeError:
                continue
            lowered = text.lower()
            for word in banned:
                if word in lowered:
                    hits.append(f"{path}:{word}")
            if "\u2014" in text or "\u2013" in text:
                hits.append(f"{path}:dash")
            if EMAIL_RE.search(text):
                hits.append(f"{path}:email")
        self.assertEqual(hits, [])

    def test_scrub_and_material_questions(self) -> None:
        sample = "see " + "yu" + "ma" + " now " + "\u2014" + " next"
        cleaned = scrub_public(sample)
        self.assertNotIn("yu" + "ma", cleaned.lower())
        self.assertNotIn("\u2014", cleaned)
        chunk = {
            "source_id": "asd-ism-oscal",
            "control_id": "ism-1001",
            "version": "2026.09.4",
            "text": "Keep the door locked.",
            "valid_to": None,
            "applicability": ["OS"],
            "essential_eight": [],
        }
        corpus = Corpus([chunk])
        existing = [
            {
                "id": "ism-lookup-000",
                "kind": "control_lookup",
                "control_id": "ism-1001",
                "must_include": "old text",
                "version": "2026.06.18",
                "expected_ids": ["ism-1001"],
            }
        ]
        result = sync_material_questions(
            {"new": [], "changed": ["ism-1001"], "withdrawn": ["ism-1002"]},
            corpus=corpus,
            questions=existing,
            write=False,
        )
        self.assertEqual(result["updated"], 1)
        self.assertEqual(result["added"], 1)
        self.assertEqual(existing[0]["must_include"], "Keep the door locked.")
        self.assertEqual(existing[1]["kind"], "unknown_id")

    def test_follow_skips_listing_filters(self) -> None:
        from hermes_cyber_au.refresh import _same_host_link, _worth_following

        hosts = {"www.cyber.gov.au"}
        listing = _same_host_link(
            "https://www.cyber.gov.au/alerts-and-advisories",
            "/alerts-and-advisories?f%5B0%5D=content_type%3Aalert",
            hosts,
        )
        article = _same_host_link(
            "https://www.cyber.gov.au/alerts-and-advisories",
            "/alert/example-title?ref=search",
            hosts,
        )
        self.assertFalse(_worth_following(listing))
        self.assertEqual(article, "https://www.cyber.gov.au/alert/example-title")
        self.assertTrue(_worth_following(article))
        self.assertFalse(_worth_following("https://www.cyber.gov.au/report-a-cyber-security-incident"))

    def test_atlas_parser_skips_case_studies(self) -> None:
        from hermes_cyber_au.refresh import _atlas_entries

        text = """techniques:
  AML.T0000:
    name: Search Open Technical Databases
    description: 'Adversaries may search.
      More text.'
    references: []
case-studies:
  AML.CS0000:
    name: Do not keep
"""
        entries = _atlas_entries(text)
        self.assertEqual(entries, [("AML.T0000", "Search Open Technical Databases", "Adversaries may search. More text.")])


class LiveOffTests(unittest.TestCase):
    def test_live_query_off_without_env(self) -> None:
        from hermes_cyber_au.live import live_query

        with tempfile.TemporaryDirectory() as tmp:
            for name in (
                "CYBER_AU_SENTINEL_TENANT_ID",
                "CYBER_AU_SENTINEL_CLIENT_ID",
                "CYBER_AU_SENTINEL_CLIENT_SECRET",
                "CYBER_AU_SENTINEL_WORKSPACE_ID",
                "CYBER_AU_AWS_REGION",
            ):
                os.environ.pop(name, None)
            result = live_query(
                "sentinel",
                'DeviceProcessEvents\n| where FileName =~ "x"\n| project DeviceName',
                home=Path(tmp),
                transport=lambda kind, query: {"row_count": 1},
            )
            self.assertFalse(result["executed"])


if __name__ == "__main__":
    unittest.main()

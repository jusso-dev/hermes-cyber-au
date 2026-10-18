"""Tests for tools/ci/style_check.py. No network."""

from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "tools" / "ci" / "style_check.py"
    spec = importlib.util.spec_from_file_location("cyberau_ci_style_check", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class StyleCheckTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load()

    def test_repository_has_no_style_errors(self):
        errors, _hints = self.mod.check(ROOT)
        self.assertEqual(errors, [])

    def test_main_on_repository(self):
        self.assertEqual(self.mod.main(["--root", str(ROOT)]), 0)

    def test_em_dash_fails(self):
        with _TempTree() as root:
            (root / "notes.md").write_text("A pause \u2014 then more.\n", encoding="utf-8")
            errors, hints = self.mod.check(root)
        self.assertTrue(any(item.endswith("em dash") for item in errors))
        self.assertEqual(hints, [])

    def test_emoji_fails(self):
        with _TempTree() as root:
            (root / "notes.md").write_text("Ship it \U0001f680\n", encoding="utf-8")
            errors, _hints = self.mod.check(root)
        self.assertTrue(any(item.endswith("emoji") for item in errors))

    def test_banned_private_name_is_reported_without_the_name(self):
        secret = "tailnet-host.example"
        with _TempTree() as root:
            names = root / "banned.sha256"
            digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
            names.write_text(digest + "\n", encoding="utf-8")
            (root / "notes.md").write_text(f"See {secret} for the box.\n", encoding="utf-8")
            errors, _hints = self.mod.check(root, names_file=names)
        self.assertTrue(any(item.endswith("banned private name") for item in errors))
        for item in errors:
            self.assertNotIn(secret, item)

    def test_private_phrase_matches_a_hash(self):
        secret = "private hostname"
        with _TempTree() as root:
            (root / "notes.md").write_text("Use the private hostname here.\n", encoding="utf-8")
            errors, _hints = self.mod.check(root, extra_names=[secret])
        self.assertTrue(any("banned private name" in item for item in errors))
        for item in errors:
            self.assertNotIn(secret, item)

    def test_banned_name_is_found_through_punctuation(self):
        digests = {
            "acme": "Contact Acme.\n",
            "blue falcon": "Ask Blue Falcon.\n",
        }
        for name, text in digests.items():
            with _TempTree() as root:
                (root / "notes.md").write_text(text, encoding="utf-8")
                errors, _hints = self.mod.check(root, extra_names=[name])
            self.assertTrue(any(item.endswith("banned private name") for item in errors), text)

    def test_banned_name_is_found_inside_hostnames_and_identifiers(self):
        for text in ("host git.acme.internal\n", "acme_corp and Acme-Corp\n"):
            with _TempTree() as root:
                (root / "notes.md").write_text(text, encoding="utf-8")
                errors, _hints = self.mod.check(root, extra_names=["acme"])
            self.assertTrue(any(item.endswith("banned private name") for item in errors), text)

    def test_unrelated_word_is_not_banned(self):
        with _TempTree() as root:
            (root / "notes.md").write_text("Acmeville is fine.\n", encoding="utf-8")
            errors, _hints = self.mod.check(root, extra_names=["acme"])
        self.assertEqual(errors, [])

    def test_look_alike_dash_and_extra_emoji_fail(self):
        for char, label in (
            ("\u2015", "em dash"),
            ("\u2b50", "emoji"),
            ("\u23f0", "emoji"),
        ):
            with _TempTree() as root:
                (root / "notes.md").write_text(f"a {char} b\n", encoding="utf-8")
                errors, _hints = self.mod.check(root)
            self.assertTrue(any(item.endswith(label) for item in errors), char)

    def test_data_directory_is_scanned_outside_mcp(self):
        with _TempTree() as root:
            (root / "skills" / "data").mkdir(parents=True)
            (root / "skills" / "data" / "notes.md").write_text(
                "A pause \u2014 then more.\n", encoding="utf-8"
            )
            (root / "mcp" / "x" / "data").mkdir(parents=True)
            (root / "mcp" / "x" / "data" / "feed.md").write_text(
                "Upstream \u2014 text.\n", encoding="utf-8"
            )
            errors, _hints = self.mod.check(root)
        self.assertEqual(len(errors), 1)
        self.assertIn("skills/data/notes.md", errors[0])

    def test_american_spelling_is_a_hint(self):
        with _TempTree() as root:
            (root / "notes.md").write_text("Please organize the report.\n", encoding="utf-8")
            errors, hints = self.mod.check(root)
        self.assertEqual(errors, [])
        self.assertTrue(any("organise" in item for item in hints))

    def test_capitalised_product_name_is_not_a_hint(self):
        with _TempTree() as root:
            (root / "notes.md").write_text(
                "Sign in at the Integration Center.\n",
                encoding="utf-8",
            )
            errors, hints = self.mod.check(root)
        self.assertEqual(errors, [])
        self.assertEqual(hints, [])

    def test_clean_prose_passes(self):
        with _TempTree() as root:
            (root / "notes.md").write_text(
                "Use Australian spelling and plain language.\n",
                encoding="utf-8",
            )
            errors, hints = self.mod.check(root)
        self.assertEqual(errors, [])
        self.assertEqual(hints, [])

    def test_added_name_is_caught_by_the_hash_file(self):
        with _TempTree() as root:
            names = root / "tools" / "ci" / "private_names.sha256"
            names.parent.mkdir(parents=True)
            names.write_text("# header\n", encoding="utf-8")
            self.assertTrue(self.mod.add_name(names, "  Blue   Falcon. "))
            self.assertFalse(self.mod.add_name(names, "blue falcon"))
            stored = names.read_text(encoding="utf-8")
            self.assertNotIn("falcon", stored.lower())
            (root / "notes.md").write_text("Ask Blue-Falcon first.\n", encoding="utf-8")
            errors, _hints = self.mod.check(root)
        self.assertTrue(any(item.endswith("banned private name") for item in errors))

    def test_add_name_refuses_empty_and_unmatchable_names(self):
        with _TempTree() as root:
            names = root / "private_names.sha256"
            with self.assertRaises(ValueError):
                self.mod.add_name(names, " -- ")
            with self.assertRaises(ValueError):
                self.mod.add_name(names, "one two three four five")

    def test_empty_list_warns_and_require_names_fails(self):
        import contextlib
        import io
        import os
        from unittest import mock

        with _TempTree() as root:
            names = root / "tools" / "ci" / "private_names.sha256"
            names.parent.mkdir(parents=True)
            names.write_text("# no hashes yet\n", encoding="utf-8")
            (root / "notes.md").write_text("Plain text.\n", encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("CYBERAU_")}
            env["GITHUB_ACTIONS"] = "true"
            out = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out):
                self.assertEqual(self.mod.main(["--root", str(root)]), 0)
                self.assertEqual(self.mod.main(["--root", str(root), "--require-names"]), 1)
            self.assertIn("::warning title=Private name check inactive::", out.getvalue())
            self.mod.add_name(names, "example private")
            with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out):
                self.assertEqual(self.mod.main(["--root", str(root), "--require-names"]), 0)


class _TempTree:
    def __enter__(self) -> Path:
        import tempfile

        self._manager = tempfile.TemporaryDirectory()
        return Path(self._manager.__enter__())

    def __exit__(self, exc_type, exc, tb) -> None:
        self._manager.__exit__(exc_type, exc, tb)


if __name__ == "__main__":
    unittest.main()

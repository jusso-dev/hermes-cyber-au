"""Checks for the cyber-au plugin skeleton. No network and no Hermes install."""

from __future__ import annotations

import argparse
import builtins
import importlib.util
import inspect
import json
import os
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "plugins" / "cyber-au"
MODULE = "cyberau_plugin_under_test"

# Hermes v0.22.2 (43faacf), hermes_cli/plugins_manifest.py _KNOWN_MANIFEST_FIELDS.
KNOWN_MANIFEST_FIELDS = {
    "name",
    "version",
    "description",
    "author",
    "requires_env",
    "provides_tools",
    "provides_hooks",
    "kind",
    "hooks",
    "label",
    "optional_env",
    "platforms",
    "external_dependencies",
    "pip_dependencies",
    "provides_browser_providers",
    "provides_web_providers",
    "manifest_version",
    "api_version",
    "requires_plugins",
    "python_dependencies",
    "config_schema",
    "license",
    "homepage",
    "tags",
    "capabilities",
    "emits",
    "listens",
    "hermes",
    "depends",
    "requires_hermes",
    "python_runtime",
    "provides_locales",
    "requires_auth",
}
TOOLS = [
    "intel_search",
    "intel_get",
    "intel_add_observation",
    "intel_export_stix",
    "evidence_import",
]
HOOKS = ["pre_tool_call", "post_tool_call", "on_session_start", "on_session_end"]
SECRET = "fixture-secret-value"


def _purge() -> None:
    for name in list(sys.modules):
        if name == MODULE or name.startswith(MODULE + "."):
            del sys.modules[name]


def load_plugin():
    _purge()
    init = PLUGIN_DIR / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        MODULE,
        init,
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {init}")
    module = importlib.util.module_from_spec(spec)
    module.__package__ = MODULE
    module.__path__ = [str(PLUGIN_DIR)]
    sys.modules[MODULE] = module
    spec.loader.exec_module(module)
    return module


class FakeCtx:
    """Records registrations. It does not import Hermes."""

    def __init__(self) -> None:
        self.tools: dict[str, dict] = {}
        self.hooks: dict[str, list] = {}
        self.middleware: dict[str, list] = {}
        self.cli: dict[str, dict] = {}
        self.commands: dict[str, dict] = {}

    def register_tool(self, name, toolset, schema, handler, **kwargs) -> None:
        self.tools[name] = {
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
            "extra": kwargs,
        }

    def register_hook(self, hook_name, callback) -> None:
        self.hooks.setdefault(hook_name, []).append(callback)

    def register_middleware(self, kind, callback) -> None:
        self.middleware.setdefault(kind, []).append(callback)

    def register_cli_command(self, name, help, setup_fn, handler_fn=None, description="") -> None:
        self.cli[name] = {
            "help": help,
            "setup_fn": setup_fn,
            "handler_fn": handler_fn,
            "description": description,
        }

    def register_command(self, name, handler, description="", args_hint="") -> None:
        self.commands[name] = {
            "handler": handler,
            "description": description,
            "args_hint": args_hint,
        }


class PluginSkeletonTest(unittest.TestCase):
    def setUp(self) -> None:
        started = time.perf_counter()
        self.plugin = load_plugin()
        self.ctx = FakeCtx()
        self.plugin.register(self.ctx)
        self.elapsed = time.perf_counter() - started

    def tearDown(self) -> None:
        _purge()

    def test_manifest_matches_pinned_hermes_and_the_ticket(self) -> None:
        manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8"))
        self.assertLessEqual(set(manifest), KNOWN_MANIFEST_FIELDS)
        self.assertEqual(
            set(manifest),
            {
                "name",
                "version",
                "manifest_version",
                "api_version",
                "description",
                "author",
                "license",
                "homepage",
                "provides_tools",
                "provides_hooks",
                "python_dependencies",
                "config_schema",
            },
        )
        self.assertEqual(manifest["name"], "cyber-au")
        self.assertEqual(manifest["version"], "0.1.0")
        self.assertEqual(manifest["manifest_version"], 2)
        self.assertEqual(manifest["api_version"], 1)
        self.assertEqual(manifest["author"], "Justin Middler")
        self.assertEqual(manifest["license"], "Apache-2.0")
        self.assertEqual(manifest["homepage"], "https://github.com/jusso-dev/hermes-cyber-au")
        self.assertEqual(manifest["provides_tools"], TOOLS)
        self.assertEqual(manifest["provides_hooks"], HOOKS)
        self.assertEqual(manifest["python_dependencies"], ["stix2>=3,<4"])
        schema = manifest["config_schema"]
        self.assertEqual(schema["audit_log_path"]["type"], "str")
        self.assertEqual(schema["audit_log_path"]["default"], "")
        self.assertEqual(schema["untrusted_banner"]["type"], "bool")
        self.assertIs(schema["untrusted_banner"]["default"], True)

    def test_registered_tools_and_hooks_match_the_manifest(self) -> None:
        self.assertEqual(list(self.ctx.tools), TOOLS)
        self.assertEqual(list(self.ctx.hooks), HOOKS)
        for name, registered in self.ctx.tools.items():
            self.assertEqual(registered["toolset"], "cyber-au")
            self.assertEqual(registered["schema"]["name"], name)
            self.assertIn("not installed yet", registered["schema"]["description"])

    def test_tools_report_that_they_are_not_installed_and_do_not_echo_input(self) -> None:
        secret_args = {
            "query": SECRET,
            "id_or_value": SECRET,
            "value": SECRET,
            "path": SECRET,
            "note": SECRET,
        }
        expected = {
            "intel_search": "The intel store is not installed yet.",
            "intel_get": "The intel store is not installed yet.",
            "intel_add_observation": "The intel store is not installed yet.",
            "intel_export_stix": "STIX export is not installed yet.",
            "evidence_import": "Evidence import is not installed yet.",
        }
        for name, message in expected.items():
            raw = self.ctx.tools[name]["handler"](secret_args, task_id="t")
            payload = json.loads(raw)
            self.assertFalse(payload["installed"])
            self.assertEqual(payload["message"], message)
            self.assertNotIn(SECRET, raw)

    def test_hooks_accept_kwargs_swallow_failures_and_do_not_block(self) -> None:
        audit = sys.modules[f"{MODULE}.hooks.audit"]
        original = audit._run

        def boom(event: str) -> None:
            raise OSError(f"unavailable {event}")

        audit._run = boom
        try:
            for name, callbacks in self.ctx.hooks.items():
                self.assertEqual(len(callbacks), 1)
                callback = callbacks[0]
                parameters = inspect.signature(callback).parameters.values()
                self.assertTrue(
                    any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters)
                )
                with self.assertLogs(audit.__name__, level="ERROR") as captured:
                    result = callback(
                        tool_name="terminal",
                        args={"command": SECRET},
                        result=SECRET,
                        task_id="task",
                        duration_ms=1,
                        session_id=SECRET,
                    )
                self.assertIsNone(result)
                logged = "\n".join(captured.output)
                self.assertIn(name, logged)
                self.assertNotIn(SECRET, logged)
                self.assertNotIn('"action"', logged)
        finally:
            audit._run = original

    def test_hooks_say_the_audit_log_is_not_installed(self) -> None:
        audit = sys.modules[f"{MODULE}.hooks.audit"]
        callback = self.ctx.hooks["on_session_start"][0]
        with self.assertLogs(audit.__name__, level="DEBUG") as captured:
            self.assertIsNone(callback(session_id=SECRET))
        logged = "\n".join(captured.output)
        self.assertIn(audit.AUDIT_NOT_INSTALLED, logged)
        self.assertNotIn(SECRET, logged)

    def test_middleware_passes_the_call_through(self) -> None:
        guard = sys.modules[f"{MODULE}.middleware.untrusted"]
        callbacks = self.ctx.middleware["tool_execution"]
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(set(self.ctx.middleware), {"tool_execution"})
        seen: list[dict] = []

        def next_call(payload):
            seen.append(payload)
            return "downstream"

        with self.assertLogs(guard.__name__, level="DEBUG") as captured:
            result = callbacks[0](
                next_call=next_call,
                args={"query": SECRET},
                tool_name="intel_search",
            )
        self.assertEqual(result, "downstream")
        self.assertEqual(seen, [{"query": SECRET}])
        logged = "\n".join(captured.output)
        self.assertIn(guard.GUARD_NOT_INSTALLED, logged)
        self.assertNotIn(SECRET, logged)

    def test_cli_and_slash_commands_are_stubs(self) -> None:
        cli = sys.modules[f"{MODULE}.cli"]
        self.assertEqual(set(self.ctx.cli), {"cyber-au"})
        self.assertEqual(set(self.ctx.commands), {"cyber-au"})
        entry = self.ctx.cli["cyber-au"]
        self.assertIs(entry["handler_fn"], cli.handle_cli)
        parser = argparse.ArgumentParser(prog="hermes")
        subparsers = parser.add_subparsers(dest="plugin_command")
        plugin = subparsers.add_parser("cyber-au")
        entry["setup_fn"](plugin)
        for command, message in (
            ("doctor", "cyber-au doctor is not installed yet."),
            ("bootstrap", "cyber-au bootstrap is not installed yet."),
            ("store", "The intel store is not installed yet."),
            ("export", "STIX export is not installed yet."),
        ):
            args = parser.parse_args(["cyber-au", command])
            self.assertEqual(cli.command_message(command), message)
            self.assertEqual(entry["handler_fn"](args), message)
            slash = self.ctx.commands["cyber-au"]["handler"]
            self.assertEqual(slash(f"{command} {SECRET}"), message)
        usage = cli.command_message(f"audit {SECRET}")
        self.assertIn("not installed yet", usage)
        self.assertNotIn(SECRET, usage)
        self.assertNotIn("audit", usage)

    def test_cli_stubs_answer_for_flags_that_ship_later(self) -> None:
        cli = sys.modules[f"{MODULE}.cli"]
        entry = self.ctx.cli["cyber-au"]
        parser = argparse.ArgumentParser(prog="hermes")
        plugin = parser.add_subparsers(dest="plugin_command").add_parser("cyber-au")
        entry["setup_fn"](plugin)
        for argv, message in (
            (["doctor", "--offline", "--json", "--fix"], "cyber-au doctor is not installed yet."),
            (["bootstrap", "--non-interactive"], "cyber-au bootstrap is not installed yet."),
            (["store", "stats"], "The intel store is not installed yet."),
            (["export", "--since", "2026-01-01"], "STIX export is not installed yet."),
        ):
            args = parser.parse_args(["cyber-au", *argv])
            self.assertEqual(entry["handler_fn"](args), message)
            self.assertEqual(cli.command_message(argv[0]), message)

    def test_stubs_do_not_open_or_write_any_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.docx"
            report.write_bytes(b"fixture")
            data = Path(tmp) / "data"
            args = {"path": str(report), "note": SECRET}

            def refuse(*_args, **_kwargs):
                raise AssertionError("a stub touched the filesystem")

            with (
                mock.patch.dict(os.environ, {"CYBERAU_DATA_DIR": str(data)}),
                mock.patch.object(builtins, "open", refuse),
                mock.patch.object(os, "open", refuse),
                mock.patch.object(Path, "open", refuse),
            ):
                for name, registered in self.ctx.tools.items():
                    registered["handler"](args, task_id="t")
                for callbacks in self.ctx.hooks.values():
                    self.assertIsNone(callbacks[0](tool_name="evidence_import", args=args))
            self.assertFalse(data.exists())
            self.assertEqual(report.read_bytes(), b"fixture")
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["report.docx"])

    def test_data_dir_uses_the_environment_and_does_not_create_it(self) -> None:
        override = ROOT / "plugin-data-should-not-exist"
        previous = os.environ.get("CYBERAU_DATA_DIR")
        os.environ["CYBERAU_DATA_DIR"] = str(override)
        try:
            self.assertEqual(self.plugin.data_dir(), override)
        finally:
            if previous is None:
                os.environ.pop("CYBERAU_DATA_DIR", None)
            else:
                os.environ["CYBERAU_DATA_DIR"] = previous
        self.assertFalse(override.exists())

    def test_load_and_register_stay_under_300ms(self) -> None:
        self.assertLess(self.elapsed, 0.3)

    def test_sources_have_no_em_dash_emoji_or_secret_material(self) -> None:
        banned = ("\u2014", "\u2013", "sk-", "AKIA", "BEGIN PRIVATE", "ghp_", "xoxb-")
        python_files = list(PLUGIN_DIR.rglob("*.py"))
        self.assertGreaterEqual(len(python_files), 6)
        for path in python_files:
            text = path.read_text(encoding="utf-8")
            for token in banned:
                self.assertNotIn(token, text, f"{path.name} contains {token!r}")
            self.assertNotIn("import stix2", text)
            self.assertNotIn("open(", text)
        prose = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
        self.assertNotIn("\u2014", prose)
        self.assertNotIn("\u2013", prose)

    def test_middleware_callback_is_callable(self) -> None:
        callback = self.ctx.middleware["tool_execution"][0]
        self.assertIsInstance(callback, Callable)


if __name__ == "__main__":
    unittest.main()

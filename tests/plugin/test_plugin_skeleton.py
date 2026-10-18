"""Checks for the cyber-au plugin entrypoint. No network and no Hermes install.

The plugin started as a skeleton of stubs. The audit hooks, feed guard, org
exposure tool, doctor, update and migrate commands have since landed, so these
checks pin the registration contract. The intel store and evidence tools are
still stubs and keep their not-installed checks.
"""

from __future__ import annotations

import argparse
import builtins
import contextlib
import importlib.util
import inspect
import io
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
STUB_TOOLS = [
    "intel_search",
    "intel_get",
    "intel_add_observation",
    "intel_export_stix",
    "evidence_import",
]
TOOLS = [*STUB_TOOLS, "cyber_au_org_exposure"]
HOOKS = ["pre_tool_call", "post_tool_call", "pre_llm_call", "on_session_start", "on_session_end"]
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
        # Audit hooks write under the data directory, so keep them off the real home.
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.data = Path(scratch.name) / "plugin-data"
        environ = mock.patch.dict(os.environ, {"CYBERAU_DATA_DIR": str(self.data)})
        environ.start()
        self.addCleanup(environ.stop)
        os.environ.pop("CYBERAU_AUDIT_LOG_PATH", None)
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
        self.assertEqual(manifest["python_dependencies"], ["pyyaml>=6,<7", "stix2>=3,<4"])
        schema = manifest["config_schema"]
        self.assertEqual(schema["audit_log_path"]["type"], "str")
        self.assertEqual(schema["audit_log_path"]["default"], "")
        self.assertEqual(schema["untrusted_banner"]["type"], "bool")
        self.assertIs(schema["untrusted_banner"]["default"], True)

    def test_registered_tools_and_hooks_match_the_manifest(self) -> None:
        self.assertEqual(list(self.ctx.tools), TOOLS)
        self.assertEqual(set(self.ctx.hooks), set(HOOKS))
        for name, registered in self.ctx.tools.items():
            self.assertEqual(registered["toolset"], "cyber-au")
            self.assertEqual(registered["schema"]["name"], name)
            if name in STUB_TOOLS:
                self.assertIn("not installed yet", registered["schema"]["description"])

    def test_tool_handlers_take_the_hermes_argument_dict(self) -> None:
        for name, registered in self.ctx.tools.items():
            parameters = list(inspect.signature(registered["handler"]).parameters.values())
            self.assertTrue(parameters, name)
            self.assertIn(
                parameters[0].kind,
                (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD),
                name,
            )
            self.assertIs(parameters[-1].kind, inspect.Parameter.VAR_KEYWORD, name)

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

    def _call_hook(self, callback, tool_name: str):
        return callback(
            tool_name=tool_name,
            args={"query": "fixture"},
            result="{}",
            task_id="task",
            duration_ms=1,
            session_id="session",
            turn_id="turn",
            user_message="hello",
            unknown_host_field=True,
        )

    def test_hooks_accept_kwargs_and_let_a_read_tool_through(self) -> None:
        guard = sys.modules[f"{MODULE}.middleware.untrusted"]
        guard.reset_state()
        for name, callbacks in self.ctx.hooks.items():
            self.assertTrue(callbacks, name)
            for callback in callbacks:
                kinds = {item.kind for item in inspect.signature(callback).parameters.values()}
                self.assertIn(inspect.Parameter.VAR_KEYWORD, kinds, name)
                self.assertIsNone(self._call_hook(callback, "intel_search"), name)

    def test_audit_hooks_write_the_chain_under_the_data_dir(self) -> None:
        for callback in self.ctx.hooks["on_session_start"]:
            self.assertIsNone(callback(session_id="session", platform="cli"))
        for callback in self.ctx.hooks["pre_tool_call"]:
            self.assertIsNone(callback(tool_name="intel_search", args={}, task_id="t"))
        for callback in self.ctx.hooks["post_tool_call"]:
            callback(tool_name="intel_search", args={}, result="{}", task_id="t", duration_ms=1)
        days = list((self.data / "audit").glob("*.jsonl"))
        self.assertEqual(len(days), 1)
        events = [json.loads(line)["event"] for line in days[0].read_text("utf-8").splitlines()]
        self.assertIn("session_start", events)

    def test_unwritable_audit_log_blocks_writes_but_not_reads(self) -> None:
        blocker = self.data.parent / "not-a-directory"
        blocker.write_text("", encoding="utf-8")
        with mock.patch.dict(os.environ, {"CYBERAU_AUDIT_LOG_PATH": str(blocker / "audit")}):
            results = [
                self._call_hook(callback, "write_file")
                for callback in self.ctx.hooks["pre_tool_call"]
            ]
            blocks = [item for item in results if isinstance(item, dict)]
            self.assertTrue(blocks)
            self.assertTrue(all(item["action"] == "block" for item in blocks))
            for callback in self.ctx.hooks["pre_tool_call"]:
                self.assertIsNone(self._call_hook(callback, "intel_search"))

    def test_middleware_passes_the_call_through(self) -> None:
        guard = sys.modules[f"{MODULE}.middleware.untrusted"]
        callbacks = self.ctx.middleware["tool_execution"]
        self.assertEqual(callbacks, [guard.tool_execution])
        self.assertEqual(set(self.ctx.middleware), {"tool_execution"})
        seen: list[dict] = []

        def next_call(payload):
            seen.append(payload)
            return "downstream"

        result = callbacks[0](
            next_call=next_call,
            args={"query": SECRET},
            tool_name="intel_search",
        )
        self.assertEqual(result, "downstream")
        self.assertEqual(seen, [{"query": SECRET}])

    def _cli_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="hermes")
        plugin = parser.add_subparsers(dest="plugin_command").add_parser("cyber-au")
        self.ctx.cli["cyber-au"]["setup_fn"](plugin)
        return parser

    def test_one_cli_command_and_one_slash_command(self) -> None:
        cli = sys.modules[f"{MODULE}.cli"]
        self.assertEqual(set(self.ctx.cli), {"cyber-au"})
        self.assertEqual(set(self.ctx.commands), {"cyber-au"})
        entry = self.ctx.cli["cyber-au"]
        self.assertIs(entry["handler_fn"], cli.handle)
        self.assertIs(entry["setup_fn"], cli.setup_parser)
        self.assertIs(self.ctx.commands["cyber-au"]["handler"], cli.slash)

    def test_cli_parses_every_shipped_subcommand(self) -> None:
        parser = self._cli_parser()
        doctor = parser.parse_args(["cyber-au", "doctor", "--offline", "--json", "--fix"])
        self.assertEqual(doctor.cyberau_command, "doctor")
        self.assertTrue(doctor.offline and doctor.json and doctor.fix)
        update = parser.parse_args(
            ["cyber-au", "update", "--source", "/src", "--to", "v0.1.0", "--force-config"]
        )
        self.assertEqual(update.cyberau_command, "update")
        self.assertEqual((update.source, update.to_tag), (Path("/src"), "v0.1.0"))
        self.assertTrue(update.force_config)
        migrate = parser.parse_args(["cyber-au", "migrate", "--migrations", "/m"])
        self.assertEqual((migrate.cyberau_command, migrate.migrations), ("migrate", Path("/m")))
        verify = parser.parse_args(["cyber-au", "audit", "verify", "--from", "2026-01-01"])
        self.assertEqual((verify.cyberau_command, verify.audit_command), ("audit", "verify"))
        export = parser.parse_args(
            ["cyber-au", "audit", "export", "--since", "2026-01-01", "--format", "csv"]
        )
        self.assertEqual((export.audit_command, export.export_format), ("export", "csv"))

    def test_cli_audit_verify_runs_against_the_data_dir(self) -> None:
        args = self._cli_parser().parse_args(["cyber-au", "audit", "verify"])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(self.ctx.cli["cyber-au"]["handler_fn"](args), 0)
        self.assertIn("audit chain verified", stdout.getvalue())

    def test_migrate_without_a_profile_home_is_refused(self) -> None:
        args = self._cli_parser().parse_args(["cyber-au", "migrate"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.ctx.cli["cyber-au"]["handler_fn"](args), 2)

    def test_slash_command_answers_usage_without_echoing_input(self) -> None:
        slash = self.ctx.commands["cyber-au"]["handler"]
        for raw in (f"store {SECRET}", f"audit {SECRET}", "", '"unbalanced'):
            usage = slash(raw)
            self.assertTrue(usage.startswith("Usage: /cyber-au doctor"), raw)
            self.assertNotIn(SECRET, usage)

    def test_stub_tools_do_not_open_or_write_any_path(self) -> None:
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
                for name in STUB_TOOLS:
                    self.ctx.tools[name]["handler"](args, task_id="t")
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
        # The remaining stubs must not touch the filesystem. Implemented modules
        # (doctor, update, store) read and write files by design.
        for stub in ("tools/store.py", "tools/evidence.py"):
            self.assertNotIn("open(", (PLUGIN_DIR / stub).read_text(encoding="utf-8"), stub)
        prose = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
        self.assertNotIn("\u2014", prose)
        self.assertNotIn("\u2013", prose)

    def test_middleware_callback_is_callable(self) -> None:
        callback = self.ctx.middleware["tool_execution"][0]
        self.assertIsInstance(callback, Callable)


if __name__ == "__main__":
    unittest.main()

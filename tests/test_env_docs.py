"""Every user-set name in mcp/servers.yaml is documented. No network."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "tools" / "build_connector_docs.py"
    spec = importlib.util.spec_from_file_location("cyberau_build_connector_docs_env", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load()

SERVERS = """servers:
  demo:
    env:
    - DEMO_TOKEN=${DEMO_TOKEN}
    - CYBERAU_DATA_DIR=${CYBERAU_DATA_DIR}
    required_env:
    - DEMO_URL
  wrap:
    token_env: WRAP_TOKEN
"""
TEMPLATE = "# DEMO_TOKEN=\n# DEMO_URL=\n# WRAP_TOKEN=\n"
DIST = """env_requires:
  - name: DEMO_TOKEN
    required: false
  - name: DEMO_URL
    required: false
  - name: WRAP_TOKEN
    required: false
"""


def _tree(tmp_path: Path, template: str = TEMPLATE, dist: str = DIST) -> Path:
    (tmp_path / "mcp").mkdir()
    (tmp_path / "mcp" / "servers.yaml").write_text(SERVERS, encoding="utf-8")
    (tmp_path / ".env.template").write_text(template, encoding="utf-8")
    (tmp_path / "distribution.yaml").write_text(dist, encoding="utf-8")
    return tmp_path


def test_repository_env_names_are_documented():
    assert MOD.env_doc_problems(ROOT) == []


def test_complete_tree_passes(tmp_path):
    assert MOD.env_doc_problems(_tree(tmp_path)) == []


def test_name_missing_from_template_fails(tmp_path):
    root = _tree(tmp_path, template="# DEMO_TOKEN=\n# DEMO_URL=\n")
    problems = MOD.env_doc_problems(root)
    assert problems == ["env WRAP_TOKEN (server wrap) is missing from .env.template"]


def test_name_missing_from_distribution_fails(tmp_path):
    root = _tree(tmp_path, dist=DIST.replace("  - name: DEMO_URL\n    required: false\n", ""))
    problems = MOD.env_doc_problems(root)
    assert problems == ["env DEMO_URL (server demo) is missing from distribution.yaml env_requires"]


def test_runtime_names_are_not_required(tmp_path):
    problems = MOD.env_doc_problems(_tree(tmp_path))
    assert not any("CYBERAU_DATA_DIR" in item for item in problems)


def test_approval_key_creation_is_documented():
    template = (ROOT / ".env.template").read_text(encoding="utf-8")
    assert "# CYBERAU_APPROVAL_KEY=" in template
    assert "secrets.token_hex(32)" in template

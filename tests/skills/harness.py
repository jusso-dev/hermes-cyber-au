"""Offline skill eval harness.

The structural check always runs and does not read a provider key. Model runs
are opt-in via ``--live`` plus ``CYBERAU_EVAL_MODELS`` and a provider key.
See ``docs/skills/STANDARD.md``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

ROOT = Path(__file__).resolve().parents[2]
SKILLS_ROOT = ROOT / "skills"
EVALS_ROOT = ROOT / "tests" / "skills"
RESULTS_ROOT = EVALS_ROOT / "results"

REQUIRED_SECTIONS = (
    "When to Use",
    "Quick Reference",
    "Procedure",
    "Pitfalls",
    "Verification",
)
TOP_LEVEL_FIELDS = {
    "name",
    "description",
    "version",
    "author",
    "license",
    "platforms",
    "metadata",
    "required_environment_variables",
}
HERMES_FIELDS = {
    "tags",
    "related_skills",
    "requires_toolsets",
    "requires_tools",
    "fallback_for_toolsets",
    "fallback_for_tools",
    "config",
    "blueprint",
}
PLATFORMS = {"macos", "linux", "windows"}
PROVIDER_ENV_VARS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "XAI_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    "HERMES_API_KEY",
    "NOUS_API_KEY",
)
SECRET_ENV = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)")
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
EM_DASH = "\u2014"
EMOJI_RE = re.compile("[\U0001f1e6-\U0001f1ff\U0001f300-\U0001faff\u2600-\u27bf\u2300-\u23ff]")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
PATH_RE = re.compile(
    r"(?<![\w./])((?:references|templates|scripts)/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+)"
)
URL_RE = re.compile(r"\b(https?)://([^\s/]+)(\S*)", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"(?i)^[a-z0-9.-]+\.[a-z]{2,}$")
CASE_FIELDS = {
    "id",
    "input",
    "required_facts",
    "forbidden_claims",
    "expect_tools",
    "forbid_tools",
    "replay",
    "offline",
}


@dataclass
class ToolCall:
    name: str
    arguments: dict


@dataclass
class Session:
    message: str
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class ReplayStep:
    connector: str
    tool: str
    arguments: dict
    env: dict[str, str]
    expect_in_result: str | None


@dataclass
class EvalCase:
    id: str
    input: str
    required_facts: list[str]
    forbidden_claims: list[str]
    expect_tools: list[str]
    forbid_tools: list[str]
    replay: list[ReplayStep]
    offline: Session | None


@dataclass
class EvalFile:
    skill: str
    path: Path
    cases: list[EvalCase]


def sydney_today() -> str:
    """Calendar date in Australia/Sydney, for the results filename."""
    try:
        return datetime.now(ZoneInfo("Australia/Sydney")).date().isoformat()
    except Exception:
        return datetime.now(UTC).date().isoformat()


def defang_observable(value: str) -> str:
    """Defang one observable for display. Tool arguments stay raw."""
    text = value.strip()
    if HOST_RE.fullmatch(text) and not IPV4_RE.fullmatch(text):
        return text.replace(".", "[.]")

    def url_sub(match: re.Match[str]) -> str:
        scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
        host = match.group(2).replace(".", "[.]")
        return f"{scheme}://{host}{match.group(3)}"

    text = URL_RE.sub(url_sub, text)

    def email_sub(match: re.Match[str]) -> str:
        return f"{match.group(1)}[@]{match.group(2).replace('.', '[.]')}"

    text = EMAIL_RE.sub(email_sub, text)
    return IPV4_RE.sub(lambda match: match.group(0).replace(".", "[.]"), text)


def provider_configured() -> bool:
    """True when a known provider key is set to a non-empty value."""
    return any(os.environ.get(name) for name in PROVIDER_ENV_VARS)


def eval_models() -> list[str]:
    raw = os.environ.get("CYBERAU_EVAL_MODELS", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def hermes_argv(profile: str, model: str, skill: str, query_file: Path) -> list[str]:
    """Non-interactive equivalent of ``hermes -p <profile> chat -q``."""
    hermes = shutil.which("hermes") or "hermes"
    return [
        hermes,
        "-p",
        profile,
        "-m",
        model,
        "chat",
        "--query-file",
        str(query_file),
        "--oneshot",
        "--format",
        "stream-json",
        "--skills",
        skill,
    ]


def parse_stream_json(stdout: str) -> Session:
    """Read Hermes ``--format stream-json`` events into a session."""
    parts: list[str] = []
    calls: list[ToolCall] = []
    result_text = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind == "tool_use":
            arguments = event.get("input")
            calls.append(
                ToolCall(
                    str(event.get("name") or ""),
                    arguments if isinstance(arguments, dict) else {},
                )
            )
        elif kind == "text":
            parts.append(str(event.get("text") or ""))
        elif kind == "result":
            result_text = str(event.get("text") or "")
    return Session(result_text or "".join(parts), calls)


def same_tool(expected: str, actual: str) -> bool:
    """Match model-facing ``mcp__server__tool`` names and short tool names."""
    if expected == actual:
        return True
    if expected.startswith("mcp__") and actual.startswith("mcp__"):
        return False
    expected_leaf = expected.split("__")[-1]
    actual_leaf = actual.split("__")[-1]
    return expected_leaf == actual_leaf and bool(expected_leaf)


def score_session(case: EvalCase, session: Session) -> list[str]:
    """Score required facts, forbidden claims, and tool calls."""
    failures: list[str] = []
    for fact in case.required_facts:
        if fact not in session.message:
            failures.append(f"missing fact: {fact}")
    for claim in case.forbidden_claims:
        if claim in session.message:
            failures.append(f"forbidden claim: {claim}")
    called = [call.name for call in session.tool_calls]
    for tool in case.expect_tools:
        if not any(same_tool(tool, actual) for actual in called):
            failures.append(f"expected tool not called: {tool}")
    for tool in case.forbid_tools:
        if any(same_tool(tool, actual) for actual in called):
            failures.append(f"forbidden tool called: {tool}")
    return failures


def check_skills(skills_root: Path | None = None) -> list[str]:
    root = skills_root or SKILLS_ROOT
    if not root.is_dir():
        return [f"{root}: skills directory does not exist"]
    problems: list[str] = []
    found = False
    for path in sorted(root.iterdir()):
        if not path.is_dir() or path.name.startswith(".") or path.name == "__pycache__":
            continue
        found = True
        problems.extend(check_skill(path))
    if not found:
        problems.append(f"{root}: no skill directories")
    return problems


def check_skill(skill_dir: Path) -> list[str]:
    skill_md = skill_dir / "SKILL.md"
    rel = skill_dir.name
    if not skill_md.is_file():
        return [f"skills/{rel}: SKILL.md is missing"]
    try:
        text = skill_md.read_text(encoding="utf-8")
    except UnicodeError as exc:
        return [f"skills/{rel}/SKILL.md: {exc}"]
    problems = _text_problems(f"skills/{rel}/SKILL.md", text)
    try:
        meta, body = split_frontmatter(text)
    except ValueError as exc:
        return problems + [f"skills/{rel}/SKILL.md: {exc}"]
    problems.extend(_frontmatter_problems(rel, meta))
    problems.extend(_section_problems(f"skills/{rel}/SKILL.md", body))
    problems.extend(_reference_problems(skill_dir, body))
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".yaml", ".yml"}:
            continue
        if path.resolve() == skill_md.resolve():
            continue
        label = _display_path(path)
        try:
            extra = path.read_text(encoding="utf-8")
        except UnicodeError as exc:
            problems.append(f"{label}: {exc}")
            continue
        problems.extend(_text_problems(label, extra))
    return problems


def split_frontmatter(text: str) -> tuple[dict, str]:
    normalised = text.replace("\r\n", "\n")
    if not normalised.startswith("---\n"):
        raise ValueError("SKILL.md must start with YAML frontmatter")
    end = normalised.find("\n---\n", 4)
    if end == -1:
        raise ValueError("frontmatter is not closed")
    loaded = yaml.safe_load(normalised[4:end])
    if not isinstance(loaded, dict):
        raise ValueError("frontmatter must be a mapping")
    return loaded, normalised[end + 5 :]


def _frontmatter_problems(directory: str, meta: Mapping) -> list[str]:
    problems: list[str] = []
    prefix = f"skills/{directory}/SKILL.md"
    unknown = sorted(set(meta) - TOP_LEVEL_FIELDS)
    if unknown:
        problems.append(f"{prefix}: unknown frontmatter field {', '.join(unknown)}")
    for field_name in ("name", "description", "version", "author", "license"):
        if field_name not in meta:
            problems.append(f"{prefix}: missing frontmatter field {field_name}")
    name = meta.get("name")
    if isinstance(name, str):
        if not NAME_RE.fullmatch(name):
            problems.append(f"{prefix}: name must be lowercase hyphenated words")
        elif name != directory:
            problems.append(f"{prefix}: name {name} does not match directory {directory}")
    elif "name" in meta:
        problems.append(f"{prefix}: name must be a string")
    description = meta.get("description")
    if isinstance(description, str) and len(description.strip()) < 20:
        problems.append(f"{prefix}: description is too short")
    elif "description" in meta and not isinstance(description, str):
        problems.append(f"{prefix}: description must be a string")
    version = meta.get("version")
    if isinstance(version, str):
        if not VERSION_RE.fullmatch(version):
            problems.append(f"{prefix}: version must be MAJOR.MINOR.PATCH")
    elif "version" in meta:
        problems.append(f"{prefix}: version must be a string")
    author = meta.get("author")
    if "author" in meta and (not isinstance(author, str) or not author.strip()):
        problems.append(f"{prefix}: author must be a non-empty string")
    if "license" in meta and meta.get("license") != "Apache-2.0":
        problems.append(f"{prefix}: license must be Apache-2.0")
    platforms = meta.get("platforms")
    if platforms is not None:
        if not isinstance(platforms, list) or any(item not in PLATFORMS for item in platforms):
            problems.append(f"{prefix}: platforms must be a list of macos, linux, windows")
    problems.extend(_metadata_problems(prefix, meta.get("metadata")))
    problems.extend(_env_problems(prefix, meta.get("required_environment_variables")))
    return problems


def _metadata_problems(prefix: str, metadata: object) -> list[str]:
    if not isinstance(metadata, dict) or not isinstance(metadata.get("hermes"), dict):
        return [f"{prefix}: metadata.hermes is required"]
    hermes = metadata["hermes"]
    unknown = sorted(set(hermes) - HERMES_FIELDS)
    problems = []
    if unknown:
        problems.append(f"{prefix}: unknown metadata.hermes field {', '.join(unknown)}")
    tags = hermes.get("tags")
    if (
        not isinstance(tags, list)
        or not tags
        or any(not isinstance(item, str) or not item for item in tags)
    ):
        problems.append(f"{prefix}: metadata.hermes.tags must be a non-empty list of strings")
    for key in (
        "related_skills",
        "requires_toolsets",
        "requires_tools",
        "fallback_for_toolsets",
        "fallback_for_tools",
    ):
        if key in hermes:
            problems.extend(_string_list(prefix, f"metadata.hermes.{key}", hermes[key]))
    if "config" in hermes:
        problems.extend(_config_problems(prefix, hermes["config"]))
    if "blueprint" in hermes and not isinstance(hermes["blueprint"], dict):
        problems.append(f"{prefix}: metadata.hermes.blueprint must be a mapping")
    return problems


def _config_problems(prefix: str, config: object) -> list[str]:
    if not isinstance(config, list):
        return [f"{prefix}: metadata.hermes.config must be a list"]
    problems = []
    for index, item in enumerate(config):
        if not isinstance(item, dict):
            problems.append(f"{prefix}: config entry {index} must be a mapping")
            continue
        for key in ("key", "description"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                problems.append(f"{prefix}: config entry {index} needs a {key}")
    return problems


def _env_problems(prefix: str, variables: object) -> list[str]:
    if variables is None:
        return []
    if not isinstance(variables, list):
        return [f"{prefix}: required_environment_variables must be a list"]
    problems = []
    for index, item in enumerate(variables):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            problems.append(f"{prefix}: environment variable {index} needs a name")
            continue
        if not ENV_NAME_RE.fullmatch(item["name"]):
            problems.append(
                f"{prefix}: environment variable {item['name']} is not an upper-case name"
            )
        if any(key in item for key in ("value", "default")):
            problems.append(f"{prefix}: environment variable {item['name']} must not carry a value")
    return problems


def _string_list(prefix: str, label: str, value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return [f"{prefix}: {label} must be a list of strings"]
    return []


def _section_problems(prefix: str, body: str) -> list[str]:
    plain = _without_fences(body)
    headings = [match.group(1).strip() for match in re.finditer(r"^## (.+)$", plain, re.M)]
    h1 = list(re.finditer(r"^# (.+)$", plain, re.M))
    problems = []
    if len(h1) != 1:
        problems.append(f"{prefix}: expected one level-1 heading")
    elif headings:
        first_h2 = re.search(r"^## ", plain, re.M)
        if first_h2 and h1[0].start() > first_h2.start():
            problems.append(f"{prefix}: the level-1 heading must come before the sections")
    if headings[: len(REQUIRED_SECTIONS)] != list(REQUIRED_SECTIONS):
        found = ", ".join(headings) or "none"
        expected = ", ".join(REQUIRED_SECTIONS)
        problems.append(f"{prefix}: level-2 sections must start with {expected} (found: {found})")
    return problems


def _reference_problems(skill_dir: Path, body: str) -> list[str]:
    problems = []
    seen: set[str] = set()
    for target in _referenced_paths(body):
        if target in seen:
            continue
        seen.add(target)
        if not (skill_dir / target).is_file():
            problems.append(f"skills/{skill_dir.name}/{target}: linked reference does not exist")
    return problems


def _referenced_paths(body: str) -> list[str]:
    found: list[str] = []
    for match in LINK_RE.finditer(body):
        target = match.group(1).strip().split()[0]
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = target.split("#", 1)[0]
        if target:
            found.append(target)
    found.extend(match.group(1) for match in PATH_RE.finditer(body))
    return found


def _without_fences(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.S)


def _text_problems(prefix: str, text: str) -> list[str]:
    problems = []
    for number, line in enumerate(text.splitlines(), start=1):
        if EM_DASH in line:
            problems.append(f"{prefix}: em dash on line {number}")
        if EMOJI_RE.search(line):
            problems.append(f"{prefix}: emoji on line {number}")
    return problems


def load_eval_file(path: Path) -> EvalFile:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: eval file must be a mapping")
    skill = loaded.get("skill")
    cases = loaded.get("cases")
    if not isinstance(skill, str) or not skill:
        raise ValueError(f"{path}: skill is required")
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"{path}: cases must be a non-empty list")
    return EvalFile(skill, path, [_load_case(path, item) for item in cases])


def _load_case(path: Path, raw: object) -> EvalCase:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: each case must be a mapping")
    unknown = sorted(set(raw) - CASE_FIELDS)
    if unknown:
        raise ValueError(f"{path}: unknown case field {', '.join(unknown)}")
    case_id = raw.get("id")
    prompt = raw.get("input")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError(f"{path}: case id is required")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError(f"{path}: case {case_id} input is required")
    return EvalCase(
        id=case_id,
        input=prompt,
        required_facts=_require_strings(
            path, case_id, "required_facts", raw.get("required_facts", [])
        ),
        forbidden_claims=_require_strings(
            path, case_id, "forbidden_claims", raw.get("forbidden_claims", [])
        ),
        expect_tools=_require_strings(path, case_id, "expect_tools", raw.get("expect_tools", [])),
        forbid_tools=_require_strings(path, case_id, "forbid_tools", raw.get("forbid_tools", [])),
        replay=_load_replay(path, case_id, raw.get("replay", [])),
        offline=_load_offline(path, case_id, raw.get("offline")),
    )


def _require_strings(path: Path, case_id: str, label: str, value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{path}: case {case_id} {label} must be a list of strings")
    return list(value)


def _load_replay(path: Path, case_id: str, value: object) -> list[ReplayStep]:
    if not isinstance(value, list):
        raise ValueError(f"{path}: case {case_id} replay must be a list")
    steps = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{path}: case {case_id} replay entries must be mappings")
        connector = item.get("connector")
        tool = item.get("tool")
        arguments = item.get("arguments", {})
        env = item.get("env", {})
        if not isinstance(connector, str) or not isinstance(tool, str):
            raise ValueError(f"{path}: case {case_id} replay needs connector and tool")
        if not isinstance(arguments, dict) or not isinstance(env, dict):
            raise ValueError(f"{path}: case {case_id} replay arguments and env must be mappings")
        string_env = {str(key): str(val) for key, val in env.items()}
        _reject_secret_env(path, case_id, string_env)
        expect = item.get("expect_in_result")
        if expect is not None and not isinstance(expect, str):
            raise ValueError(f"{path}: case {case_id} expect_in_result must be a string")
        steps.append(ReplayStep(connector, tool, arguments, string_env, expect))
    return steps


def _reject_secret_env(path: Path, case_id: str, env: Mapping[str, str]) -> None:
    for key, value in env.items():
        if SECRET_ENV.search(key) and not (value.startswith("${") and value.endswith("}")):
            raise ValueError(f"{path}: case {case_id} env {key} must use a ${{VAR}} placeholder")


def _load_offline(path: Path, case_id: str, value: object) -> Session | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{path}: case {case_id} offline must be a mapping")
    message = value.get("message")
    calls = value.get("tool_calls", [])
    if not isinstance(message, str):
        raise ValueError(f"{path}: case {case_id} offline.message must be a string")
    if not isinstance(calls, list):
        raise ValueError(f"{path}: case {case_id} offline.tool_calls must be a list")
    parsed = []
    for item in calls:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError(f"{path}: case {case_id} tool call needs a name")
        arguments = item.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ValueError(f"{path}: case {case_id} tool call arguments must be a mapping")
        parsed.append(ToolCall(item["name"], arguments))
    return Session(message, parsed)


@contextmanager
def temporary_env(updates: Mapping[str, str]) -> Iterator[None]:
    previous: dict[str, str | None] = {}
    try:
        for key, value in updates.items():
            previous[key] = os.environ.get(key)
            os.environ[key] = value
        yield
    finally:
        for key, old in previous.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


def replay_case(case: EvalCase, eval_path: Path) -> list[str]:
    """Start each replay connector offline and check the fixture envelope."""
    failures: list[str] = []
    for step in case.replay:
        env = {"CYBERAU_OFFLINE": "1"}
        for key, value in step.env.items():
            env[key] = _resolve_env_value(eval_path.parent, value)
        try:
            payload = _call_connector(step.connector, step.tool, step.arguments, env)
        except Exception as exc:
            cause = f" ({exc.__cause__})" if exc.__cause__ else ""
            failures.append(f"replay {step.connector}.{step.tool} failed: {exc}{cause}")
            continue
        if payload.get("untrusted") is not True:
            failures.append(f"replay {step.connector}.{step.tool} envelope is not untrusted")
        encoded = json.dumps(payload)
        if step.expect_in_result and step.expect_in_result not in encoded:
            failures.append(
                f"replay {step.connector}.{step.tool} missing fixture text {step.expect_in_result}"
            )
    return failures


def _resolve_env_value(base: Path, value: str) -> str:
    if "/" not in value and "\\" not in value:
        return value
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (base / path).resolve()
    if not resolved.is_relative_to(ROOT.resolve()):
        raise ValueError(f"fixture path escapes the repository: {value}")
    return str(resolved)


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def _call_connector(connector_key: str, tool: str, arguments: dict, env: Mapping[str, str]) -> dict:
    with temporary_env(env):
        from cyberau_common.server import build_server, get_connector

        connector = _load_connector(get_connector, connector_key)
        server = build_server(connector)
        result = asyncio.run(server.call_tool(tool, arguments))
    return _payload(result)


def _load_connector(get_connector, connector_key: str):
    """Load a connector from the workspace, then from ``mcp/<key>/src`` if needed."""
    try:
        return get_connector(connector_key)
    except KeyError as exc:
        src = ROOT / "mcp" / connector_key / "src"
        module = f"cyberau_{connector_key.replace('-', '_')}"
        if not src.is_dir():
            raise
        if str(src) not in sys.path:
            sys.path.insert(0, str(src))
        sys.modules.pop(module, None)
        try:
            return get_connector(connector_key)
        except KeyError:
            raise exc from exc.__cause__


def _payload(result: object) -> dict:
    if isinstance(result, dict):
        return result
    if isinstance(result, tuple):
        for item in result:
            found = _payload(item)
            if found:
                return found
    if isinstance(result, list):
        for item in result:
            text = getattr(item, "text", None)
            if text:
                loaded = json.loads(text)
                if isinstance(loaded, dict):
                    return loaded
    text = getattr(result, "text", None)
    if isinstance(text, str) and text:
        loaded = json.loads(text)
        if isinstance(loaded, dict):
            return loaded
    raise ValueError(f"cannot read tool result {type(result).__name__}")


def run_hermes(
    profile: str,
    model: str,
    skill: str,
    prompt: str,
    extra_env: Mapping[str, str],
) -> Session:
    """Run one live Hermes query. Callers must already have gated on a provider key."""
    if shutil.which("hermes") is None:
        raise RuntimeError("hermes is not on PATH")
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        query_file = Path(tmp) / "prompt.txt"
        query_file.write_text(prompt, encoding="utf-8")
        command = hermes_argv(profile, model, skill, query_file)
        env = dict(os.environ)
        env["CYBERAU_OFFLINE"] = "1"
        env.update(extra_env)
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"hermes exited {completed.returncode}: {detail[:500]}")
    return parse_stream_json(completed.stdout)


def run_eval_file(
    path: Path,
    *,
    live: bool = False,
    profile: str | None = None,
) -> dict:
    """Score one eval file. Live model calls stay off unless ``live`` is true."""
    eval_file = load_eval_file(path)
    profile_name = profile or os.environ.get("CYBERAU_EVAL_PROFILE", "cyber-au-eval")
    models = eval_models()
    matrix = _matrix_plan(live, models)
    case_results = []
    for case in eval_file.cases:
        case_results.append(_run_case(eval_file, case, matrix, models, profile_name))
    return {
        "skill": eval_file.skill,
        "file": str(path.relative_to(ROOT)),
        "model_matrix": matrix,
        "ok": all(item["ok"] for item in case_results),
        "cases": case_results,
    }


def _matrix_plan(live: bool, models: Sequence[str]) -> dict:
    if not live:
        return {"ran": False, "reason": "skipped: offline run", "models": []}
    if not provider_configured():
        return {"ran": False, "reason": "skipped: no provider key", "models": []}
    if not models:
        return {"ran": False, "reason": "skipped: CYBERAU_EVAL_MODELS is unset", "models": []}
    return {"ran": True, "reason": "live", "models": list(models)}


def _run_case(
    eval_file: EvalFile,
    case: EvalCase,
    matrix: Mapping,
    models: Sequence[str],
    profile: str,
) -> dict:
    failures = replay_case(case, eval_file.path)
    sessions: list[tuple[str, Session]] = []
    if matrix["ran"]:
        extra_env: dict[str, str] = {}
        for step in case.replay:
            for key, value in step.env.items():
                extra_env[key] = _resolve_env_value(eval_file.path.parent, value)
        for model in models:
            try:
                sessions.append(
                    (model, run_hermes(profile, model, eval_file.skill, case.input, extra_env))
                )
            except Exception as exc:
                failures.append(f"model {model}: {exc}")
    elif case.offline is None:
        failures.append("no offline session and the model matrix was skipped")
    else:
        sessions.append(("offline", case.offline))
    for label, session in sessions:
        for failure in score_session(case, session):
            failures.append(f"{label}: {failure}")
    return {
        "id": case.id,
        "ok": not failures,
        "failures": failures,
        "tools_called": [call.name for _, session in sessions for call in session.tool_calls],
    }


def discover_eval_files(root: Path | None = None) -> list[Path]:
    base = root or EVALS_ROOT
    return sorted(base.glob("**/evals.yaml"))


def summarise(structural: Sequence[str], eval_runs: Sequence[Mapping]) -> str:
    lines = []
    if structural:
        lines.append(f"Skill structural check: {len(structural)} problem(s)")
        lines.extend(f"- {item}" for item in structural)
    else:
        lines.append("Skill structural check: ok")
    for run in eval_runs:
        passed = sum(1 for case in run["cases"] if case["ok"])
        failed = len(run["cases"]) - passed
        reason = run["model_matrix"]["reason"]
        lines.append(f"Offline eval {run['skill']}: {passed} passed, {failed} failed ({reason})")
        for case in run["cases"]:
            if not case["ok"]:
                lines.append(f"- {case['id']}: {'; '.join(case['failures'])}")
    return "\n".join(lines)


def write_results(directory: Path, payload: Mapping) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{payload['date']}.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def build_report(
    *,
    skills_root: Path | None = None,
    eval_paths: Sequence[Path] | None = None,
    live: bool = False,
    profile: str | None = None,
) -> dict:
    structural = check_skills(skills_root)
    paths = list(eval_paths) if eval_paths is not None else discover_eval_files()
    eval_runs = [run_eval_file(path, live=live, profile=profile) for path in paths]
    summary = summarise(structural, eval_runs)
    ok = not structural and all(run["ok"] for run in eval_runs)
    return {
        "date": sydney_today(),
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ok": ok,
        "structural": {"ok": not structural, "problems": structural},
        "evals": eval_runs,
        "summary": summary,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness")
    parser.add_argument("--structural", action="store_true", help="Run only the structural check")
    parser.add_argument("--evals", type=Path, help="Score one evals.yaml offline")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Call hermes when a provider key and CYBERAU_EVAL_MODELS are set",
    )
    parser.add_argument("--results-dir", type=Path, default=RESULTS_ROOT)
    parser.add_argument("--profile", default=None)
    args = parser.parse_args(argv)

    if args.structural and args.evals:
        print("Use either --structural or --evals", file=sys.stderr)
        return 2
    eval_paths: list[Path] | None
    if args.structural:
        eval_paths = []
    elif args.evals:
        eval_paths = [args.evals if args.evals.is_absolute() else ROOT / args.evals]
    else:
        eval_paths = None
    report = build_report(eval_paths=eval_paths, live=args.live, profile=args.profile)
    results_path = write_results(args.results_dir, report)
    print(report["summary"])
    if results_path.is_relative_to(ROOT):
        shown = results_path.relative_to(ROOT)
    else:
        shown = results_path
    print(f"Results: {shown}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

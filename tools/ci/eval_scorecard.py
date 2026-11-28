"""Turn a live skill eval run into per-skill scorecards and flag regressions.

``.github/workflows/live-evals.yml`` runs ``tests/skills/harness.py --live`` and then:

    python tools/ci/eval_scorecard.py score --results-dir eval-out \\
        --thresholds tests/skills/eval-thresholds.yaml --out-dir scorecards \\
        --summary docs/skills/scorecard.md --pr-body PR_BODY.md --issue-body ISSUE_BODY.md

    python tools/ci/eval_scorecard.py issue --body-file ISSUE_BODY.md

``score`` writes one markdown scorecard per skill, a published summary for the
data pull request, and an issue body when any skill falls below its pass
threshold. ``issue`` opens one issue titled ``Live eval regression``, or comments
on the open one. It never closes, merges or labels anything else.

Scoring, per skill and model: a case passes when it has no failure for that
model. Quiet Hermes runs cannot report tool calls, so the harness adds a note
that tool assertions are unscored. That note alone does not fail a case; the
scorecard counts those cases separately.

Model output and Hermes error text are never copied into a scorecard or an issue.
Failures are reduced to fixed categories. Only text that comes from the
committed eval files (required facts, forbidden claims, tool names) is kept.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISSUE_TITLE = "Live eval regression"
ISSUE_LABELS = ["type:task", "area:skills", "live-evals"]
FORCED_THRESHOLD = 1.01
UNOBSERVABLE = "tool calls are not observable in this run, so tool assertions are unscored"
_SKILL = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MODEL = re.compile(r"^[A-Za-z0-9._:/@+-]{1,100}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CASE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_KEEP = (
    "missing fact: ",
    "forbidden claim: ",
    "expected tool not called: ",
    "forbidden tool called: ",
)


class ScorecardError(Exception):
    """The run cannot be scored."""


# Inputs.


def load_thresholds(path: Path) -> dict[str, float]:
    import yaml

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("skills"), dict):
        raise ScorecardError("thresholds file needs a skills mapping")
    out: dict[str, float] = {}
    for skill, value in loaded["skills"].items():
        if not isinstance(skill, str) or not _SKILL.fullmatch(skill):
            raise ScorecardError(f"threshold skill id is not valid: {skill!r}")
        if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 1:
            raise ScorecardError(f"threshold for {skill} must be a number from 0 to 1")
        out[skill] = float(value)
    return out


def expected_skills(evals_root: Path) -> list[str]:
    """Every skill that has an evals.yaml with at least one case."""
    import yaml

    skills = []
    for path in sorted(evals_root.glob("**/evals.yaml")):
        if "results" in path.relative_to(evals_root).parts:
            continue
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if (
            isinstance(loaded, dict)
            and loaded.get("cases")
            and isinstance(loaded.get("skill"), str)
        ):
            skills.append(loaded["skill"])
    return sorted(set(skills))


def load_results(path: Path | None, directory: Path | None) -> dict:
    if path is None:
        if directory is None:
            raise ScorecardError("pass --results or --results-dir")
        found = sorted(directory.glob("*.json"))
        if not found:
            raise ScorecardError(f"no results file in {directory}")
        path = found[-1]
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScorecardError("results file could not be read") from exc
    except json.JSONDecodeError as exc:
        raise ScorecardError("results file is not valid JSON") from exc
    if not isinstance(loaded, dict) or not isinstance(loaded.get("evals"), list):
        raise ScorecardError("results file has no evals list")
    return loaded


# Scoring.


def classify(failure: str) -> tuple[str, str]:
    """Return (kind, safe detail). Model and Hermes text never survives."""
    for prefix in _KEEP:
        if failure.startswith(prefix):
            return prefix[:-2], _cell(failure[len(prefix) :])
    if failure == UNOBSERVABLE:
        return "unscored", ""
    if failure.startswith("malformed citation"):
        return "malformed citation", ""
    if failure.startswith("replay "):
        return "connector replay failed", ""
    return "other failure", ""


def _for_model(failures: list[str], model: str, models: list[str]) -> tuple[list[str], bool]:
    """Failures that belong to one model, and whether that model's run itself errored.

    The harness prefixes a scored failure with ``<model>: `` and a run error with
    ``model <model>: ``. Anything with another model's prefix is skipped. Anything with
    no model prefix (a connector replay failure) counts against every model.
    """
    own: list[str] = []
    errored = False
    others = [m for m in models if m != model]
    for item in failures:
        if not isinstance(item, str):
            continue
        if item.startswith(f"model {model}: "):
            errored = True
            own.append("model run failed")
        elif item.startswith(f"{model}: "):
            own.append(item[len(model) + 2 :])
        elif any(item.startswith((f"model {m}: ", f"{m}: ")) for m in others):
            continue
        else:
            own.append(item)
    return own, errored


def score(
    report: dict,
    thresholds: dict[str, float],
    expected: list[str],
    *,
    force_regression: str = "",
    require_live: bool = True,
) -> dict:
    if force_regression and not _SKILL.fullmatch(force_regression):
        raise ScorecardError("force_regression must be a skill id")
    if force_regression and force_regression not in expected:
        raise ScorecardError(f"force_regression names a skill with no evals: {force_regression}")
    runs = {}
    models: list[str] = []
    for run in report["evals"]:
        if not isinstance(run, dict) or not isinstance(run.get("skill"), str):
            raise ScorecardError("results file has a malformed eval run")
        matrix = run.get("model_matrix") or {}
        if require_live and matrix.get("ran") is not True:
            reason = matrix.get("reason") if isinstance(matrix.get("reason"), str) else ""
            reason = reason if re.fullmatch(r"[A-Za-z0-9 :_.,-]{0,80}", reason) else "unknown"
            raise ScorecardError(f"the live model run did not happen for {run['skill']}: {reason}")
        run_models = list(matrix.get("models") or []) if matrix.get("ran") else ["offline"]
        for model in run_models:
            if model not in models:
                models.append(model)
        runs[run["skill"]] = (run, run_models)
    skills = []
    regressions = []
    for skill in sorted(set(expected) | set(runs)):
        forced = skill == force_regression
        threshold = FORCED_THRESHOLD if forced else thresholds.get(skill)
        entry = {"skill": skill, "threshold": threshold, "forced": forced, "models": []}
        if skill not in runs:
            entry["status"] = "no results"
            regressions.append({"skill": skill, "model": None, "reason": "no results"})
            skills.append(entry)
            continue
        run, run_models = runs[skill]
        for model in run_models:
            row = _score_model(run, model, run_models)
            if threshold is None:
                row["status"] = "no threshold"
                regressions.append({"skill": skill, "model": model, "reason": "no threshold set"})
            elif row["total"] == 0:
                row["status"] = "no cases"
                regressions.append({"skill": skill, "model": model, "reason": "no cases"})
            elif row["rate"] < threshold:
                row["status"] = "below threshold"
                regressions.append(
                    {
                        "skill": skill,
                        "model": model,
                        "reason": f"pass rate {_pct(row['rate'])} below {_pct(threshold)}",
                        "forced": forced,
                    }
                )
            else:
                row["status"] = "ok"
            entry["models"].append(row)
        entry["status"] = (
            "ok" if all(row["status"] == "ok" for row in entry["models"]) else "regression"
        )
        skills.append(entry)
    date = report.get("date") if isinstance(report.get("date"), str) else ""
    return {
        "date": date if _DATE.fullmatch(date) else "unknown",
        "models": [_model_name(m, i) for i, m in enumerate(models)],
        "skills": skills,
        "regressions": regressions,
        "forced": force_regression or None,
    }


def _score_model(run: dict, model: str, models: list[str]) -> dict:
    cases = []
    passed = unscored = 0
    for case in run.get("cases") or []:
        if not isinstance(case, dict):
            continue
        case_id = case.get("id") if isinstance(case.get("id"), str) else ""
        failures, errored = _for_model(list(case.get("failures") or []), model, models)
        reasons = []
        had_unscored = False
        for failure in failures:
            if failure == "model run failed":
                reasons.append(("model run failed", ""))
                continue
            kind, detail = classify(failure)
            if kind == "unscored":
                had_unscored = True
            else:
                reasons.append((kind, detail))
        ok = not reasons and not errored
        passed += ok
        unscored += had_unscored
        cases.append(
            {
                "id": case_id if _CASE.fullmatch(case_id) else "unnamed case",
                "ok": ok,
                "tool_assertions_unscored": had_unscored,
                "reasons": [f"{k}: {d}" if d else k for k, d in reasons],
            }
        )
    total = len(cases)
    return {
        "model": _model_name(model, 0),
        "passed": passed,
        "failed": total - passed,
        "total": total,
        "rate": passed / total if total else 0.0,
        "tool_assertions_unscored": unscored,
        "cases": cases,
    }


def _model_name(model: object, index: int) -> str:
    return model if isinstance(model, str) and _MODEL.fullmatch(model) else f"model {index + 1}"


def _pct(value: float) -> str:
    return f"{round(value * 100)}%"


def _cell(text: str) -> str:
    clean = re.sub(r"[\r\n\t]+", " ", text).replace("|", "\\|").replace("`", "'")
    return clean[:160]


# Rendering.


def render_skill(card: dict, entry: dict) -> str:
    lines = [
        f"# Live eval scorecard: {entry['skill']}",
        "",
        f"Run date: {card['date']}. Models: {', '.join(card['models']) or 'none'}.",
        f"Threshold: {_threshold_text(entry)}. Status: {entry['status']}.",
        "",
    ]
    if not entry["models"]:
        lines.append("No results for this skill in the run.")
        return "\n".join(lines) + "\n"
    for row in entry["models"]:
        lines.extend(
            [
                f"## {row['model']}",
                "",
                f"Passed {row['passed']} of {row['total']} ({_pct(row['rate'])}). "
                f"Status: {row['status']}.",
                f"Cases with tool assertions unscored: {row['tool_assertions_unscored']}.",
                "",
                "| Case | Result | Reasons |",
                "|---|---|---|",
            ]
        )
        for case in row["cases"]:
            result = "pass" if case["ok"] else "fail"
            reasons = "; ".join(case["reasons"]) or "none"
            lines.append(f"| {case['id']} | {result} | {reasons} |")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def render_summary(card: dict) -> str:
    lines = [
        "# Live eval scorecard",
        "",
        "Written by the weekly live-evals workflow. Do not edit by hand. Each skill's evals ran "
        "against the listed models through Hermes with connectors offline. A case passes when "
        "the answer has every required fact, no forbidden claim and well-formed citations. "
        "Quiet Hermes runs cannot report tool calls, so tool assertions are not scored here; "
        "the offline evals in CI still score them.",
        "",
        f"Run date: {card['date']}. Models: {', '.join(card['models']) or 'none'}.",
        "Thresholds: `tests/skills/eval-thresholds.yaml`. "
        "How it works: [live-model evals](live-evals.md).",
        "",
        "| Skill | Model | Passed | Rate | Threshold | Status |",
        "|---|---|---|---|---|---|",
    ]
    for entry in card["skills"]:
        if not entry["models"]:
            lines.append(
                f"| {entry['skill']} | none | 0 of 0 | n/a | {_threshold_text(entry)} | "
                f"{entry['status']} |"
            )
            continue
        for row in entry["models"]:
            lines.append(
                f"| {entry['skill']} | {row['model']} | {row['passed']} of {row['total']} | "
                f"{_pct(row['rate'])} | {_threshold_text(entry)} | {row['status']} |"
            )
    lines.append("")
    if card["regressions"]:
        lines.append(
            f"Regressions: {len(card['regressions'])}. See the open `{ISSUE_TITLE}` issue."
        )
    else:
        lines.append("Regressions: none.")
    return "\n".join(lines) + "\n"


def render_issue(card: dict) -> str:
    forced = card.get("forced")
    lines = [
        "Draft for a maintainer to triage. The weekly live eval run found skills below their "
        "pass threshold. Nothing was changed, reverted or merged automatically.",
        "",
        f"Run date: {card['date']}. Models: {', '.join(card['models']) or 'none'}.",
        "",
    ]
    if forced:
        lines.extend(
            [
                f"This run was dispatched with force_regression set to `{forced}`, to check the "
                "regression path. That skill's threshold was raised above 100% for this run only. "
                "Close this issue if that is the only regression.",
                "",
            ]
        )
    lines.extend(["| Skill | Model | Reason |", "|---|---|---|"])
    for item in card["regressions"]:
        model = item["model"] or "none"
        reason = item["reason"] + (" (forced)" if item.get("forced") else "")
        lines.append(f"| {item['skill']} | {model} | {reason} |")
    lines.extend(
        [
            "",
            "Next steps: open the `live-eval-scorecards` artifact on the workflow run for the "
            "failing cases, rerun the skill's offline evals, and decide whether the skill, the "
            "eval or the threshold needs a change. Lower a threshold only with a reason in the "
            "pull request.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_pr_body(card: dict) -> str:
    count = len(card["regressions"])
    status = f"{count} regression(s) flagged in a separate issue." if count else "No regressions."
    return (
        f"Weekly live eval scorecard for {card['date']}.\n\n"
        f"Models: {', '.join(card['models']) or 'none'}. {status}\n\n"
        "Updates `docs/skills/scorecard.md` only. Review before merging. "
        "This pull request is not merged automatically.\n"
    )


def _threshold_text(entry: dict) -> str:
    if entry["threshold"] is None:
        return "not set"
    text = _pct(entry["threshold"])
    return f"{text} (forced)" if entry["forced"] else text


def write_outputs(card: dict, args: argparse.Namespace) -> None:
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for entry in card["skills"]:
            (args.out_dir / f"{entry['skill']}.md").write_text(
                render_skill(card, entry), encoding="utf-8"
            )
        (args.out_dir / "scorecard.json").write_text(
            json.dumps(card, indent=2) + "\n", encoding="utf-8"
        )
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(render_summary(card), encoding="utf-8")
    if args.pr_body:
        args.pr_body.write_text(render_pr_body(card), encoding="utf-8")
    if args.issue_body and card["regressions"]:
        args.issue_body.write_text(render_issue(card), encoding="utf-8")
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write("scored=true\n")
            handle.write(f"regression={'true' if card['regressions'] else 'false'}\n")


# Issue.


def open_or_comment(body: str, github) -> str:
    """Comment on the open regression issue, or create one. Returns what was done."""
    for issue in github.find(ISSUE_TITLE):
        if str(issue.get("state", "")).lower() == "open" and issue.get("title") == ISSUE_TITLE:
            github.comment(int(issue["number"]), body)
            return f"commented on #{int(issue['number'])}"
    number = github.create(ISSUE_TITLE, body, ISSUE_LABELS)
    return f"opened #{number}"


class GhCli:
    """GitHub issues through the gh CLI. Tests pass a fake client instead."""

    def find(self, title: str) -> list[dict]:
        raw = self._run(
            [
                "issue",
                "list",
                "--state",
                "open",
                "--limit",
                "20",
                "--json",
                "number,title,state",
                "--search",
                f'"{title}" in:title',
            ]
        )
        rows = json.loads(raw or "[]")
        return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    def create(self, title: str, body: str, labels: list[str]) -> int:
        args = ["issue", "create", "--title", title, "--body", body]
        for label in labels:
            self._ensure_label(label)
            args.extend(["--label", label])
        match = re.search(r"/issues/(\d+)$", self._run(args).strip())
        if not match:
            raise RuntimeError("gh issue create did not return an issue number")
        return int(match.group(1))

    def comment(self, number: int, body: str) -> None:
        self._run(["issue", "comment", str(number), "--body", body])

    def _ensure_label(self, label: str) -> None:
        try:
            self._run(["label", "create", label])
        except RuntimeError as exc:
            if "already exists" not in str(exc):
                raise

    def _run(self, args: list[str]) -> str:
        proc = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "gh failed")
        return proc.stdout


# CLI.


def main(argv: list[str] | None = None, *, client=None) -> int:
    parser = argparse.ArgumentParser(description="Live eval scorecards and regression issues.")
    sub = parser.add_subparsers(dest="command", required=True)
    scoring = sub.add_parser("score", help="Write scorecards from a harness results file")
    scoring.add_argument("--results", type=Path)
    scoring.add_argument("--results-dir", type=Path)
    scoring.add_argument("--thresholds", type=Path, required=True)
    scoring.add_argument("--evals-root", type=Path, default=ROOT / "tests" / "skills")
    scoring.add_argument("--out-dir", type=Path)
    scoring.add_argument("--summary", type=Path)
    scoring.add_argument("--pr-body", type=Path)
    scoring.add_argument("--issue-body", type=Path)
    scoring.add_argument("--force-regression", default="")
    scoring.add_argument("--github-output", type=Path)
    scoring.add_argument(
        "--allow-offline",
        action="store_true",
        help="Score an offline run. For local checks only; the workflow requires a live run.",
    )
    issue = sub.add_parser("issue", help="Open or comment on the regression issue")
    issue.add_argument("--body-file", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.command == "issue":
        try:
            body = args.body_file.read_text(encoding="utf-8")
        except OSError:
            print("issue body not found", file=sys.stderr)
            return 2
        try:
            print(open_or_comment(body, client or GhCli()))
        except (RuntimeError, json.JSONDecodeError) as exc:
            print(f"could not open the regression issue: {exc}", file=sys.stderr)
            return 1
        return 0
    try:
        card = score(
            load_results(args.results, args.results_dir),
            load_thresholds(args.thresholds),
            expected_skills(args.evals_root),
            force_regression=args.force_regression.strip(),
            require_live=not args.allow_offline,
        )
        write_outputs(card, args)
    except ScorecardError as exc:
        print(f"::error title=Live eval scorecard::{exc}")
        return 1
    print(render_summary(card))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

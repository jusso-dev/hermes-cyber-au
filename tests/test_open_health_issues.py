"""Issue reporter tests. They use a fake GitHub client and never call gh."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET = "super-secret-value"


def load():
    path = ROOT / "tools" / "ci" / "open_health_issues.py"
    spec = importlib.util.spec_from_file_location("open_health_issues", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeGitHub:
    def __init__(self):
        self.issues = []
        self.calls = []
        self._next = 1

    def find(self, title: str) -> list[dict]:
        return [dict(issue) for issue in self.issues if issue["title"] == title]

    def create(self, title: str, body: str, labels: list[str]) -> int:
        self.calls.append(("create", title, body, list(labels)))
        issue = {
            "number": self._next,
            "title": title,
            "state": "open",
            "body": body,
            "labels": list(labels),
        }
        self._next += 1
        self.issues.append(issue)
        return issue["number"]

    def comment(self, number: int, body: str) -> None:
        self.calls.append(("comment", number, body))
        self._issue(number)["body"] = body

    def close(self, number: int, body: str) -> None:
        self.calls.append(("close", number, body))
        issue = self._issue(number)
        issue["state"] = "closed"
        issue["body"] = body

    def reopen(self, number: int, body: str) -> None:
        self.calls.append(("reopen", number, body))
        issue = self._issue(number)
        issue["state"] = "open"
        issue["body"] = body

    def _issue(self, number: int) -> dict:
        return next(issue for issue in self.issues if issue["number"] == number)


def _report() -> dict:
    return {
        "checked_at": "2026-10-17",
        "connectors": [
            {
                "key": "first-epss",
                "status": "fail",
                "status_code": 200,
                "error_class": "schema_drift",
                "last_good": "2026-10-01",
                "detail": "schema drift",
                "keyed": False,
                "body": SECRET,
                "schema_diff": [
                    {
                        "change": "added",
                        "field": "data.0.note",
                        "schema": "epss_scores.response.json",
                    },
                    {
                        "change": "removed",
                        "field": "data.0.percentile",
                        "schema": "epss_scores.response.json",
                    },
                    {
                        "change": "type_changed",
                        "field": "data.0.epss",
                        "from": "number",
                        "to": "string",
                        "schema": "epss_scores.response.json",
                    },
                    {
                        "change": "type_changed",
                        "field": "data.0.percentile",
                        "from": SECRET,
                        "to": "string",
                    },
                ],
            },
            {
                "key": "nvd",
                "status": "not_checked",
                "status_code": None,
                "error_class": None,
                "schema_diff": [],
                "last_good": None,
                "detail": SECRET,
                "keyed": True,
                "body": SECRET,
                "response": SECRET,
            },
        ],
    }


def test_open_comment_and_do_not_duplicate(tmp_path: Path):
    module = load()
    github = FakeGitHub()
    report = _report()
    module.sync(report, github, close_recovered=True)
    assert [call[0] for call in github.calls] == ["create"]
    title, body, labels = github.calls[0][1:]
    assert title == "Connector health: first-epss failing"
    assert labels == ["type:task", "area:connectors", "priority:p1", "connector-health"]
    assert "Status code: 200" in body
    assert "Error class: schema_drift" in body
    assert "Last good: 2026-10-01" in body
    assert "field added: data.0.note" in body
    assert "field removed: data.0.percentile" in body
    assert "type changed: data.0.epss" in body
    assert "from number to string" in body
    assert SECRET not in body
    assert all(issue["title"] != "Connector health: nvd failing" for issue in github.issues)

    module.sync(report, github, close_recovered=True)
    assert [call[0] for call in github.calls] == ["create", "comment"]
    assert len(github.issues) == 1
    assert SECRET not in github.calls[1][2]


def test_recovery_closes_and_a_later_failure_reopens():
    module = load()
    github = FakeGitHub()
    github.issues.append(
        {
            "number": 7,
            "title": "Connector health: first-epss failing",
            "state": "open",
            "body": "Last good: 2026-09-01\n",
        }
    )
    recovered = {
        "connectors": [
            {
                "key": "first-epss",
                "status": "ok",
                "status_code": 200,
                "error_class": None,
                "last_good": "2026-10-17",
                "schema_diff": [],
                "body": SECRET,
            }
        ]
    }
    module.sync(recovered, github, close_recovered=False)
    assert github.calls == []
    assert github.issues[0]["state"] == "open"

    module.sync(recovered, github, close_recovered=True)
    assert github.calls[0][0] == "close"
    assert "has recovered" in github.calls[0][2]
    assert "Last good: 2026-10-17" in github.calls[0][2]
    assert SECRET not in github.calls[0][2]
    assert github.issues[0]["state"] == "closed"

    failing = _report()
    failing["connectors"][0]["last_good"] = None
    module.sync(failing, github, close_recovered=True)
    assert github.calls[-1][0] == "reopen"
    assert "Last good: 2026-10-17" in github.calls[-1][2]
    assert len(github.issues) == 1
    assert SECRET not in github.calls[-1][2]


def test_not_checked_does_not_close_an_existing_issue():
    module = load()
    github = FakeGitHub()
    github.issues.append(
        {
            "number": 3,
            "title": "Connector health: nvd failing",
            "state": "open",
            "body": "still open\n",
        }
    )
    module.sync(_report(), github, close_recovered=True)
    nvd = next(issue for issue in github.issues if issue["number"] == 3)
    assert nvd["state"] == "open"
    assert nvd["body"] == "still open\n"


def test_keyed_failure_omits_the_response(tmp_path: Path):
    module = load()
    github = FakeGitHub()
    report = {
        "connectors": [
            {
                "key": "nvd",
                "status": "fail",
                "status_code": 401,
                "error_class": SECRET,
                "detail": SECRET,
                "keyed": True,
                "body": SECRET,
                "response": {"vulnerabilities": SECRET},
                "schema_diff": [],
                "last_good": None,
            }
        ]
    }
    module.sync(report, github, close_recovered=True)
    body = github.calls[0][2]
    assert "Status code: 401" in body
    assert "Error class: unknown" in body
    assert SECRET not in body
    assert "vulnerabilities" not in body


def test_main_never_calls_gh(tmp_path: Path, monkeypatch):
    module = load()

    def explode(*_args, **_kwargs):
        raise AssertionError("gh was called")

    monkeypatch.setattr(module.subprocess, "run", explode)
    path = tmp_path / "health.json"
    path.write_text(json.dumps(_report()), encoding="utf-8")
    github = FakeGitHub()
    assert (
        module.main(
            ["--kind", "connector", "--input", str(path), "--close-recovered"],
            client=github,
        )
        == 0
    )
    assert github.calls[0][0] == "create"
    assert module.main(["--kind", "parser", "--input", str(path)], client=github) == 0
    assert module.main(["--kind", "connector", "--input", str(tmp_path / "missing.json")]) == 2


def test_a_github_error_on_one_connector_does_not_skip_the_rest(tmp_path: Path, capsys):
    module = load()

    class Flaky(FakeGitHub):
        def find(self, title: str) -> list[dict]:
            if "first-epss" in title:
                raise RuntimeError("gh failed")
            return super().find(title)

    report = _report()
    report["connectors"].append(
        {
            "key": "cisa-kev",
            "status": "fail",
            "status_code": 503,
            "error_class": "http_error",
            "last_good": None,
            "schema_diff": [],
        }
    )
    github = Flaky()
    path = tmp_path / "health.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert module.main(["--kind", "connector", "--input", str(path)], client=github) == 1
    assert [call[1] for call in github.calls] == ["Connector health: cisa-kev failing"]
    assert "first-epss: gh failed" in capsys.readouterr().err

#!/usr/bin/env python3
"""Create labels, milestones, issues and sub-issue links from tickets/*.md.

Reproducible and idempotent: an issue whose exact title already exists is reused, not duplicated.
Uses the gh CLI for auth. Sleeps between writes to stay clear of GitHub's secondary rate limits.

Usage:
  python3 tools/issues/create_issues.py --repo OWNER/REPO --dry-run
  python3 tools/issues/create_issues.py --repo OWNER/REPO --banned-terms ~/.config/hermes-cyber-au/banned-terms.txt

The banned terms file (one term per line) lives outside the repo so the list itself is never published.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TICKETS = ROOT / "tickets"
STATE = ROOT / "tools" / "issues" / ".state.json"

LABELS = {
    "roadmap": ("0e1726", "Top-level roadmap"),
    "type:epic": ("3e4b9e", "Epic with sub-issues"),
    "type:feature": ("a2eeef", "New capability"),
    "type:task": ("cfd3d7", "Engineering or operations task"),
    "type:docs": ("0075ca", "Documentation"),
    "area:install": ("fbca04", "Install and bootstrap"),
    "area:connectors": ("c5def5", "MCP connectors and shared client"),
    "area:skills": ("bfd4f2", "Hermes skills"),
    "area:intel-store": ("d4c5f9", "Local threat intel store"),
    "area:routines": ("fef2c0", "Scheduled routines and briefings"),
    "area:security": ("b60205", "Security of the agent itself"),
    "area:docs": ("0e8a16", "Docs"),
    "area:ci": ("5319e7", "GitHub Actions and automation"),
    "area:release": ("1d76db", "Packaging and releases"),
    "area:premium-feeds": ("c2e0c6", "Paid, bring-your-own-licence intel feeds"),
    "priority:p0": ("b60205", "Must have for the milestone"),
    "priority:p1": ("d93f0b", "Should have"),
    "priority:p2": ("fbca04", "Could have"),
    "priority:p3": ("c2e0c6", "Later"),
}
MILESTONES = {
    "v0.1 MVP": "Install, core AU and vulnerability connectors, eleven skills, intel store, daily briefing, core security controls, CI.",
    "v0.2": "More connectors and integrations, watchlists, retention, update path, supply chain, weekly releases.",
    "v1.0": "Optional bridges, analytics exports, Windows installer, hardened evals.",
}
REF = re.compile(r"\{\{ref:([a-z0-9-]+)\}\}")
GH_LINK = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def gh(*args: str, input: str | None = None, check: bool = True) -> str:
    p = subprocess.run(["gh", *args], input=input, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {p.stderr.strip()}")
    return p.stdout


def load_tickets() -> list[dict]:
    out = []
    for f in sorted(TICKETS.glob("*.md")):
        text = f.read_text(encoding="utf-8")
        _, fm, body = text.split("---\n", 2)
        meta = {}
        for line in fm.strip().splitlines():
            k, v = line.split(": ", 1)
            meta[k] = json.loads(v)
        meta["body"] = body.strip()
        meta["file"] = f.name
        out.append(meta)
    return out


def preflight(tickets: list[dict], repo: str, banned_file: str | None, readme: Path) -> list[str]:
    problems = []
    keys = {t["key"] for t in tickets}
    texts = [(t["file"], t["title"] + "\n" + t["body"]) for t in tickets] + [("README.md", readme.read_text())]
    for name, text in texts:
        for k in REF.findall(text):
            if k not in keys:
                problems.append(f"{name}: unknown ref {k}")
        if re.search("[\u2014\u2013]", text):
            problems.append(f"{name}: contains an em or en dash")
        if re.search("[\U0001F300-\U0001FAFF]", text):
            problems.append(f"{name}: contains an emoji")
        for l in (t for t in tickets if t["file"] == name):
            for lab in l["labels"]:
                if lab not in LABELS:
                    problems.append(f"{name}: unknown label {lab}")
            if l["milestone"] and l["milestone"] not in MILESTONES:
                problems.append(f"{name}: unknown milestone {l['milestone']}")
            if l["parent"] and l["parent"] not in keys:
                problems.append(f"{name}: unknown parent {l['parent']}")
            if len(l["body"]) > 60000:
                problems.append(f"{name}: body too long")
    if banned_file:
        terms = [t.strip() for t in Path(banned_file).expanduser().read_text().splitlines() if t.strip()]
        for name, text in texts:
            for term in terms:
                if re.search(re.escape(term), text, re.I):
                    problems.append(f"{name}: contains a banned term (#{terms.index(term) + 1})")
    repos = set()
    for _, text in texts:
        for owner, name in GH_LINK.findall(text):
            repos.add(f"{owner}/{name.removesuffix('.git')}")
    for r in sorted(repos):
        vis = gh("api", f"repos/{r}", "--jq", ".visibility", check=False).strip()
        if vis != "public":
            problems.append(f"linked repo {r} is not public (got {vis or 'not found'})")
    return problems


def ensure_labels(repo: str, dry: bool, sleep: float):
    existing = {l["name"] for l in json.loads(gh("label", "list", "-R", repo, "--limit", "200", "--json", "name"))}
    for name, (color, desc) in LABELS.items():
        if name in existing:
            continue
        print(f"label + {name}")
        if not dry:
            gh("label", "create", name, "-R", repo, "--color", color, "--description", desc)
            time.sleep(sleep)


def ensure_milestones(repo: str, dry: bool, sleep: float) -> dict[str, int]:
    ms = {m["title"]: m["number"] for m in json.loads(gh("api", f"repos/{repo}/milestones?state=all&per_page=100"))}
    for title, desc in MILESTONES.items():
        if title in ms:
            continue
        print(f"milestone + {title}")
        if not dry:
            m = json.loads(gh("api", f"repos/{repo}/milestones", "-f", f"title={title}", "-f", f"description={desc}"))
            ms[title] = m["number"]
            time.sleep(sleep)
        else:
            ms[title] = -1
    return ms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--sleep", type=float, default=3.0, help="seconds between write calls")
    ap.add_argument("--banned-terms", help="file of terms that must not appear (kept outside the repo)")
    args = ap.parse_args()
    repo, dry = args.repo, args.dry_run

    tickets = load_tickets()
    problems = preflight(tickets, repo, args.banned_terms, ROOT / "README.md")
    if problems:
        print("Preflight failed:\n  " + "\n  ".join(problems), file=sys.stderr)
        sys.exit(2)
    print(f"preflight ok: {len(tickets)} tickets")
    if not args.banned_terms:
        print("warning: no --banned-terms file given; private-name check skipped", file=sys.stderr)

    ensure_labels(repo, dry, args.sleep)
    ms = ensure_milestones(repo, dry, args.sleep)

    state = json.loads(STATE.read_text()) if STATE.exists() and not dry else {}
    state.setdefault(repo, {})
    st = state[repo]
    existing = {}
    if not dry:
        for i in json.loads(gh("issue", "list", "-R", repo, "--state", "all", "--limit", "1000", "--json", "number,title,id")):
            existing[i["title"]] = i["number"]

    for t in tickets:
        if t["key"] in st:
            continue
        if t["title"] in existing:
            num = existing[t["title"]]
            iid = json.loads(gh("api", f"repos/{repo}/issues/{num}"))["id"]
            st[t["key"]] = {"number": num, "id": iid}
            print(f"reuse #{num} {t['title']}")
            continue
        print(f"issue + {t['title']}")
        if dry:
            continue
        fields = ["-f", f"title={t['title']}", "-f", f"body={t['body']}"]
        for lab in t["labels"]:
            fields += ["-f", f"labels[]={lab}"]
        if t["milestone"]:
            fields += ["-F", f"milestone={ms[t['milestone']]}"]
        res = json.loads(gh("api", f"repos/{repo}/issues", *fields))
        st[t["key"]] = {"number": res["number"], "id": res["id"]}
        STATE.write_text(json.dumps(state, indent=2))
        time.sleep(args.sleep)

    if dry:
        print("dry run: no writes")
        return

    # Sync: resolve {{ref:key}} to #N and bring title, body, labels and milestone in line with the ticket
    # file. Only issues that differ are patched, so re-running is cheap and never duplicates.
    current = {i["number"]: i for i in json.loads(gh(
        "issue", "list", "-R", repo, "--state", "all", "--limit", "1000",
        "--json", "number,title,body,labels,milestone"))}
    for t in tickets:
        num = st[t["key"]]["number"]
        body = REF.sub(lambda m: f"#{st[m.group(1)]['number']}", t["body"])
        cur = current.get(num, {})
        fields = []
        if cur.get("title") != t["title"]:
            fields += ["-f", f"title={t['title']}"]
        if (cur.get("body") or "").strip() != body.strip():
            fields += ["-f", f"body={body}"]
        if sorted(l["name"] for l in cur.get("labels", [])) != sorted(t["labels"]):
            fields += ["-f", "labels[]=" + t["labels"][0]] + sum((["-f", f"labels[]={l}"] for l in t["labels"][1:]), [])
        want_ms = t["milestone"]
        have_ms = (cur.get("milestone") or {}).get("title")
        if want_ms != have_ms:
            fields += ["-F", f"milestone={ms[want_ms]}"] if want_ms else ["-F", "milestone=null"]
        if fields:
            print(f"sync #{num} {t['key']}")
            gh("api", "-X", "PATCH", f"repos/{repo}/issues/{num}", *fields)
            time.sleep(args.sleep)

    # Link sub-issues: POST /repos/{owner}/{repo}/issues/{parent_number}/sub_issues with the child's numeric id.
    linked = st.setdefault("_linked", [])
    for t in tickets:
        if not t["parent"] or t["key"] in linked:
            continue
        parent = st[t["parent"]]["number"]
        child_id = st[t["key"]]["id"]
        out = subprocess.run(["gh", "api", "-X", "POST", f"repos/{repo}/issues/{parent}/sub_issues",
                              "-F", f"sub_issue_id={child_id}"], capture_output=True, text=True)
        if out.returncode != 0 and "already" not in out.stderr.lower() and "422" not in out.stderr:
            raise RuntimeError(f"sub-issue link failed for {t['key']}: {out.stderr}")
        linked.append(t["key"])
        STATE.write_text(json.dumps(state, indent=2))
        time.sleep(args.sleep)
    print("done")


if __name__ == "__main__":
    main()

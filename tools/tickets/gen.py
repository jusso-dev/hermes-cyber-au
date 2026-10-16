"""Generate tickets/*.md, docs/research/connectors.md and the README connector table.

Run: python3 tools/tickets/gen.py
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import *  # noqa: E402
import t_install, t_connectors, t_skills, t_store, t_routines, t_security, t_docs_ci, t_premium  # noqa: E402
from inventory import CONNECTORS as _BASE  # noqa: E402
from inventory_added import ADDED  # noqa: E402

from inventory_premium import PREMIUM  # noqa: E402

CONNECTORS = _BASE + ADDED
TABLE_CONNECTORS = CONNECTORS + PREMIUM

EPICS = [
    ("epic-install", "Epic: Install and bootstrap", ["area:install"], "p0", M_V01, t_install,
     "One-command install of Hermes plus the cyber-au profile distribution, Docker image, doctor, plugin skeleton and the update path."),
    ("epic-connectors", "Epic: Connectors and the shared connector library", ["area:connectors"], "p0", M_V01, t_connectors,
     "A shared HTTP client with egress policy, caching and rate limiting, plus one read-only MCP connector per source in the inventory."),
    ("epic-skills", "Epic: Skills for Australian security teams", ["area:skills"], "p0", M_V01, t_skills,
     "Eleven skills from incident triage to SOCI reporting, built to one standard and tested offline."),
    ("epic-intel-store", "Epic: Local threat intel store with dedupe and STIX 2.1 export", ["area:intel-store"], "p0", M_V01, t_store,
     "SQLite store shared by connectors, skills and routines, with canonical dedupe, STIX 2.1 export, retention and snapshots."),
    ("epic-routines", "Epic: Daily briefing and scheduled routines", ["area:routines"], "p1", M_V01, t_routines,
     "Paused-by-default cron jobs: hourly ingest, 07:30 Sydney briefing, KEV watch, weekly executive summary, watchlists."),
    ("epic-security", "Epic: Security of the agent itself", ["area:security"], "p0", M_V01, t_security,
     "Threat model, secrets handling, prompt injection defences for feed content, egress allowlist, audit log and supply chain."),
    ("epic-docs", "Epic: Documentation", ["area:docs"], "p1", M_V01, None,
     "Docs site, quick start, generated connector and skill references, data licensing, contribution and security policy."),
    ("epic-ci", "Epic: GitHub Actions, data automation and releases", ["area:ci", "area:release"], "p0", M_V01, None,
     "CI, nightly intel refresh, skill data regeneration, connector health with auto issues, dependency and Hermes bumps, weekly releases, auto-PRs."),
]
# Added after the first filing; written last so earlier ticket files keep their numbers.
LATE_EPICS = [
    ("epic-premium", "Epic: Premium and commercial intel feeds", ["area:premium-feeds", "area:connectors"], "p2", M_V02, t_premium,
     "Paid, bring-your-own-licence feeds on Australian organisations (dark web and leak sites, ransomware victims, infostealer and breach exposure, brand and attack surface) behind one interface with terms flags, budgets and privacy handling, plus a free AU ransomware victim tracker, an AU org exposure skill and alert routine, and wiring into briefings and incident skills."),
]


def collect():
    children = []
    for mod in (t_install, t_connectors, t_skills, t_store, t_routines, t_security, t_docs_ci):
        children.extend(mod.tickets())
    children.extend(t_connectors.added_tickets())  # filed after the first 80, so appended last
    return children


def epic_body(key, summary, kids):
    by_ms = {}
    for k in kids:
        by_ms.setdefault(k["milestone"], []).append(k)
    lines = [f"## Outcome\n{summary}\n", "## Sub-issues", "Linked as GitHub sub-issues. Checklist mirrors them by milestone.\n"]
    for ms in (M_V01, M_V02, M_V10):
        if ms in by_ms:
            lines.append(f"### {ms}")
            for k in by_ms[ms]:
                pr = next(l for l in k["labels"] if l.startswith("priority:")).split(":")[1]
                lines.append(f"- [ ] {{{{ref:{k['key']}}}}} {k['title']} ({pr})")
            lines.append("")
    lines.append("## Definition of done\n- [ ] Every sub-issue closed or moved to a later milestone with a reason.\n- [ ] Docs updated for anything user-visible.\n- [ ] Security review against `docs/security/threat-model.md`.")
    return "\n".join(lines)


def roadmap_body(epics):
    out = [dedent(f"""
## What this is
`hermes-cyber-au` is a planned Hermes Agent profile distribution for Australian cyber security teams. One install gives an analyst ASD guidance (ISM, Essential Eight, ASD Essentials), Australian and global threat intel connectors, a local intel store, daily briefings, and skills for triage, enrichment, vulnerability prioritisation, phishing, hunting, NDB and SOCI reporting and executive briefings.

Status: planned. This repository holds the plan as issues. No code has shipped yet.

## How it fits Hermes
It is a profile distribution (`distribution.yaml` at the repo root), installed with `hermes profile install github.com/jusso-dev/hermes-cyber-au --alias` and updated with `hermes profile update`. It ships a native plugin (`plugins/cyber-au`), stdio MCP connectors (`mcp/`), skills, paused cron jobs and scripts. Verified structure notes: `docs/research/hermes-structure.md`, checked against NousResearch/hermes-agent `{HERMES_COMMIT[:7]}` ({HERMES_RELEASE}).

## Milestones
- **v0.1 MVP**: install and doctor, shared connector library, the first five connectors (ASD's ACSC feeds; ISM and Essential Eight from ISM OSCAL, plus ASD Essentials; KEV with EPSS and NVD; AusCERT bulletins; abuse.ch), ATT&CK, and the zero-build wraps of Cloudflare's unified MCP for Radar, the HIBP MCP, GitHub security advisories and the VirusTotal MCP (Radar, VirusTotal and abuse.ch off by default under their non-commercial terms), the eleven skills at first quality, intel store with STIX export, daily briefing, core security controls, CI and data workflows.
- **v0.2**: OTX, GreyNoise, InternetDB, OSV, Sigma, crt.sh, CVE Program records, AbuseIPDB, Spamhaus DROP, NCSC NZ, a TAXII 2.1 reader for ASD CTIS, Cloudflare URL Scanner (approval-gated), AU obligations data, the premium feed interface with Recorded Future, Flare and UpGuard (paid, bring your own licence) and the free ransomware.live tracker, the AU org exposure skill and alert routine, Junction and M365-Secure integrations, watchlists, retention, update path, supply chain, weekly releases.
- **v1.0**: optional Brolga and ThreatSieve bridges, premium connectors for Hudson Rock, SpyCloud, Flashpoint, Intel 471, Google TI DTM, CrowdStrike Recon, SOCRadar and DarkOwl, MISP and OpenCTI for teams with their own instance, AusCERT member feeds, IRAP, PSPF, Blueprint, Scamwatch, data.gov.au, PhishTank and OpenPhish, DuckDB and MISP exports, Windows installer, hardened evals across model providers.

## Epics
""")]
    for key, title, *_ in epics:
        out.append(f"- [ ] {{{{ref:{key}}}}} {title}")
    out.append("")
    out.append(dedent("""
## Principles
- Read-only by default. The agent proposes; people act.
- Feed content is data, never instructions.
- Every claim carries a source, version and date. "I don't know" beats a guess.
- Works with zero API keys; each key adds sources.
- Australian English, plain language.
"""))
    return "\n".join(out)


def write_inventory_docs():
    rows = ["| Connector | Server | Group | Auth | Default | Milestone | Status | Docs |", "|---|---|---|---|---|---|---|---|"]
    for c in TABLE_CONNECTORS:
        auth = "none" if not c["env"] else ", ".join(f"`{n}`" + ("" if r else " (optional)") for n, r, _ in c["env"])
        if c.get("paid"):
            default = "off: paid, bring your own licence"
        elif c.get("terms_flags"):
            default = "off: free, victim data"
        else:
            default = "off: " + ("non-commercial terms, bring your own key" if any(w in c.get("default_off", "") for w in ("non-commercial", "not-for-profit", "CC BY-NC", "commercial use")) else "bring your own access") if c.get("default_off") else "on"
        rows.append(f"| {c['name']} | `{c['server']}` | {c['group']} | {auth} | {default} | {c['milestone']} | planned | {c['docs']} |")
    table = "\n".join(rows)
    doc = ["# Connector inventory\n",
           "Checked on 16 October 2026. The first 21 sources were compiled and verified for this plan. The rest were added from a second, independent inventory checked on the same date, for sources the first list did not cover. Sources with non-commercial terms (Cloudflare Radar, VirusTotal, abuse.ch) ship off by default and users bring their own key. Each connector ticket carries endpoints, auth, limits, terms and what was verified.\n",
           table, "\n## Details\n"]
    for c in TABLE_CONNECTORS:
        doc.append(f"### {c['name']}\n- Endpoints: " + "; ".join(f"`{m}` {u}" for m, u, _ in c["endpoints"]) +
                   f"\n- Auth: {c['auth']}\n- Rate limits: {c['rate']}\n- Terms: {c['terms']}\n- Verified: {c['verified']}\n")
    (ROOT / "docs" / "research" / "connectors.md").write_text("\n".join(doc), encoding="utf-8")
    readme = ROOT / "README.md"
    if readme.exists():
        s = readme.read_text()
        s = re.sub(r"<!-- connectors:start -->.*<!-- connectors:end -->",
                   "<!-- connectors:start -->\n" + table + "\n<!-- connectors:end -->", s, flags=re.S)
        readme.write_text(s)


def main():
    if TICKETS.exists():
        shutil.rmtree(TICKETS)
    kids = collect()
    keys = [k["key"] for k in kids]
    assert len(keys) == len(set(keys)), "duplicate keys"
    order = 0
    write_ticket("roadmap", "Roadmap: hermes-cyber-au, a Hermes Agent distribution for Australian cyber security teams",
                 ["roadmap", "type:docs", "area:docs", "priority:p0"], None, roadmap_body(EPICS + LATE_EPICS), None, order)
    for key, title, areas, pr, ms, _mod, summary in EPICS:
        order += 1
        mine = [k for k in kids if k["parent"] == key]
        write_ticket(key, title, ["type:epic", *areas, f"priority:{pr}"], ms, epic_body(key, summary, mine), "roadmap", order)
    for k in kids:
        order += 1
        write_ticket(k["key"], k["title"], k["labels"], k["milestone"], k["body"], k["parent"], order)
    for key, title, areas, pr, ms, mod, summary in LATE_EPICS:
        mine = mod.tickets()
        order += 1
        write_ticket(key, title, ["type:epic", *areas, f"priority:{pr}"], ms, epic_body(key, summary, mine), "roadmap", order)
        for k in mine:
            order += 1
            write_ticket(k["key"], k["title"], k["labels"], k["milestone"], k["body"], k["parent"], order)
    write_inventory_docs()
    print(f"wrote {order + 1} tickets")


if __name__ == "__main__":
    main()

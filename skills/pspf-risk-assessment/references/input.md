# Renderer input

`scripts/render_risk.py` reads one JSON object. Only `as_of` is required. Every other key may be absent. An absent value is printed as `missing`. The script never fills one in.

```json
{
  "as_of": "2026-10-19",
  "documents": ["tra", "srmp"],
  "scope": {
    "entity": "Example Agency (synthetic)",
    "subject": "Payroll web application",
    "kind": "system",
    "classification": "OFFICIAL: Sensitive",
    "objectives": ["Pay staff accurately and on time"],
    "out_of_scope": ["Corporate network"],
    "acceptance_authority": "Authorising Officer"
  },
  "matrix": {
    "name": "Example Agency enterprise risk matrix 2026",
    "likelihood": ["rare", "unlikely", "possible", "likely", "almost certain"],
    "consequence": ["minor", "moderate", "major", "severe", "catastrophic"],
    "levels": ["low", "medium", "high", "extreme"],
    "grid": [["low", "low", "medium", "medium", "high"], ["...one row per likelihood..."]]
  },
  "tolerance": {"rating": "medium", "approved_by": "Secretary", "date": "2026-07-01"},
  "threat_environment": {
    "national_terrorism_threat_level": "PROBABLE",
    "asio_reporting": "Supplied by the entity security adviser",
    "source": {"name": "supplied context", "version": "none", "retrieved": "2026-10-19"}
  },
  "assets": [
    {"id": "A1", "name": "Payroll records", "type": "information",
     "classification": "OFFICIAL: Sensitive", "critical": true, "owner": "CFO"}
  ],
  "threats": [
    {"id": "T1", "name": "Financially motivated cybercriminals",
     "actor_type": "external", "capability": "high", "intent": "financial gain",
     "attack_techniques": ["T1190"],
     "evidence": [
       {"text": "CVE-2021-44228 is in the KEV catalogue.",
        "source": {"name": "CISA Known Exploited Vulnerabilities", "version": "2026.10.18", "retrieved": "2026-10-19"}}
     ]}
  ],
  "risks": [
    {"id": "R1", "statement": "Cybercriminals exploit ... resulting in ...",
     "assets": ["A1"], "threats": ["T1"], "vulnerability": "Log4j 2.14.1 on an internet-facing host",
     "controls": [{"text": "Monthly patching", "ism": ["ism-1876"], "effectiveness": "partial",
                   "source": {"name": "asd-ism", "version": "v2026.09.4", "retrieved": "2026-10-19"}}],
     "likelihood": "likely", "consequence": "major", "rated_by": "proposed",
     "rationale": "Why these ratings, from the evidence.",
     "steward": "Chief Information Security Officer",
     "treatment": {"option": "reduce",
                   "actions": [{"text": "Upgrade Log4j", "owner": "Application owner", "due": "2026-10-21", "ism": ["ism-1876"]}],
                   "residual_likelihood": "unlikely", "residual_consequence": "major"},
     "acceptance": {"by": "Authorising Officer", "date": "2026-10-30"}}
  ],
  "plan": {
    "goals": "...", "capability": "...", "implications": "...", "pspf_implementation": "...",
    "directions": "...", "incident_management": "...", "monitoring": "...",
    "approval": {"by": "Authorising Officer", "date": "2026-10-30"}
  },
  "missing_sources": ["ASD ACSC advisories (mcp__asd__asd_search)"]
}
```

## Keys

| Key | Meaning |
| --- | --- |
| `documents` | `tra`, `srmp` or both. Default both. |
| `scope.kind` | `entity`, `system`, `technology` (Technology Security Risk Management Plan, PSPF Requirement 0211), `facility` or `project`. Default `entity`. |
| `scope.acceptance_authority` | Who decides on residual risk. Default `Authorising Officer` for `system` and `technology`, otherwise `Accountable Authority`. |
| `matrix` | The entity's own matrix. Omit it to use the labelled default 5 by 5 matrix. `grid` has one row per likelihood label (lowest first) and one column per consequence label (lowest first). Every cell is one of `levels` (lowest first). |
| `tolerance.rating` | The highest residual rating the Accountable Authority accepts. One of `levels`. Omit it when the user did not supply it. |
| `threats[].evidence[].source` | The tool envelope name, its version or release, and the retrieval date. Omit `source` for text the user supplied. It is cited as `supplied context`. |
| `risks[].rated_by` | `proposed` when the assistant drafted the rating from the evidence. Otherwise the person or role who rated it. |
| `risks[].treatment.option` | `reduce`, `avoid`, `share` or `accept`. |
| `risks[].treatment.residual_likelihood` and `residual_consequence` | The target after treatment. When absent, the inherent rating is carried as the residual. |
| `risks[].acceptance` | Only a decision the user says was made. Never a proposed one. |
| `plan` | Free text for the security plan elements the user supplied. An absent element is `missing`. |
| `missing_sources` | Labels for each tool that was absent or returned nothing. |

## Output

The script prints the TRA, then the SRMP. With `--out DIR` it also writes `tra.md`, `srmp.md` and `register.csv` (risk register) into `DIR`. CSV cells that start with `=`, `+`, `-` or `@` are prefixed with `'`.

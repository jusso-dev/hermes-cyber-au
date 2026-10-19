# PSPF threat and risk assessments and SRMPs

The `pspf-risk-assessment` skill drafts a threat and risk assessment (TRA) and a security risk management plan (SRMP) that follow the Protective Security Policy Framework (PSPF) Release 2026 security risk management process. It covers:

| Plan | `scope.kind` | PSPF hook |
|---|---|---|
| Risk component of the entity security plan | `entity` | Requirements 0018 to 0020, 0036 to 0038 |
| System SRMP (supports authorisation to operate) | `system` | Requirements 0085, 0086, 0089, 0090 |
| Technology Security Risk Management Plan for the internet-facing estate | `technology` | Requirement 0211 |
| Facility or project SRMP | `facility`, `project` | Requirements 0036, 0037 |

It is a drafting aid. It is not an IRAP assessment, an authorisation to operate, or a PSPF compliance finding. It never accepts a risk, approves a plan or sends anything.

## Run one

```bash
hermes -p cyber-au chat
```

Then ask, for example:

```text
Do a PSPF threat and risk assessment of APP-DEMO-07 in examples/assets.csv and draft its security risk management plan. Our risk tolerance is medium.
```

The assistant:

1. Asks the intake questions in one message (`skills/pspf-risk-assessment/templates/intake.md`): scope, classification, objectives, your risk matrix, who set the risk tolerance, critical assets, products and versions, the National Terrorism Threat Level, existing controls, risk stewards, and the security plan elements you already have.
2. Builds the threat assessment from the connectors: KEV for products and CVEs in scope, ASD's ACSC advisories, MITRE ATT&CK, and the local intel store. Each fact carries a `Source:` line. A connector that is off is listed as a missing source.
3. Writes risk statements (threat, asset, vulnerability, consequence), maps existing controls and treatments to ISM controls the ISM connector returned, and proposes ratings for the risk steward to confirm.
4. Runs `skills/pspf-risk-assessment/scripts/render_risk.py`, which applies the matrix, compares residual risk with the tolerance, lists gaps (no steward, no tolerance, unsourced threats, risks above tolerance without treatment, instructions found in pasted content) and computes the annual consideration and two-yearly review dates.

Ask it to save the output and name a directory. It writes `tra.md`, `srmp.md` and `register.csv` there. Keep those files at the classification of the subject. Do not commit them.

## Bring your own matrix

Without your matrix the script uses a labelled default 5 by 5 matrix (likelihood times consequence: 1 to 3 low, 4 to 9 medium, 10 to 15 high, 16 to 25 extreme) and says to replace it before approval. To use your enterprise matrix, give the assistant your likelihood labels, consequence labels, rating levels and the grid. The input format is in `skills/pspf-risk-assessment/references/input.md`.

## What stays with people

- Risk tolerance is set by the Accountable Authority (Requirement 0036). With no tolerance, no risk is evaluated against one.
- Every risk needs a risk steward (Requirement 0037). A missing steward is a gap.
- Residual risk above tolerance is a decision for the Accountable Authority, or the Authorising Officer for a technology system (Requirement 0086). The plan shows it as a proposal.
- The Accountable Authority approves the entity security plan (Requirement 0019).

PSPF text comes from `skills/pspf-risk-assessment/references/pspf-2026.md`, quoted from the PSPF Release 2026 published by the Department of Home Affairs under Creative Commons Attribution 3.0 Australia.

---

Owner ticket: pspf-risk-assessment
Last verified: 19 October 2026

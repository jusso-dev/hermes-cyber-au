# Threat model

This is the threat model for the cyber-au Hermes profile. Later security work traces each control back to a threat here. It names assets, impacts, and the ticket and test that address each control.

Reviewed on 17 October 2026 against STRIDE and the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/). Hermes platform facts are from [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) at `43faacf` (v0.22.2), the same pin as the security tickets. The checked notes are in [docs/research/hermes-structure.md](../research/hermes-structure.md).

## Scope

The system is the installed `cyber-au` profile: `distribution.yaml`, `SOUL.md`, `config.yaml`, skills, cron jobs, the `plugins/cyber-au` plugin, the MCP connectors under `mcp/`, and the local intel store. Routines can deliver to Slack, Teams, or email once an operator resumes them.

The host matters as the place the profile home sits (`~/.hermes/profiles/cyber-au/`), including `.env`, sessions, and `plugin-data/`. The Hermes binary, the model provider's weights, and the customer's wider network sit outside this model. This document records the Hermes controls the profile relies on. The Hermes source tree stays out of it.

Assumptions:

- The person who installs the profile is the operator of that host.
- Cron jobs ship paused. A resumed job has no person at the keyboard, so a write must fail closed.
- Text from catalogue hosts (cyber.gov.au, AusCERT, OTX, abuse.ch, NVD, and the rest of the feed list) is data about the world, including when the publisher is a known body.
- The model provider receives the prompt the agent builds. Keys that live in the profile `.env` have to stay out of that prompt, out of logs, and out of deliveries.

## Assets

| Id | Asset | Where it lives | Impact if lost |
|---|---|---|---|
| A1 | Provider keys and connector keys | Profile `.env`, referenced only as `${VAR}`. Names start in `distribution.yaml` `env_requires`. | Someone else spends the team's quota or uses a paid feed under the team's licence. A key that reaches git history or a cassette stays disclosed. |
| A2 | Intel store | `plugin-data/cyber-au/intel.sqlite`. User-owned, so a profile update leaves it in place. Rows may be TLP:CLEAR public feeds or TLP:AMBER analyst data. | Disclosure of an investigation, of customer indicators, or of a draft breach assessment. A poisoned row that a later answer cites as fact. Loss of the store on an update. |
| A3 | Delivery channels | Slack, Teams, and email, chosen when an operator resumes a routine. | A briefing is a copy. A secret or a TLP:AMBER conclusion in that copy is visible to the whole channel. The post itself is an action taken in the team's name. |
| A4 | The analyst's trust in outputs | Skill answers and briefings: ISM control ids, Essential Eight claims, NDB assessments and their 30-day deadline, SOCI 12-hour, 72-hour, and 84-hour deadlines, all in Sydney time. | A wrong id or a wrong deadline becomes a missed statutory report or a false compliance claim. The profile states that its output is guidance, and the analyst is still invited to rely on it. |
| A5 | The host running Hermes | The machine or container, and the profile home on it. | The host can read `.env`, the store, sessions, and the audit log. Any code this distribution runs (a skill, a plugin hook, a dependency) inherits that access. |

Two further assets sit under those five. Distribution files (`SOUL.md`, skills, cron, plugin code) are the instructions the host will run; tampering with them exposes A1 to A5. The audit log is the record an assessor uses after the fact; losing it is threat T6.

## Threats

| Id | Threat | Entry | Impact on | Later ticket | Test |
|---|---|---|---|---|---|
| T1 | Indirect prompt injection in feed content | MCP tool results | A4, then A1, A3, or A5 if it steers a later action | [062](../../tickets/062-sec-prompt-injection.md) (issue 66) | `TestEnvelope.test_untrusted_text_property`, `TestEnvelope.test_warning_redaction_and_cache_names`; corpus and hook test in issue 66 |
| T2 | Secret leakage | Tool args, logs, cassettes, exports, briefing delivery | A1, and A2 when a delivery copies store data | [061](../../tickets/061-sec-secrets.md) (issue 65) | Redaction tests in `test_library.py` and `test_nvd.py`; gitleaks in issue 65 |
| T3 | Exfiltration to an attacker host | Web tools, MCP | A1, A2, A5 | [063](../../tickets/063-sec-egress.md) (issue 67) | `TestEgress` and `TestHttp.test_redirect_to_denied_host`; allowlist check in issue 67 |
| T4 | Tampered distribution or dependency | `hermes profile update`, uv | A5, then A1 and A2 | [065](../../tickets/065-sec-supply-chain.md) (issue 69) | Release-notes, SBOM, and attestation checks in issue 69 |
| T5 | Unreviewed action | Write tools | A3, A4 | [062](../../tickets/062-sec-prompt-injection.md) (issue 66), on top of Hermes approvals | SOUL rules test; hook test in issue 66 |
| T6 | Loss of accountability | No single entry; the record is missing or altered | A2, A3, A4 | [064](../../tickets/064-sec-audit-log.md) (issue 68) | `audit verify` tamper test in issue 68 |
| T7 | Over-trust in a wrong answer | Skills | A4 | [040](../../tickets/040-skill-standards-evals.md) (issue 44) | SOUL rules test; `tests/skills/harness.py` in issue 44 |

### T1. Indirect prompt injection

Feed text (RSS items, OTX pulses, advisory pages, email bodies under analysis) arrives as an MCP tool result. The impact is that the model treats that text as a new task. The analyst then trusts a steered answer (A4). The same turn can go on to disclose a key (T2), call an outside host (T3), or take a write action (T5).

STRIDE: spoofing and tampering. OWASP: LLM01:2025 Prompt Injection.

Control ticket: [Prompt injection defences for feed content](../../tickets/062-sec-prompt-injection.md) (GitHub issue 66). That ticket wraps free text as untrusted, banners connector results, guards the next write or outbound tool unless the analyst approves that exact call, requires `trust: untrusted` on every connector server, keeps the SOUL rule free of scanner phrases, and states allowed actions in cron prompts.

The guard shows the tool and its full redacted arguments with a random approval code. The person's message must name that code. Approval binds the tool name and argument hash, permits one call, and expires after ten minutes or when the next turn starts. A bare approval, feed text and an empty session id grant nothing. Arguments too large to show in full cannot be approved through this guard. Wrapper look-alikes in nested fields and warnings are defused before reaching the model. These controls limit the effect of flagged content; the injection detector remains a heuristic.

Tests:

- In tree: `TestEnvelope.test_untrusted_text_property` and `TestEnvelope.test_warning_redaction_and_cache_names` in [mcp/common/tests/test_library.py](../../mcp/common/tests/test_library.py). The first checks that feed text is wrapped, length-capped, and stripped of control and bidi characters. The second checks that the result envelope carries `untrusted: true`. Neither shows that the model ignores the text.
- Specified by issue 66: the corpus under `tests/security/injection/`, and the deterministic hook test that every corpus case is blocked from triggering a write or outbound tool. The model eval pass rate is recorded per release.
- In tree: `tests/security/injection/test_approval.py` checks exact-call approval, single use, expiry, session isolation and safe previews. `mcp/common/tests/test_envelope.py` and `tests/security/injection/test_feed_fields.py` check nested fields and wrapper look-alikes.

### T2. Secret leakage

A provider key or connector key leaves `.env` through a tool argument, a log line, an exception, a pytest-recording cassette, a STIX or other export, or a briefing delivered to Slack, Teams, or email. The impact is use of the team's upstream access (A1). The same paths can copy TLP:AMBER store contents into a log or a channel (A2, A3).

STRIDE: information disclosure. OWASP: LLM02:2025 Sensitive Information Disclosure.

Control ticket: [Secrets handling](../../tickets/061-sec-secrets.md) (GitHub issue 65). Config keeps `${VAR}` placeholders, `cyberau_common.secrets.redact()` covers logs, envelopes, exceptions, and the audit log, cassettes are scrubbed, gitleaks runs on history, and doctor warns when `.env` is looser than mode 600. Hermes already filters the MCP subprocess environment and redacts common secret shapes in MCP errors.

Tests:

- In tree: `TestHttp.test_secrets_are_redacted_in_errors`, `TestEnvelope.test_redact_headers_and_log`, `TestEnvelope.test_fixtures_have_no_secret`, and `TestCache.test_key_ignores_secret_and_changes_with_scope` in [mcp/common/tests/test_library.py](../../mcp/common/tests/test_library.py). Also `test_offline_prefers_cache_and_redacts_api_key` and `test_nvd_vcr_config_filters_api_key` in [mcp/nvd/tests/test_nvd.py](../../mcp/nvd/tests/test_nvd.py). `DistributionSkeletonTest.test_env_template_has_no_values` and `test_git_index_has_no_secret_files` in [tests/test_distribution_skeleton.py](../../tests/test_distribution_skeleton.py).
- Specified by issue 65: seeded fake keys never appear in test output, cassettes, logs, or exports, and gitleaks is clean on full history.

### T3. Exfiltration

A URL tool or a connector reaches a host outside the catalogue and sends session content, store rows, or keys there. The same path can reach the host's private network. The impact is disclosure of A1 and A2, and use of the host as an open client (A5).

STRIDE: information disclosure. OWASP: LLM02:2025, with LLM01:2025 as the usual way the call gets chosen.

Control ticket: [Egress allowlist](../../tickets/063-sec-egress.md) (GitHub issue 67). Connectors use `mcp/egress-allowlist.yaml` (HTTPS, private ranges refused, redirects checked again). Web and browser tools are either disabled in this profile or refused by a `pre_tool_call` hook for hosts outside that list. Sandbox egress is Docker with no network, or iron-proxy limited to catalogue hosts. Hermes already provides `security.website_blocklist`, SSRF protection on URL tools, and `security.allow_private_urls: false` (set in this profile's `config.yaml`).

Tests:

- In tree: `TestEgress.test_denies_other_host`, `TestEgress.test_denies_private_dns_and_link_local`, `TestEgress.test_punycode_lookalike_is_denied`, and `TestHttp.test_redirect_to_denied_host` in [mcp/common/tests/test_library.py](../../mcp/common/tests/test_library.py).
- Specified by issue 67: a connector test that refuses an off-list call before a socket opens, `tools/ci/check_allowlist.py` so the allowlist and the inventory cannot drift, and hook tests for allowed, denied, and redirecting URLs.

### T4. Tampered update or dependency

`hermes profile update` or a uv dependency replaces SOUL, a skill, a cron job, the plugin, or a library with something the operator did not review. Hermes distributions are unsigned and installed from git. Cron jobs arrive paused. SOUL and skills are live on the first chat. The impact is attacker-controlled code on the host (A5), with the profile `.env` and the intel store in reach (A1, A2).

STRIDE: spoofing and tampering. OWASP: LLM03:2025 Supply Chain.

Control ticket: [Supply chain](../../tickets/065-sec-supply-chain.md) (GitHub issue 69, milestone v0.2). Lockfile hashes, a CycloneDX SBOM, GitHub artifact attestations, release notes that list every changed skill, SOUL line, and cron job, and docs that recommend `install.sh --ref <tag>` over `main`. A legitimate update must still keep `.env`, memories, the intel store, and local config edits: [Update and pinning path](../../tickets/014-install-update-path.md).

Tests specified by issue 69: `gh attestation verify` on a release asset, an SBOM that lists every runtime dependency in the lock, and a release-notes generator test covering SOUL, skills, and cron diffs. Nothing in tree yet implements those checks. `DistributionSkeletonTest.test_owned_paths_exist` only checks that the manifest's owned paths are present.

### T5. Unreviewed action

The agent blocks an address, sends email, opens a ticket, posts to a channel, or contacts a regulator without an explicit approval in this session. In cron, the same action would run with nobody watching. The impact is an action in the team's name (A3) and a decision the analyst did not make (A4), including a containment change or a notification to a regulator.

STRIDE: elevation of privilege. OWASP: LLM06:2025 Excessive Agency. T1 is the usual way an unreviewed write gets chosen.

Controls:

- Already in the profile: `SOUL.md` states that the agent proposes and a person acts. Sending a report, blocking an address, opening a ticket, or contacting a regulator needs that person's approval in this session.
- Platform, relied on and not re-built here: dangerous command approval and `approvals.deny`. See [Hermes security](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/security.md).
- In tree: `mcp/servers.yaml` and the scaffold template already set `trust: untrusted` on every current connector server, so a tool without `readOnlyHint: true` asks for approval and fails closed in cron. No test pins that setting yet. Issue 66 owns the requirement.
- In tree: the `pre_tool_call` guard blocks a write or outbound tool after flagged content unless the analyst approved that exact pending call. The grant is consumed once and does not carry into later turns.

Tests:

- In tree: `DistributionSkeletonTest.test_soul_states_the_rules_and_avoids_scanner_phrases` in [tests/test_distribution_skeleton.py](../../tests/test_distribution_skeleton.py). `TestServer.test_read_only_hint_unless_writes` in [mcp/common/tests/test_library.py](../../mcp/common/tests/test_library.py).
- Specified by issue 66: the deterministic hook test that every injection-corpus case is blocked from triggering a write or outbound tool. Issue 44's harness can assert that a named tool was not called.

### T6. Loss of accountability

After a tool call, an approval, a block, an export, or a delivery, an assessor cannot show what happened, or can be shown a log that was edited. The impact is that a TLP:AMBER export (A2), a channel post (A3), or a wrong briefing (A4) cannot be reconstructed. There is no single entry point. The failure is the missing or altered record.

STRIDE: repudiation. OWASP: this cuts across LLM02 and LLM06. The log is what makes those two detectable.

Control ticket: [Tamper-evident audit log](../../tickets/064-sec-audit-log.md) (GitHub issue 68). Append-only hash-chained JSONL of session, tool, approval, export, delivery, and config events. Results are hashed, so TLP:AMBER bodies stay out of the log. If the log cannot be written, write tools are blocked and read tools continue with a warning.

Test specified by issue 68: deleting or editing any line makes `cyber-au audit verify` fail with the line number. The plugin directory is still a placeholder, so this test is not in the tree yet.

### T7. Over-trust in a wrong answer

A skill states an ISM control id that is not in the loaded release, or a deadline that does not match the SOCI 12-hour, 72-hour, or 84-hour clock or the NDB 30-day assessment period, and the analyst acts on it. The impact is a false compliance claim or a missed statutory report (A4). The entry point is the skill, including when the underlying feed was silent or stale.

STRIDE: no category fits a wrong but honest answer. Tampering is the nearest, with the analyst's decision record as the thing that ends up wrong. OWASP: LLM09:2025 Misinformation.

Control ticket: [Skill authoring standard and offline eval harness](../../tickets/040-skill-standards-evals.md) (GitHub issue 44). Citations are `Source: <name>, <version>, retrieved <date>`. A missing fact is answered with "I don't know". The same rule is already in `SOUL.md`. The workflows where a wrong id or a wrong deadline does the damage are [ISM control lookup](../../tickets/044-skill-ism-control-lookup.md), [NDB breach notification](../../tickets/049-skill-ndb-breach-notification.md), and [SOCI reporting](../../tickets/050-skill-soci-reporting.md). Those skills are held to the issue 44 harness.

Tests:

- In tree: `DistributionSkeletonTest.test_soul_states_the_rules_and_avoids_scanner_phrases` in [tests/test_distribution_skeleton.py](../../tests/test_distribution_skeleton.py).
- Specified by issue 44: `tests/skills/harness.py` scores required facts, forbidden claims, and expected tool calls against recorded fixtures. Structural checks (frontmatter, sections, citation shape) run in CI with no model key.

## Platform controls this distribution relies on

These are Hermes v0.22.2 controls. The distribution uses them as they ship. Each one is named in [the Hermes security guide](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/security.md) or the [iron-proxy egress guide](https://github.com/NousResearch/hermes-agent/blob/43faacfb8de7b29548547a7fbdedad0cc6e7391c/website/docs/user-guide/egress/iron-proxy.md) at `43faacf`.

| Control | What we rely on it for | Threat |
|---|---|---|
| Dangerous command approval | A dangerous terminal command waits for the operator. | T5 |
| `approvals.deny` | A denied command pattern is blocked even when approval mode is relaxed. | T5 |
| SSRF protection | URL tools refuse private, loopback, and link-local targets. | T3 |
| `security.website_blocklist` | Named sites are refused for web and browser tools. This is a deny list. The allowlist is issue 67. | T3 |
| Context-file injection scanning | A distribution `SOUL.md` that matches the scanner is blocked on install and update. The scanner is a pattern heuristic and covers `SOUL.md` only, so it does not review skills, cron jobs, or plugin code. | T1, T4 |
| MCP environment filtering | A stdio connector receives a filtered environment plus only the keys that server's `env` lists. | T2 |
| MCP error redaction | Common secret shapes in connector errors are replaced before the model sees them. | T2 |
| `trust: untrusted` | A connector tool without `readOnlyHint: true` requires approval and fails closed in cron. | T5 |
| Iron-proxy, or Docker with no network | A terminal sandbox's egress is limited to the hosts the operator listed, or has no network. | T3 |

`config.yaml` in this repo sets `security.allow_private_urls: false` and `security.redact_secrets: true`. The model and provider stay unset so the installer chooses them.

## STRIDE review

| STRIDE | Where it shows up | Covered by |
|---|---|---|
| Spoofing | Feed text presenting itself as a new task (T1). An update presenting itself as this distribution (T4). A hostname that only looks like a catalogue host (T3). | Issue 66, issue 69, `TestEgress.test_punycode_lookalike_is_denied` |
| Tampering | Replaced SOUL, skill, cron job, or dependency (T4). A store row that a later answer cites (T1, T7). | Issue 69, issue 66, issue 44 |
| Repudiation | A tool call, approval, export, or delivery with no intact record (T6). | Issue 68 |
| Information disclosure | Keys in logs, cassettes, exports, or briefings (T2). A call to a host outside the catalogue (T3). | Issue 65, issue 67 |
| Denial of service | A huge page or a long tool loop consuming provider quota or stalling a briefing. Not given its own T id. | Residual. See LLM10 below. |
| Elevation of privilege | A read-only assistant blocking, emailing, ticketing, or notifying a regulator (T5), including when T1 chose that action. | Hermes approvals, issue 66 |

## OWASP Top 10 for LLM Applications (2025)

| Id | Risk | Disposition in this distribution |
|---|---|---|
| LLM01:2025 | Prompt Injection | T1. Issue 66. |
| LLM02:2025 | Sensitive Information Disclosure | T2 and T3. Issues 65 and 67. |
| LLM03:2025 | Supply Chain | T4. Issue 69. Distributions are unsigned today; that is the gap issue 69 closes. |
| LLM04:2025 | Data and Model Poisoning | Vendor model training stays with the model provider. Feed rows can still bias a later answer once they sit in the store. Issue 66 marks that text untrusted. Issue 44 requires a citation for a factual claim. [Store schema and ingest](../../tickets/052-store-schema-ingest.md) keeps a `source_id` on each observation. |
| LLM05:2025 | Improper Output Handling | A briefing or a drafted ticket is output that Slack, Teams, email, or a tracker may render. T5 requires approval before that write. Issue 65 keeps secrets out of the delivery. Residual: a markup sanitiser for channel posts has no ticket yet. The agent's own later fetches still have to pass the T3 allowlist. |
| LLM06:2025 | Excessive Agency | T5. Hermes approvals plus `trust: untrusted` (set today, required by issue 66). Cron ships paused. |
| LLM07:2025 | System Prompt Leakage | `SOUL.md` and the skills are published in this repository. Secrecy of the system prompt is not an asset. The impact that matters is a secret written into SOUL or a skill, which issue 65 and `test_env_template_has_no_values` forbid. Hermes still blocks a distribution SOUL that trips the injection scanner. |
| LLM08:2025 | Vector and Embedding Weaknesses | v0.1 stores indicators as SQLite rows ([store schema](../../tickets/052-store-schema-ingest.md)). Revisit this row if a later ticket adds an embedding index. |
| LLM09:2025 | Misinformation | T7. Issue 44, with the ISM, NDB, and SOCI skills as the workflows where a wrong fact does harm. |
| LLM10:2025 | Unbounded Consumption | Residual. The shared client already caps response size (`TestHttp.test_size_cap`) and rate-limits (`TestLimiter` in [mcp/common/tests/test_library.py](../../mcp/common/tests/test_library.py)). Issue 66 caps the length of an untrusted field. No ticket yet sets a provider-spend limit. The impact is a run that spends the team's model quota or delays the briefing. |

## Residuals

These stay accepted until a later ticket takes them.

- The host is trusted to the same degree as the operator. Disk encryption and OS hardening are outside the distribution.
- TLP:AMBER handling in the store is marking, retention, and export ([retention and snapshots](../../tickets/054-store-retention-snapshots.md), [STIX export](../../tickets/053-store-stix-export.md), issue 68). Choosing a delivery channel whose audience is wider than the marking is an operator decision. The log records the delivery. Channel choice stays with the operator.
- LLM05 markup in a delivered briefing, and LLM10 provider spend, have no dedicated ticket. The bounds above are what exists.
- Issue 69 is milestone v0.2. Until it lands, an operator who tracks `main` is trusting an unsigned git update. The install docs for that pin are part of issue 69.

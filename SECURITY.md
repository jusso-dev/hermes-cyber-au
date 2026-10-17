# Security policy

## Reporting a vulnerability

Report a vulnerability in this repository privately through GitHub Security Advisories:

<https://github.com/jusso-dev/hermes-cyber-au/security/advisories/new>

Use the **Report a vulnerability** button on the Security tab of the repository. That opens a private advisory to the maintainers.

There is no private email address for security reports. Do not open a public GitHub issue, discussion, or pull request for an unfixed vulnerability. Do not post proof-of-concept details on a public channel.

Maintainers enable private vulnerability reporting in the repository security settings. If that page says reporting is unavailable, wait and try the same link again rather than filing a public issue.

This is the channel for defects in this distribution: connector code, the shared library, skills, workflows, fixtures, and published configuration. Examples include a credential leaked into the tree, an egress allowlist bypass, authentication that fails open, or feed content that is treated as instructions instead of data inside the result envelope.

## What to include

- The affected version or git commit. The distribution version is the `version` field in `distribution.yaml`.
- What an attacker gains, and what they already need.
- A minimal proof of concept if you have one.
- Whether you have published the details anywhere.

Do not include live credentials, customer data, or data taken from someone else's system. If a fixture or commit already contains a secret, describe the path and the kind of secret. Do not paste the value.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.1.x on the default branch (`distribution.yaml` is 0.1.0) | Yes |
| Tag `legacy-skills-pack-final` | No |

`0.1.x` is the supported line. Fixes land on the default branch of this repository. There is no older release of this distribution to patch.

The tag `legacy-skills-pack-final` is a frozen copy of an earlier skill pack. It does not receive security fixes here. The maintained pack is [jusso-dev/hermes-skills](https://github.com/jusso-dev/hermes-skills).

## Response targets

Targets are counted in business days, Australia/Sydney. They are targets, not a service level agreement. If a target will be missed, maintainers post the new expectation on the advisory.

| Step | Target |
|---|---|
| Acknowledge a report that names the affected version and the impact | 3 business days |
| Say whether it is accepted, declined, or needs more detail | 7 business days |
| Ship a fix or mitigation on the supported line, or explain the remaining work in the advisory | 90 days |

A declined report is closed on the advisory with a reason. An accepted report stays private until a fix is on the supported line, or until the reporter and the maintainers agree to publish sooner. Publishing uses the same GitHub Security Advisory. There is no bug bounty.

## Out of scope

Report defects in Hermes Agent itself to [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent). Report defects in an upstream data source to that source. If this distribution mishandles that data, or configures Hermes in an unsafe way, report that here.

A missing connector, a feature idea, or a documentation typo is not a vulnerability. Use a [public issue](https://github.com/jusso-dev/hermes-cyber-au/issues/new/choose).

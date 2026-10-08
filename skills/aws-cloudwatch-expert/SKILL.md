---
name: aws-cloudwatch-expert
description: "Review AWS log queries against shipped schemas."
version: 0.1.0
author: Justin Middler
license: MIT
metadata:
  hermes:
    tags: [AWS, CloudWatch, CloudTrail, GuardDuty, Security Hub, Athena]
    related_skills: [detection-engineering, ism-control-lookup]
---

# AWS logging expert

Review CloudWatch Logs Insights, CloudTrail, CloudTrail Lake, GuardDuty, Security Hub, Security Lake, Athena, EventBridge, and Step Functions response designs. Read-only.

## When to Use

- The user wants a Logs Insights query, a CloudTrail Lake SQL query, or an Athena query checked before use.
- The user wants GuardDuty or Security Hub findings explained against the ISM.
- The user wants an EventBridge or Step Functions response sketched, not deployed.
- Not for IAM changes, account changes, or any write API.

## Procedure

1. Name the schema in a comment: `-- cyber-au-schema: cloudtrail_lake` (or another name in `knowledge/schemas/aws.json`).
2. Call `cyber_au_check_query` with `sql` or `logs_insights`. Show the query as ready only when the tool says ready.
3. Security Lake rows in the schema are OCSF field names from the public AWS pages recorded in that file. If a field is missing, say so. Do not invent a column.
4. Map the detection to the ISM with `cyber_au_control`. Cite version, date, and URL.
5. GuardDuty and Security Hub: describe the finding the user pasted. Do not claim the account's live posture.
6. EventBridge and Step Functions: write the intended pattern as a proposal. Open `cyber_au_propose_response` before you treat it as approved. This pack still does not call a write API.
7. Live queries use `cyber_au_live_query` with kind `logs_insights` or `cloudtrail_lake`. They stay off until `CYBER_AU_AWS_REGION` and a read-only role are set. Logs Insights also needs `CYBER_AU_LOG_GROUP`.

## Pitfalls

- A SELECT that lacks the schema comment is not ready.
- `INSERT`, `UPDATE`, `DELETE`, `DROP`, and `UNLOAD` are refused.
- YARA-L and Chronicle are not covered by the AWS schema. Do not mark them ready here.
- Do not put an account ID into a skill, a commit, or a fine-tune row.

## Verification

- The checker result is in the answer.
- ISM citations come from `cyber_au_control`.
- Live status is reported from the tool, not assumed.

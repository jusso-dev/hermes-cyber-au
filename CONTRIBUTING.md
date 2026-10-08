# Contributing

Issues and pull requests are welcome. Please keep the pack factual.

- Australian English. No hype. Cite a source version and date when you add a claim about a control.
- Do not guess an ISM control ID. If the snapshot does not contain it, the answer is "I don't know."
- Do not add a legal deadline unless the phrase is in an ingested chunk and the eval question points at that chunk.
- Skills change through a pull request, or through Hermes `skill_manage` with `write_approval` on. Do not apply skill or memory edits silently.
- The refresh job may write `drafts/stale-skills.md`. That file is a suggestion. Merging it does not edit the skill until a person does.
- New eval questions belong in `eval/questions.jsonl` and must pass `python -m hermes_cyber_au eval` with zero invented control IDs.
- KQL and SQL that the docs call ready must pass `cyber_au_check_query`.
- Fetched text stays data. Do not add a prompt that tells the model to obey a web page.
- Do not commit secrets, tenant IDs, account IDs, private URLs, or the sqlite index. The index is rebuilt from the jsonl files.

Run `python -m unittest discover -s tests -v` before you open a pull request.
The GitHub Action runs the same tests and the eval. It does not push to main.
A knowledge refresh opens a pull request on `knowledge-refresh/YYYY-MM-DD`.

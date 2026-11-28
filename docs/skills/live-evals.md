# Live-model eval scorecard

The weekly `live-evals` workflow (`.github/workflows/live-evals.yml`) runs every skill's evals against real models, so a Hermes, model or prompt change that makes a skill worse shows up within a week. Offline evals in CI still run on every pull request; they score recorded sessions and the harness logic, not a model.

The latest published summary is the [scorecard](scorecard.md).

## What it does

1. Runs on Monday at 05:00 AEDT (Sunday 18:00 UTC), or by hand from the Actions tab.
2. Skips with a notice, and does nothing else, when the `OPENROUTER_API_KEY` secret or the model list is missing.
3. Installs the profile from the checkout inside the pinned Hermes image and runs `tests/skills/harness.py --live`. Connectors run with `CYBERAU_OFFLINE=1`, so only the model call goes to the network.
4. Scores each skill and model with `tools/ci/eval_scorecard.py`: the share of cases that pass, against the skill's threshold in `tests/skills/eval-thresholds.yaml`.
5. Uploads one markdown scorecard per skill as the `live-eval-scorecards` artifact.
6. Opens or updates a data pull request for `docs/skills/scorecard.md` through the shared data PR flow. The pull request is never merged automatically.
7. When any skill and model is below its threshold, has no threshold, or has no results, opens one issue titled `Live eval regression`, or comments on the open one. The issue is a draft for a maintainer to triage. Nothing is reverted or merged.

Hermes quiet mode does not report tool calls, so live runs score required facts, forbidden claims and citation format only. The scorecard counts the cases whose tool assertions were left unscored. Offline evals still score tool calls.

Model output and Hermes error text are never copied into a scorecard, the summary or the issue. Failures are reduced to fixed categories, plus text from the committed eval files (the required fact or forbidden claim that failed).

## Set it up

A maintainer adds these in the repository settings. Nothing runs until they exist.

| Name | Kind | What it holds |
|---|---|---|
| `OPENROUTER_API_KEY` | Repository secret | An OpenRouter API key for an account with an agreed spending limit. |
| `CYBERAU_EVAL_MODELS` | Repository variable | Comma-separated OpenRouter model ids to evaluate, for example `anthropic/claude-sonnet-4.5`. |
| `DATA_PR_TOKEN` | Repository secret, optional | The same token the other data workflows use, so the scorecard pull request triggers CI. |

The workflow passes the key to the Hermes container as an environment variable with `HERMES_INFERENCE_PROVIDER=openrouter`. It never prints the key or puts it on a command line. Each case makes one model call per model, so the weekly cost is roughly the number of eval cases times the number of models; set a spending limit on the key.

## Run it by hand

From the Actions tab, run `live-evals` with:

- `models`: overrides `CYBERAU_EVAL_MODELS` for this run.
- `force_regression`: a skill id. That skill's threshold is raised above 100% for this run only, so it is flagged and the issue path can be checked. The issue says the regression was forced. Close it afterwards.

A manual run with the secret set produces a scorecard for every skill that has an `evals.yaml` with cases. A skill missing from the run is reported as `no results`.

## Thresholds

`tests/skills/eval-thresholds.yaml` holds one pass rate per skill, from 0 to 1. Every skill with evals must have an entry; a test enforces this. The starting values are a conservative 0.6 because no live baseline existed when the workflow was added. After the first few runs, raise each threshold to just below the observed pass rate. Lower one only with a reason in the pull request.

## Run the scorer locally

```bash
uv run --project mcp python tests/skills/harness.py --results-dir eval-out
uv run --project mcp python tools/ci/eval_scorecard.py score --results-dir eval-out \
  --thresholds tests/skills/eval-thresholds.yaml --out-dir scorecards --allow-offline
```

`--allow-offline` scores the recorded offline sessions. The workflow does not pass it, so a run where the model matrix was skipped fails instead of publishing an offline score as a live one.

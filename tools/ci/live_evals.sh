#!/bin/bash
# Run the live skill evals inside the pinned Hermes image, with the checkout mounted at /src.
# .github/workflows/live-evals.yml calls this. It installs the profile from the checkout
# (offline, no network for the profile itself), then runs tests/skills/harness.py --live.
#
# Needs in the environment (names only; values come from the workflow):
#   CYBERAU_EVAL_MODELS        comma-separated model ids
#   HERMES_INFERENCE_PROVIDER  the Hermes provider for those ids
#   OPENROUTER_API_KEY         the provider key (repo secret)
# Connectors still run with CYBERAU_OFFLINE=1, set by the harness. Only the model call is live.
set -euo pipefail

: "${CYBERAU_EVAL_MODELS:?CYBERAU_EVAL_MODELS is not set}"

export HERMES_HOME=/tmp/cyber-au-eval-home
export HERMES_PYTHON=/opt/hermes/.venv/bin/python
export PATH="/opt/hermes/.venv/bin:$PATH"
export CYBERAU_EVAL_PROFILE=cyber-au-eval

"$HERMES_PYTHON" -m ensurepip --upgrade >/dev/null
"$HERMES_PYTHON" -m pip install --quiet 'uv<1'

cp -R /src/mcp /tmp/cyber-au-eval-mcp
uv sync --quiet --project /tmp/cyber-au-eval-mcp --all-packages --frozen
uv pip install --quiet --python "$HERMES_PYTHON" 'pyyaml>=6,<7' 'stix2>=3,<4'

/src/install/install.sh --profile "$CYBERAU_EVAL_PROFILE" --offline --no-hermes-install \
  --non-interactive --yes --allow-root

mkdir -p /src/eval-out
set +e
uv run --quiet --project /tmp/cyber-au-eval-mcp python /src/tests/skills/harness.py \
  --live --results-dir /src/eval-out
status=$?
set -e
# 0: every case passed. 1: some cases failed, which the scorecard scores. 2: a broken eval file.
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
  echo "::error title=Live evals::harness exited $status"
  exit "$status"
fi

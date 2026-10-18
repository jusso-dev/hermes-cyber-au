#!/bin/bash
# Run inside the pinned Hermes image, with the checkout mounted at /src:ro.
set -euo pipefail

export HERMES_HOME=/tmp/cyber-au-ci
export HERMES_PYTHON=/opt/hermes/.venv/bin/python
export PATH="/opt/hermes/.venv/bin:$PATH"

# Install the same uv range as the Python jobs. The image's venv has ensurepip
# but does not ship pip or uv. This container and its interpreter are disposable.
"$HERMES_PYTHON" -m ensurepip --upgrade >/dev/null
"$HERMES_PYTHON" -m pip install --quiet 'uv<1'

# Populate the cache before exercising the installer's offline path.
cp -R /src/mcp /tmp/cyber-au-warm-mcp
uv sync --quiet --project /tmp/cyber-au-warm-mcp --all-packages --frozen
uv pip install --quiet --python "$HERMES_PYTHON" 'pyyaml>=6,<7' 'stix2>=3,<4'

/src/install/install.sh --profile cyber-au-ci --offline --no-hermes-install \
  --non-interactive --yes --allow-root
export CYBERAU_HOME="$HERMES_HOME/profiles/cyber-au-ci"
"$CYBERAU_HOME/mcp/.venv/bin/python" - <<'PY'
import json
import os
from pathlib import Path

jobs = json.loads((Path(os.environ["CYBERAU_HOME"]) / "cron/jobs.json").read_text())["jobs"]
enabled = {job["id"] for job in jobs if job.get("enabled")}
assert enabled == {"cyberau-store-expire", "cyberau-store-maintenance"}, enabled
PY
hermes -p cyber-au-ci cyber-au doctor --offline --json

# Hermes's plugin doctor imports a scratch copy. Point it at the installed
# profile's connector environment, and run it only after bootstrap has built it.
hermes -p cyber-au-ci plugins doctor "$CYBERAU_HOME/plugins/cyber-au" --ci

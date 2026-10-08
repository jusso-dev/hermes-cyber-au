#!/usr/bin/env python3
"""Daily refresh. Silent unless the Australia/Sydney hour is 6, or the force flag is set.

Empty output means nothing material changed, or this run is outside that hour.
The GitHub Action uses that silence to avoid opening an empty pull request.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hermes_cyber_au.common import sydney_now  # noqa: E402
from hermes_cyber_au.refresh import refresh  # noqa: E402


def main() -> int:
    force = os.environ.get("CYBER_AU_FORCE_REFRESH") == "1" or "--force" in sys.argv
    if not force and sydney_now().hour != 6:
        return 0
    result = refresh(apply_pin=True)
    if not result.get("material"):
        return 0
    public = {
        "material": True,
        "ism": result.get("ism"),
        "failures": result.get("failures"),
        "digest": result.get("digest"),
        "stale_skills": result.get("stale_skills"),
    }
    sys.stdout.write(json.dumps(public, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

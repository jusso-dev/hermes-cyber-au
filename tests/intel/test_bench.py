"""The benchmark script runs on a small count. The million-row run is the script itself."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BENCH = Path(__file__).with_name("bench.py")


def test_bench_script_smoke(tmp_path):
    db = tmp_path / "intel.sqlite"
    completed = subprocess.run(
        [
            sys.executable,
            str(BENCH),
            "--count",
            "200",
            "--searches",
            "5",
            "--batch",
            "100",
            "--path",
            str(db),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert "ingest 200" in completed.stdout
    assert db.is_file()

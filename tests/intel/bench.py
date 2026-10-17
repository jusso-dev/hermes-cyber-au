"""Benchmark indicator ingest and search.

One million upserts should finish in under five minutes, and search p95 on
that data should stay under 100 ms. From the repository root:

    uv run --directory mcp python ../tests/intel/bench.py

Pass ``--count`` for a smaller run. The database is a fresh file, not a
shared temporary cache.
"""

from __future__ import annotations

import argparse
import math
import random
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "cyber-au"
if str(PLUGIN) not in sys.path:
    sys.path.insert(0, str(PLUGIN))

from store.api import search, upsert_indicator  # noqa: E402
from store.db import close_store, open_store  # noqa: E402

INGEST_BUDGET_SECONDS = 300
SEARCH_BUDGET_MS = 100


def run(
    count: int = 1_000_000,
    searches: int = 100,
    batch: int = 5_000,
    path: Path | None = None,
) -> dict:
    """Load ``count`` indicators and time point searches. Returns the measurements."""
    if count < 1 or searches < 1 or batch < 1:
        raise ValueError("count, searches and batch must be positive")
    if path is None:
        raise ValueError("path is required")
    store = open_store(path)
    conn = store.connection()
    conn.execute("PRAGMA cache_size=-1048576")
    conn.execute("PRAGMA wal_autocheckpoint=100000")
    conn.execute("INSERT INTO fts(fts, rank) VALUES ('automerge', 0)")
    started = time.perf_counter()
    done = 0
    while done < count:
        step = min(batch, count - done)
        with store.transaction():
            for offset in range(step):
                index = done + offset
                upsert_indicator(
                    "domain",
                    f"h{index}.example",
                    source="bench",
                    observed_at="2026-01-01T00:00:00Z",
                    raw=str(index).encode(),
                    verdict="malicious",
                    confidence=80,
                    path=path,
                )
        done += step
    ingest_seconds = time.perf_counter() - started
    conn.execute("INSERT INTO fts(fts) VALUES ('optimize')")

    rng = random.Random(52)
    samples: list[float] = []
    for _ in range(searches):
        token = f"h{rng.randrange(count)}"
        moment = time.perf_counter()
        rows = search(token, kinds=("indicator",), limit=5, path=path)
        samples.append((time.perf_counter() - moment) * 1000)
        if not any(row.get("value_norm") == f"{token}.example" for row in rows):
            raise RuntimeError(f"search missed {token}")
    search_p95_ms = _p95(samples)
    close_store(path)
    within_ingest = ingest_seconds < INGEST_BUDGET_SECONDS
    within_search = search_p95_ms < SEARCH_BUDGET_MS
    return {
        "count": count,
        "ingest_seconds": ingest_seconds,
        "search_p95_ms": search_p95_ms,
        "ok": within_ingest and within_search,
    }


def _p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    index = min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)
    return ordered[max(0, index)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark the intel store")
    parser.add_argument("--count", type=int, default=1_000_000)
    parser.add_argument("--searches", type=int, default=100)
    parser.add_argument("--batch", type=int, default=20_000)
    parser.add_argument("--path")
    args = parser.parse_args(argv)
    if args.path:
        result = run(args.count, args.searches, args.batch, Path(args.path))
        _report(result)
        return 0 if result["ok"] else 1
    with tempfile.TemporaryDirectory(prefix="cyberau-intel-") as directory:
        result = run(
            args.count,
            args.searches,
            args.batch,
            Path(directory) / "intel.sqlite",
        )
    _report(result)
    return 0 if result["ok"] else 1


def _report(result: dict) -> None:
    print(
        f"ingest {result['count']} in {result['ingest_seconds']:.1f}s; "
        f"search p95 {result['search_p95_ms']:.1f} ms"
    )
    if not result["ok"]:
        print(
            f"budget is {INGEST_BUDGET_SECONDS}s ingest and {SEARCH_BUDGET_MS} ms search p95",
            file=sys.stderr,
        )


if __name__ == "__main__":
    raise SystemExit(main())

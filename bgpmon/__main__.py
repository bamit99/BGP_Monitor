"""Entry point: run the monitoring service.

    python -m bgpmon          # API + monitoring (default)
    python -m bgpmon --soak 120   # headless throughput soak, no API
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logging.getLogger("websockets").setLevel(logging.WARNING)
    logging.getLogger("neo4j").setLevel(logging.WARNING)


def run_api() -> None:
    import uvicorn
    from bgpmon.api import create_app
    from bgpmon.config import Settings

    settings = Settings.load()
    uvicorn.run(create_app(settings), host=settings.api.host, port=settings.api.port, log_level="info")


def run_soak(seconds: int) -> int:
    from bgpmon.config import Settings
    from bgpmon.pipeline import Pipeline

    settings = Settings.load()
    pipeline = Pipeline(settings)
    pipeline.start()
    print(f"soak started for {seconds}s, collectors={','.join(settings.source.collectors)}")
    try:
        for i in range(seconds):
            time.sleep(1)
            if i % 15 == 14:
                h = pipeline.health()
                print(f"[{i+1:4d}s] q={h['queue_depth']:>6} updates={h['metrics']['updates_total']:>8} "
                      f"alerts={h['metrics']['alerts_total']:>5} suppressed={h['metrics']['suppressed_total']:>5} "
                      f"detect={h['metrics']['mean_detect_us']:.1f}us rpki={h['rpki']['indexed_prefixes']} "
                      f"neo4j_upd={h['sink']['updates_written']}")
    finally:
        pipeline.stop()
    h = pipeline.health()
    print("\n=== FINAL ===")
    print(f"updates={h['metrics']['updates_total']} ({h['metrics']['updates_per_second']}/s)")
    print(f"alerts={h['metrics']['alerts_total']} by_kind={h['metrics']['alerts_by_kind']}")
    print(f"severity={h['metrics']['alerts_by_severity']} suppressed={h['metrics']['suppressed_total']}")
    print(f"feed={h['feed']}")
    print(f"sink={h['sink']}")
    total = h["metrics"]["updates_total"] or 1
    print(f"alert rate = {100.0 * h['metrics']['alerts_total'] / total:.2f}% of updates")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="bgpmon")
    parser.add_argument("--soak", type=int, metavar="SECONDS", help="headless throughput test")
    parser.add_argument("--level", default=None, help="log level override")
    args = parser.parse_args()

    from bgpmon.config import Settings
    level = args.level or Settings.load().log_level
    setup_logging(level)

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    if args.soak:
        return run_soak(args.soak)
    run_api()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

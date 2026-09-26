"""BGP Monitor entry point.

    python main.py            # API + monitoring + dashboard on :8080
    python main.py --soak 120 # headless throughput verification
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bgpmon.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())

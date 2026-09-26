#!/usr/bin/env bash
# Telecom-grade BGP Monitor: service install (Linux).
set -euo pipefail
PY=${PY:-python3}
echo "==> Creating virtualenv"
"$PY" -m venv .venv
source .venv/bin/activate
echo "==> Installing runtime dependencies"
pip install -q -r requirements-service.txt -r requirements.txt
echo "==> Checking optional extras"
python - <<'PY'
missing = []
for name in ("prometheus_client", "fastapi", "neo4j", "websockets"):
    try:
        __import__(name)
    except ImportError:
        missing.append(name)
print("missing:", missing or "none")
PY
echo "==> Pulling CAIDA AS relationship data (route-leak detection)"
python - <<'PY'
from pathlib import Path
import urllib.request
out = Path("data/as_relationships.txt.bz2")
out.parent.mkdir(exist_ok=True)
if out.exists():
    print("    already present:", out)
else:
    url = "https://publicdata.caida.org/datasets/as-relationships/serial-1/20260901.as-rel.txt.bz2"
    print("    downloading", url)
    urllib.request.urlretrieve(url, out)
    print("    wrote", out, out.stat().st_size, "bytes")
PY
echo
echo "==> Done. Start with:  python -m bgpmon"
echo "    (set BGPMON_OWNED_PREFIXES to enable hijack/visibility baselines)"

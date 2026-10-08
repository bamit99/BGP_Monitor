"""FastAPI service: REST for history, WebSocket for live alert fanout, /metrics.

This is the API the web dashboard consumes; the Tkinter GUI is retired.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from bgpmon.config import Settings
from bgpmon.pipeline import Pipeline
from bgpmon.scope import ScopeLookup

logger = logging.getLogger(__name__)


def mount_dashboard(app: FastAPI, dist: Path) -> bool:
    """Serve the built SPA such that client-side deep links work.

    `StaticFiles(html=True)` mounted at "/" cannot serve a fresh GET of
    `/alerts`: the file does not exist, so it 404s before the React router ever
    runs. Route order matters — this is registered last, so the API, WebSocket
    and /metrics routes (already declared) still win.
    """
    index = dist / "index.html"
    if not index.is_file():
        logger.warning("Dashboard build not found at %s (run `npm run build` in web/)", dist)
        return False

    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        candidate = (dist / full_path).resolve()
        # Serve a real file when asked for one (favicon, manifest), but never
        # escape the build directory via a crafted path.
        if full_path and candidate.is_file() and str(candidate).startswith(str(dist.resolve())):
            return FileResponse(candidate)
        return FileResponse(index)

    logger.info("Serving dashboard from %s with SPA fallback", dist)
    return True


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings.load()
    pipeline = Pipeline(settings)
    scope_lookup = ScopeLookup()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        pipeline.start()
        app.state.pipeline = pipeline
        try:
            yield
        finally:
            await scope_lookup.close()
            pipeline.stop()

    app = FastAPI(
        title="BGP Monitor",
        description="Telecom-grade BGP routing security monitoring",
        version="2.0.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.api.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def require_token(authorization: Optional[str] = Header(default=None)) -> None:
        if not settings.api.token:
            return
        expected = f"Bearer {settings.api.token}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        return pipeline.health()

    @app.get("/api/alerts")
    def alerts(limit: int = Query(200, ge=1, le=2000),
               severity: Optional[str] = Query(None, description="minimum severity"),
               kind: Optional[str] = None,
               owned_only: bool = False,
               source: str = Query("auto", description="auto|memory|graph"),
               _: None = Depends(require_token)) -> Dict[str, Any]:
        if source in ("auto", "graph") and pipeline.sink.enabled:
            rows = pipeline.sink.recent_alerts(limit=limit, min_severity=severity, kind=kind)
            if rows:
                return {"source": "graph", "count": len(rows), "alerts": rows}
            if source == "graph":
                return {"source": "graph", "count": 0, "alerts": []}
        rows = pipeline.recent(limit=limit, min_severity=severity, kind=kind, owned_only=owned_only)
        return {"source": "memory", "count": len(rows), "alerts": rows}

    @app.get("/api/prefix/{prefix:path}/history")
    def prefix_history(prefix: str, limit: int = Query(50, ge=1, le=500),
                       _: None = Depends(require_token)) -> Dict[str, Any]:
        return {"prefix": prefix, "history": pipeline.sink.prefix_history(prefix, limit)}

    @app.get("/api/episodes")
    def episodes(limit: int = Query(200, ge=1, le=2000),
                 _: None = Depends(require_token)) -> Dict[str, Any]:
        """Open incidents: related alerts for a prefix, one per origin.

        Session-scoped. A restart mid-incident starts a new episode.
        """
        active = pipeline.episodes.active()
        active.sort(key=lambda e: (e.score, e.end_time), reverse=True)
        rows = [episode.to_dict() for episode in active[:limit]]
        return {"count": len(rows), "episodes": rows, "stats": pipeline.episodes.stats()}

    @app.get("/api/topology")
    def topology(limit: int = Query(300, ge=10, le=2000),
                 _: None = Depends(require_token)) -> Dict[str, Any]:
        return pipeline.sink.topology(limit)

    @app.get("/api/rpki/{prefix:path}/{origin_as}")
    def rpki_check(prefix: str, origin_as: int, _: None = Depends(require_token)) -> Dict[str, Any]:
        result = pipeline.rpki.validate(prefix, origin_as)
        return {
            "prefix": prefix,
            "origin_as": origin_as,
            "state": result.state,
            "reason": result.reason,
            "source": result.source,
            "matched": [{"asn": a, "max_length": m} for a, m in result.matched],
            "offending": [{"asn": a, "max_length": m, "why": w} for a, m, w in result.offending],
        }

    @app.get("/api/config")
    def config_summary(_: None = Depends(require_token)) -> Dict[str, Any]:
        return {
            "collectors": list(settings.source.collectors),
            "owned_prefixes": [str(p) for p in settings.detection.owned_prefixes],
            "critical_prefixes": [str(p) for p in settings.detection.critical_prefixes],
            "monitored_asns": list(settings.detection.monitored_asns),
            "heuristics": {
                "more_specific_min_delta": settings.detection.more_specific_min_delta,
                "long_path_zscore": settings.detection.long_path_zscore,
                "long_path_floor": settings.detection.long_path_floor,
                "prepend_floor": settings.detection.prepend_floor,
                "leak_confidence_floor": settings.detection.leak_confidence_floor,
                "visibility_loss_grace_s": settings.detection.visibility_loss_grace_s,
            },
        }

    @app.get("/api/scope/search")
    async def scope_search(
        q: str = Query(..., description="ASN (AS1234) or telecom/operator name", min_length=1),
        _: None = Depends(require_token),
    ) -> Dict[str, Any]:
        results = await scope_lookup.search(q, pipeline.rpki)
        return {
            "query": q,
            "count": len(results),
            "asns": [
                {
                    "asn": r.asn,
                    "name": r.name,
                    "country": r.country,
                    "prefixes": [
                        {"prefix": p.prefix, "origin_as": p.origin_as, "rpki_state": p.rpki_state}
                        for p in r.prefixes
                    ],
                }
                for r in results
            ],
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> str:
        try:
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
            return generate_latest().decode("utf-8")
        except Exception:  # noqa: BLE001
            return "# prometheus_client unavailable\n"

    @app.websocket("/ws/alerts")
    async def alerts_ws(ws: WebSocket) -> None:
        if settings.api.token:
            token = ws.query_params.get("token", "")
            if token != settings.api.token:
                await ws.close(code=4401)
                return
        await ws.accept()
        sub = pipeline.subscribe()
        try:
            backlog = pipeline.recent(limit=50)
            await ws.send_text(json.dumps({"type": "snapshot", "alerts": backlog}))
            while True:
                payload = await sub.get()
                await ws.send_text(json.dumps({"type": "alert", "alert": payload}))
        except WebSocketDisconnect:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("WebSocket closed: %s", exc)
        finally:
            pipeline.unsubscribe(sub)

    # Serve the built dashboard when present, so deployment is one service.
    mount_dashboard(app, Path(__file__).resolve().parent.parent / "web" / "dist")

    return app

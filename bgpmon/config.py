"""Typed configuration for the telecom-grade pipeline.

Secrets are NEVER stored in git: they come from environment variables, with the
legacy JSON files read only as a migration path.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    try:
        return int(raw) if raw is not None else default
    except ValueError:
        logger.warning("Invalid int for %s=%r, using %d", name, raw, default)
        return default


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    try:
        return float(raw) if raw is not None else default
    except ValueError:
        logger.warning("Invalid float for %s=%r, using %s", name, raw, default)
        return default


def _parse_prefixes(raw: List[str]) -> Tuple[ipaddress._BaseNetwork, ...]:
    out = []
    for item in raw:
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        try:
            out.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid prefix in config: %r", item)
    return tuple(out)


@dataclass(frozen=True)
class RPkiSettings:
    """Local validator first (Routinator), remote as a rate-limited fallback."""

    rtr_host: str = "127.0.0.1"
    rtr_port: int = 3323
    local_url: str = "http://127.0.0.1:8323"    # HTTP API, used for health/context only
    remote_url: str = "https://stat.ripe.net/data/rpki-validation/data.json"
    enable_remote_fallback: bool = True
    remote_min_interval_s: float = 2.0          # RIPEstat politeness / rate limiting
    timeout_s: float = 30.0                     # full VRP sync needs headroom
    resync_interval_s: int = 1800
    max_concurrency: int = 32

    @classmethod
    def from_env(cls) -> "RPkiSettings":
        return cls(
            rtr_host=_env("BGPMON_RPKI_RTR_HOST", cls.rtr_host) or cls.rtr_host,
            rtr_port=_env_int("BGPMON_RPKI_RTR_PORT", cls.rtr_port),
            local_url=_env("BGPMON_RPKI_LOCAL_URL", cls.local_url) or cls.local_url,
            remote_url=_env("BGPMON_RPKI_REMOTE_URL", cls.remote_url) or cls.remote_url,
            enable_remote_fallback=_env_bool("BGPMON_RPKI_REMOTE_FALLBACK", cls.enable_remote_fallback),
            timeout_s=_env_float("BGPMON_RPKI_TIMEOUT", cls.timeout_s),
            resync_interval_s=_env_int("BGPMON_RPKI_RESYNC", cls.resync_interval_s),
            max_concurrency=_env_int("BGPMON_RPKI_CONCURRENCY", cls.max_concurrency),
        )


@dataclass(frozen=True)
class SourceSettings:
    """RIS Live feed selection. Only RRCs are valid `host` values."""

    url: str = "wss://ris-live.ripe.net/v1/ws/"
    client_tag: str = "bgpmon-telecom"
    collectors: Tuple[str, ...] = ("rrc00", "rrc01", "rrc11", "rrc12", "rrc24")
    subscribe_types: Tuple[str, ...] = ("UPDATE",)
    include_raw: bool = True
    ack: bool = True
    queue_max: int = 200_000
    reconnect_base_s: float = 1.0
    reconnect_max_s: float = 60.0
    stale_after_s: float = 60.0

    @classmethod
    def from_env(cls) -> "SourceSettings":
        raw = _env("BGPMON_COLLECTORS")
        collectors = tuple(c.strip() for c in raw.split(",") if c.strip()) if raw else cls.collectors
        bad = [c for c in collectors if not c.startswith("rrc")]
        if bad:
            raise ValueError(f"RIS Live accepts only RRC collector ids; got {bad}")
        return cls(
            collectors=collectors,
            include_raw=_env_bool("BGPMON_INCLUDE_RAW", cls.include_raw),
            queue_max=_env_int("BGPMON_QUEUE_MAX", cls.queue_max),
        )


@dataclass(frozen=True)
class DetectionSettings:
    """Tuning for every heuristic. Owned space drives severity."""

    owned_prefixes: Tuple[ipaddress._BaseNetwork, ...] = ()
    monitored_asns: Tuple[int, ...] = ()
    critical_prefixes: Tuple[ipaddress._BaseNetwork, ...] = ()
    expected_origins: Dict[int, Tuple[int, ...]] = field(default_factory=dict)  # prefix_int -> asns

    # hijack
    more_specific_min_delta: int = 1
    sub_prefix_severity: Severity = None  # set in __post_init__ via default below
    trust_rpki_valid_origins: bool = True
    moas_confirm_updates: int = 3      # distinct sightings before promoting a new MOAS participant

    # leak
    leak_confidence_floor: float = 0.55
    long_path_zscore: float = 4.0
    long_path_floor: int = 15
    prepend_floor: int = 6

    # bogon
    enforce_bogon_asn: bool = True
    enforce_bogon_prefix: bool = True

    # visibility
    visibility_loss_grace_s: int = 900
    visibility_min_expected_collectors: int = 2

    # how long an incident signature suppresses a repeat of the same finding
    # before it is allowed to alert again
    incident_ttl_s: int = 3600

    @classmethod
    def from_env(cls) -> "DetectionSettings":
        sec = _read_json(CONFIG_DIR / "security_config.json") or {}
        raw_owned = _env("BGPMON_OWNED_PREFIXES")
        owned = _parse_prefixes(raw_owned.split(",") if raw_owned else sec.get("owned_prefixes", []))
        critical = _parse_prefixes(sec.get("critical_prefixes", []))
        monitored = tuple(int(a) for a in sec.get("monitored_asns", []) if str(a).strip().isdigit())
        expected = {}
        for prefix_str, asns in (sec.get("expected_origins") or {}).items():
            try:
                key = int(ipaddress.ip_network(prefix_str, strict=False).network_address)
            except ValueError:
                continue
            expected[key] = tuple(int(a) for a in asns)
        return cls(
            owned_prefixes=owned,
            critical_prefixes=critical,
            monitored_asns=monitored,
            expected_origins=expected,
            incident_ttl_s=_env_int("BGPMON_INCIDENT_TTL", cls.incident_ttl_s),
            visibility_loss_grace_s=_env_int("BGPMON_VISIBILITY_GRACE", cls.visibility_loss_grace_s),
        )


@dataclass(frozen=True)
class SinkSettings:
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    neo4j_enabled: bool = False
    batch_size: int = 500
    flush_interval_s: float = 2.0
    max_retries: int = 3
    csv_dir: Path = DATA_DIR / "security_alerts"
    syslog_enabled: bool = False
    syslog_host: str = "localhost"
    syslog_port: int = 514

    @classmethod
    def from_env(cls) -> "SinkSettings":
        password = _env("BGPMON_NEO4J_PASSWORD")
        user = _env("BGPMON_NEO4J_USER", "neo4j")
        uri = _env("BGPMON_NEO4J_URI", "bolt://localhost:7687")
        enabled = _env_bool("BGPMON_NEO4J_ENABLED", bool(password))
        if password is None:
            legacy = _read_json(CONFIG_DIR / "db_config.json") or {}
            password = legacy.get("password", "")
            uri = legacy.get("uri", uri)
            user = legacy.get("username", user)
            if password:
                logger.warning(
                    "Neo4j password read from config/db_config.json. Move it to BGPMON_NEO4J_PASSWORD; "
                    "that file must not be tracked in git."
                )
        return cls(
            neo4j_uri=uri,
            neo4j_user=user,
            neo4j_password=password or "",
            neo4j_enabled=enabled,
            batch_size=_env_int("BGPMON_NEO4J_BATCH", cls.batch_size),
            syslog_enabled=_env_bool("BGPMON_SYSLOG_ENABLED", cls.syslog_enabled),
            syslog_host=_env("BGPMON_SYSLOG_HOST", cls.syslog_host) or cls.syslog_host,
            syslog_port=_env_int("BGPMON_SYSLOG_PORT", cls.syslog_port),
        )


@dataclass(frozen=True)
class ApiSettings:
    host: str = "127.0.0.1"
    port: int = 8080
    ws_max_clients: int = 200
    ws_queue: int = 5000
    cors_origins: Tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")
    token: str = ""

    @classmethod
    def from_env(cls) -> "ApiSettings":
        return cls(
            host=_env("BGPMON_API_HOST", cls.host) or cls.host,
            port=_env_int("BGPMON_API_PORT", cls.port),
            token=_env("BGPMON_API_TOKEN", "") or "",
        )


@dataclass(frozen=True)
class Settings:
    rpki: RPkiSettings
    source: SourceSettings
    detection: DetectionSettings
    sink: SinkSettings
    api: ApiSettings
    relationship_file: Path = DATA_DIR / "as_relationships.txt.bz2"
    log_level: str = "INFO"

    @classmethod
    def load(cls) -> "Settings":
        return cls(
            rpki=RPkiSettings.from_env(),
            source=SourceSettings.from_env(),
            detection=DetectionSettings.from_env(),
            sink=SinkSettings.from_env(),
            api=ApiSettings.from_env(),
            relationship_file=Path(_env("BGPMON_AS_REL_FILE", str(DATA_DIR / "as_relationships.txt.bz2"))),
            log_level=_env("BGPMON_LOG_LEVEL", "INFO") or "INFO",
        )


def _read_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to read %s: %s", path, exc)
        return None


# DetectionSettings uses Severity in a default; import lazily to avoid a cycle.
from bgpmon.models import Severity  # noqa: E402

DetectionSettings.sub_prefix_severity = Severity.HIGH  # type: ignore[misc]

"""
Enhanced Security Analyzer for BGP Updates
Specifically tailored for UK Telecom Security Teams

This module provides advanced analysis of BGP updates to detect:
1. BGP hijacking attempts
2. Route leaks
3. Unusual AS path changes
4. Critical UK infrastructure impacts
"""

import logging
import ipaddress
import datetime
import re
from typing import Dict, List, Optional, Any, Tuple, Set
import json
import os
from pathlib import Path
import requests
from dataclasses import dataclass
from datetime import datetime, timedelta
import csv
from utils.bgp_utils import ( # Import AS relationship functions
    load_as_relationships,
    get_as_relationship,
    P2C, P2P, C2P, S2S, UNKNOWN
)
from utils.as_lookup import ASLookup # Added import
from utils.config_manager import config_manager # Import shared config manager
from utils.anomaly_detector import AnomalyDetector # Import ML detector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Path for security configuration
CONFIG_DIR = Path(__file__).parent.parent / "config"

# Load critical prefixes (generalized name)
CRITICAL_PREFIXES = set()
TRUSTED_TRANSIT_ASNS = set()
KNOWN_BAD_ACTORS = set()

# Create data directory for security config if it doesn't exist
CONFIG_DIR.mkdir(exist_ok=True)

# Removed DEFAULT_UK_TELECOM_ASNS block

# Try to load configuration, or create with defaults if not exists
def load_security_config():
    """Load security configuration or create with defaults if not exists."""
    global CRITICAL_PREFIXES, TRUSTED_TRANSIT_ASNS, KNOWN_BAD_ACTORS

    config_file = CONFIG_DIR / "security_config.json"

    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                config = json.load(f)

            # Use the new generic key name "critical_prefixes"
            CRITICAL_PREFIXES = set(config.get("critical_prefixes", config.get("uk_critical_prefixes", []))) # Read new key, fallback to old for compatibility
            TRUSTED_TRANSIT_ASNS = set(config.get("trusted_transit_asns", []))
            KNOWN_BAD_ACTORS = set(config.get("known_bad_actors", []))

            logger.info(f"Loaded security configuration: {len(CRITICAL_PREFIXES)} critical prefixes.")
        except Exception as e:
            logger.error(f"Error loading security config: {e}")
            # Initialize with defaults
            init_default_config()
    else:
        # Config doesn't exist, create default
        init_default_config()
        save_security_config()

def init_default_config():
    """Initialize security configuration with default values."""
    global CRITICAL_PREFIXES, TRUSTED_TRANSIT_ASNS, KNOWN_BAD_ACTORS

    # Default critical prefixes (examples) - Define prefixes whose announcements require extra scrutiny.
    CRITICAL_PREFIXES = {
        "195.166.0.0/16",  # Example Government
        "194.159.0.0/16",  # Example financial
        "146.227.0.0/16",  # Example academic
        "62.172.0.0/16",   # Example UK telecom
        "194.36.0.0/16",   # Example UK telecom
    }

    # Removed setting UK_TELECOM_ASNS

    # Default trusted transit providers - ASNs generally considered reliable for transit (used in potential future checks).
    TRUSTED_TRANSIT_ASNS = {
        174,    # Cogent
        3356,   # Level3
        1299,   # Telia
        2914,   # NTT
        6461,   # Zayo
        6939,   # Hurricane Electric
        3257,   # GTT
        1273,   # Vodafone International
        6453,   # TATA
        6762,   # Telecom Italia
    }

    # Known BGP bad actors - ASNs identified as sources of malicious BGP activity (requires external threat intel).
    KNOWN_BAD_ACTORS = {
        # These would typically come from threat intelligence feeds
        # Empty by default - to be populated based on your threat intel
    }

def save_security_config():
    """Save the current security configuration to disk."""
    config_file = CONFIG_DIR / "security_config.json"

    config = {
        "critical_prefixes": list(CRITICAL_PREFIXES), # Use the new generic key name
        "trusted_transit_asns": list(TRUSTED_TRANSIT_ASNS),
        "known_bad_actors": list(KNOWN_BAD_ACTORS),
    }

    try:
        with open(config_file, "w") as f:
            json.dump(config, f, indent=2)
        logger.info(f"Security configuration saved to {config_file}")
    except Exception as e:
        logger.error(f"Error saving security config: {e}")

# Initialize configuration
load_security_config()

# Load AS relationship data on startup
load_as_relationships()

# Initialize AS Lookup globally
as_lookup = ASLookup()

# Load app settings globally for security analysis parameters
APP_SETTINGS = config_manager.load_app_settings()
SECURITY_HEURISTICS_CONFIG = APP_SETTINGS.get("security_analysis", {}).get("heuristics", {})

def is_critical_prefix(prefix: str) -> bool:
    """Check if prefix overlaps with the configured critical prefixes list."""
    try:
        prefix_net = ipaddress.ip_network(prefix)

        # Check if this prefix is in our critical list
        for critical in CRITICAL_PREFIXES: # Use the renamed global variable
            critical_net = ipaddress.ip_network(critical)

            # If the prefix contains or is contained within a critical prefix
            if prefix_net.version == critical_net.version: # Ensure same IP version
                if prefix_net.subnet_of(critical_net) or critical_net.subnet_of(prefix_net):
                    return True

        return False
    except Exception:
        return False

def get_path_countries(as_path: str) -> Set[str]:
    """Get the set of unique countries associated with ASNs in the path."""
    countries = set()
    if not as_path:
        return countries

    try:
        asns = [asn for asn in as_path.split(",") if asn.isdigit()]
        # Use bulk lookup for potentially better performance if implemented well in ASLookup
        # For simplicity here, lookup one by one
        for asn_str in asns:
            info = as_lookup.get_as_info(asn_str) # Use the global instance
            if info and info.get('country'):
                countries.add(info['country'].upper()) # Add country code (uppercase)
    except Exception as e:
        logger.error(f"Error getting countries for path '{as_path}': {e}")

    return countries

def get_origin_as(as_path: str) -> Optional[int]:
    """Extract origin AS from AS path."""
    if not as_path:
        return None

    try:
        asns = as_path.split(",")
        # Origin is the last AS in the path
        return int(asns[-1]) if asns else None
    except:
        return None

def check_path_prepending(as_path: str) -> Tuple[bool, str]:
    """Check for excessive AS path prepending."""
    config = SECURITY_HEURISTICS_CONFIG.get("prepending", {"enabled": True, "threshold": 5})
    if not config.get("enabled", True) or not as_path:
        return False, ""

    try:
        asns = as_path.split(",")

        # Count consecutive repetitions
        current = None
        count = 0
        max_count = 0

        for asn in asns:
            if asn == current:
                count += 1
                max_count = max(max_count, count)
            else:
                current = asn
                count = 1

        # Check against configured threshold
        threshold = config.get("threshold", 5)
        if max_count > threshold:
            reason = f"Excessive prepending detected (>{threshold} times)"
            return True, reason
        return False, ""
    except:
        return False, ""

def check_unusual_transit(as_path: str) -> Tuple[bool, List[str]]:
    """Check for unusual transit arrangements."""
    if not as_path:
        return False, []

    try:
        asns = [int(asn) for asn in as_path.split(",")]
        unusual = []

        # Removed UK-specific transit checks
        # Consider adding a generalized check for untrusted transit if needed,
        # e.g., check if asns[i] not in TRUSTED_TRANSIT_ASNS and relationship is C2P.
        # For now, keeping it simple and removing UK specifics.

        # Check if known bad actor is in path
        for asn in asns:
            if asn in KNOWN_BAD_ACTORS:
                unusual.append(f"Known problematic AS in path: AS{asn}")

        return len(unusual) > 0, unusual
    except:
        return False, []

def check_possible_hijack(prefix: str, origin_as: Optional[int],
                          previous_origin_as: Optional[int],
                          app_settings: Dict = APP_SETTINGS) -> Tuple[bool, List[str]]: # Pass settings
    """Check if update suggests a possible prefix hijack."""
    if not prefix or not origin_as:
        return False, []

    reasons = []

    # Check if the origin AS has changed compared to the cached previous origin
    if previous_origin_as is not None and previous_origin_as != origin_as:
        # If this is a critical prefix, this is high severity
        if is_critical_prefix(prefix):
            reasons.append(f"CRITICAL: Origin change for critical prefix {prefix} " # Updated reason text
                           f"from AS{previous_origin_as} to AS{origin_as}")
        else:
            reasons.append(f"Origin change for prefix {prefix} "
                           f"from AS{previous_origin_as} to AS{origin_as}")

    # Check for more-specific announcements of critical prefixes
    try:
        prefix_net = ipaddress.ip_network(prefix)

        for critical in CRITICAL_PREFIXES: # Use the renamed global variable
            try:
                critical_net = ipaddress.ip_network(critical)
            except ValueError:
                logger.warning(f"Skipping invalid critical prefix format in config: {critical}")
                continue # Skip this critical prefix if format is wrong

            # --- Check IP Version Compatibility ---
            if prefix_net.version != critical_net.version:
                continue # Skip comparison if versions don't match
            # ------------------------------------

            # Check if this is a more specific announcement based on config
            more_specific_config = app_settings.get("security_analysis", {}).get("heuristics", {}).get("more_specific", {})
            if more_specific_config.get("enabled", True):
                length_diff_threshold = more_specific_config.get("prefix_length_diff", 4)
                # Compare only if versions match (already checked above)
                if (prefix_net.subnet_of(critical_net) and
                    prefix != critical and
                    prefix_net.prefixlen > critical_net.prefixlen + length_diff_threshold):

                    reasons.append(f"CRITICAL: Suspicious more-specific announcement "
                                   f"(>{critical_net.prefixlen + length_diff_threshold}) "
                                   f"of critical prefix: {prefix} (parent: {critical})")
    except Exception as e:
        logger.warning(f"Error during more-specific check for {prefix}: {e}")

    # Check if origin is a known problematic AS
    if origin_as in KNOWN_BAD_ACTORS:
        reasons.append(f"CRITICAL: Origin AS{origin_as} is a known problematic entity")

    return len(reasons) > 0, reasons

def check_route_leak(prefix: str, as_path: str, peer_asn: str,
                     app_settings: Dict = APP_SETTINGS) -> Tuple[bool, List[str]]: # Pass settings
    """
    Check for potential route leaks using valley-free path validation
    based on loaded AS relationship data.
    """
    if not as_path:
        return False, []

    reasons = []
    try:
        # Parse AS path into integers
        asns = [int(asn) for asn in as_path.split(",") if asn.isdigit()]
        if len(asns) < 2:
            return False, [] # Need at least two ASNs to check relationships

        in_valley = False # Flag to track if we've gone "down" (p2c or p2p)

        for i in range(len(asns) - 1):
            asn1 = asns[i]
            asn2 = asns[i+1]

            # Skip self-loops (prepending)
            if asn1 == asn2:
                continue

            relationship = get_as_relationship(asn1, asn2)

            if relationship == UNKNOWN:
                # Optional: Could flag paths with unknown relationships as suspicious
                # reasons.append(f"Unknown relationship between AS{asn1} and AS{asn2}")
                pass # For now, we ignore unknown relationships for leak detection

            elif relationship == P2C or relationship == S2S: # Provider -> Customer or Sibling -> Sibling
                in_valley = True # We are now in the "valley" or at the same level

            elif relationship == P2P: # Peer -> Peer
                 in_valley = True # Peers are at the same level

            elif relationship == C2P: # Customer -> Provider
                if in_valley:
                    # Violation: Going "up" (c2p) after being in the valley (p2c or p2p)
                    reasons.append(f"Potential route leak (valley violation): "
                                   f"AS{asn1} (customer) announced to AS{asn2} (provider) "
                                   f"after a p2c/p2p/s2s link.")
                    # Once a leak is detected, no need to check further down this path segment
                    break
            # else: UNKNOWN case handled above

        # --- Other existing checks ---

        # Check for long AS paths based on config
        long_path_config = app_settings.get("security_analysis", {}).get("heuristics", {}).get("long_path", {})
        if long_path_config.get("enabled", True):
            threshold = long_path_config.get("threshold", 30)
            if len(asns) > threshold:
                reasons.append(f"Suspiciously long AS path ({len(asns)} hops, threshold: {threshold})")

        # Check for paths containing private ASNs
        private_asns = []
        for asn in asns:
            # Standard private ASN ranges
            if (64512 <= asn <= 65534) or (4200000000 <= asn <= 4294967294):
                private_asns.append(asn)

        if private_asns:
            reasons.append(f"Path contains private ASNs: {private_asns}")

        return len(reasons) > 0, reasons

    except Exception as e:
        logger.error(f"Error during route leak check for path '{as_path}': {e}")
        return False, []

@dataclass
class RPKIValidationResult:
    """RPKI validation result for a BGP announcement."""
    state: str  # "VALID", "INVALID", "UNKNOWN"
    reason: Optional[str] = None
    roa_prefixes: List[Dict] = None

class RPKIValidator:
    """RPKI validation using RIPE Validator API."""

    def __init__(self):
        self.validator_url = "https://stat.ripe.net/data/rpki-validation/data.json"
        self.cache = {}  # Simple cache for validation results
        self.cache_duration = timedelta(hours=1)

    def validate(self, prefix: str, origin_as: int) -> RPKIValidationResult:
        """
        Validate a BGP announcement against RPKI data.

        Args:
            prefix: IP prefix in CIDR notation
            origin_as: ASN originating the prefix

        Returns:
            RPKIValidationResult with validation state and details
        """
        try:
            # Check cache first
            cache_key = f"{prefix}_{origin_as}"
            if cache_key in self.cache:
                result, timestamp = self.cache[cache_key]
                if datetime.now() - timestamp < self.cache_duration:
                    return result

            # Query RIPE validator
            params = {
                "prefix": prefix,
                "resource": str(origin_as)  # Use 'resource' and just the number
            }
            response = requests.get(self.validator_url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            # Parse validation result from RIPEstat API
            api_data = data.get("data", {}) # RIPEstat nests results under 'data'
            state_raw = api_data.get("status", "unknown").upper()
            reason = api_data.get("description")

            # Map RIPEstat status to our internal states
            if state_raw == "VALID":
                state = "VALID"
            elif state_raw in ["INVALID_ASN", "INVALID_LENGTH"]:
                state = "INVALID"
            else: # Includes "UNKNOWN" and any other unexpected values
                state = "UNKNOWN"

            result = RPKIValidationResult(
                state=state,
                reason=reason,
                roa_prefixes=None # This API doesn't provide ROA details in the same way
            )

            # Cache the result
            self.cache[cache_key] = (result, datetime.now())
            return result

        except Exception as e:
            logger.error(f"RPKI validation error: {e}")
            return RPKIValidationResult(state="UNKNOWN", reason=str(e))

# Initialize RPKI validator
rpki_validator = RPKIValidator()

# Initialize Anomaly Detector globally (consider lifecycle management later)
anomaly_detector = AnomalyDetector()

def check_rpki_validity(prefix: str, origin_as: Optional[int]) -> Tuple[bool, List[str]]:
    """
    Check if the route announcement is invalid according to RPKI.

    Args:
        prefix: IP prefix in CIDR notation
        origin_as: ASN originating the prefix

    Returns:
        Tuple of (is_invalid, list of reasons)
    """
    if not origin_as:
        return False, []

    result = rpki_validator.validate(prefix, origin_as)

    if result.state == "INVALID":
        # Clarify the "None" reason if present
        reason_text = result.reason if result.reason else "Reason unspecified by API"
        reasons = [f"RPKI Invalid: {reason_text}"]
        return True, reasons

    return False, []

class SecurityAlertLogger:
    """Handles logging of security alerts to both database and CSV."""

    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir) / "security_alerts"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.current_file = None
        self._init_csv()

    def _init_csv(self):
        """Initialize CSV file for current day."""
        current_date = datetime.now().strftime("%Y-%m-%d")
        self.current_file = self.data_dir / f"security_alerts_{current_date}.csv"

        # Create new file with headers if doesn't exist
        if not self.current_file.exists():
            with open(self.current_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([
                    'Timestamp', 'Severity', 'Prefix', 'AS Path',
                    'Peer ASN', 'Reasons', 'Critical Prefix' # Removed 'UK Telecom' header
                ])

    def log_alert(self, alert, db_manager=None):
        """Log alert using standard logging, and optionally to CSV/DB."""

        # --- Log using standard Python logging ---
        severity = alert.get('severity', 'UNKNOWN').upper()
        # Prepare structured data for logging
        log_extra = {
            'alert_prefix': alert.get('prefix', 'N/A'),
            'alert_as_path': alert.get('as_path', 'N/A'),
            'alert_peer_asn': alert.get('peer_asn', 'N/A'),
            'alert_reasons': '; '.join(alert.get('reasons', [])),
            'alert_critical': alert.get('is_critical_prefix', False),
            'alert_severity': severity,
            'alert_origin_as': alert.get('origin_as'), # Add origin
            'alert_previous_origin_as': alert.get('previous_origin_as') # Add previous origin
        }
        log_message = (
            f"SecurityAlert [{severity}]: Prefix={log_extra['alert_prefix']}, "
            f"ASPath={log_extra['alert_as_path']}, Peer={log_extra['alert_peer_asn']}, "
            f"Reasons='{log_extra['alert_reasons']}', Critical={log_extra['alert_critical']}"
        )

        if severity == "HIGH":
            logger.error(log_message, extra=log_extra) # Pass structured data
        elif severity == "MEDIUM":
            logger.warning(log_message, extra=log_extra) # Pass structured data
        else: # LOW or UNKNOWN
            logger.info(log_message, extra=log_extra) # Pass structured data
        # -----------------------------------------

        # --- Existing CSV logging (optional fallback/backup) ---
        try:
            self._log_to_csv(alert)
        except Exception as e:
            logger.error(f"Failed to log alert to CSV backup: {e}")
        # -------------------------------------------------------

        # --- Existing DB logging (optional) ---
        if db_manager:
            try:
                db_manager.store_security_alert(alert)
            except Exception as e:
                logger.error(f"Failed to log alert to database: {e}")
        # --------------------------------------

    def _log_to_csv(self, alert):
        """Log alert to CSV file."""
        # Check if we need to rotate to new day's file
        current_date = datetime.now().strftime("%Y-%m-%d")
        expected_file = self.data_dir / f"security_alerts_{current_date}.csv"

        if expected_file != self.current_file:
            self.current_file = expected_file
            self._init_csv()

        # Write alert to CSV
        with open(self.current_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                alert.get('timestamp', datetime.now()).isoformat(),
                alert.get('severity', 'LOW'),
                alert.get('prefix', 'N/A'),
                alert.get('as_path', 'N/A'),
                alert.get('peer_asn', 'N/A'),
                "; ".join(alert.get('reasons', [])),
                'Yes' if alert.get('is_critical_prefix', False) else 'No',
                # Removed UK Telecom field
            ])


def check_suspicious_patterns(timestamp, prefix, as_path, peer_asn, previous_origin_as, db_manager,
                              app_settings: Dict = APP_SETTINGS): # Pass settings
    """
    Check BGP update for various suspicious patterns.

    Args:
        timestamp: Timestamp of the update.
        prefix: Announced prefix.
        as_path: AS path string.
        peer_asn: ASN of the BGP peer.
        previous_origin_as: Previously seen origin AS for this prefix (from cache/state).
        db_manager: Instance of BGPDatabaseManager (optional).
        app_settings: Dictionary containing application settings (heuristics thresholds).

    Returns:
        Dictionary representing the alert if suspicious, otherwise None.
    """
    all_reasons = []
    alert_severity = "LOW" # Default severity
    is_critical = is_critical_prefix(prefix)

    # Load heuristic configs
    heuristics_config = app_settings.get("security_analysis", {}).get("heuristics", {})
    long_path_config = heuristics_config.get("long_path", {})
    prepending_config = heuristics_config.get("prepending", {})
    more_specific_config = heuristics_config.get("more_specific", {})

    # 1. Extract Origin AS
    origin_as = get_origin_as(as_path)
    if not origin_as:
        # Cannot perform origin-based checks without an origin AS
        # Might still perform other checks like RPKI if applicable based on prefix only?
        # For now, return if no origin found in path
         # logger.debug(f"No origin AS found in path: {as_path} for prefix {prefix}")
         return None # Or potentially log a low-severity path format issue

    # 2. Check for Hijacks (Origin Change, More Specifics, Bad Actors)
    # Pass app_settings to check_possible_hijack
    is_hijack, hijack_reasons = check_possible_hijack(prefix, origin_as, previous_origin_as, app_settings)
    if is_hijack:
        # Origin changes or bad actors are typically high severity
        # More-specific might be medium by default (configurable)
        current_severity = "HIGH"
        if any("more-specific" in r.lower() for r in hijack_reasons):
             current_severity = more_specific_config.get("severity", "MEDIUM") # Use configured severity
        alert_severity = max(alert_severity, current_severity, key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(s, 0))
        all_reasons.extend(hijack_reasons)

    # 3. Check for Route Leaks (Valley Free, Long Path, Private ASN)
    # Pass app_settings to check_route_leak
    is_leak, leak_reasons = check_route_leak(prefix, as_path, peer_asn, app_settings)
    if is_leak:
        # Leaks are often medium severity, long paths might be lower
        current_severity = "MEDIUM"
        if any("long AS path" in r.lower() for r in leak_reasons) and not any("valley violation" in r.lower() for r in leak_reasons):
             current_severity = long_path_config.get("severity", "LOW") # Use configured severity for long path
        alert_severity = max(alert_severity, current_severity, key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(s, 0))
        all_reasons.extend(leak_reasons)

    # 4. Check RPKI Validity
    is_rpki_invalid, rpki_reasons = check_rpki_validity(prefix, origin_as)
    if is_rpki_invalid:
        alert_severity = max(alert_severity, "HIGH", key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(s, 0)) # RPKI Invalid is always HIGH
        all_reasons.extend(rpki_reasons)

    # 5. Check Path Prepending
    is_prepending, prepending_reason = check_path_prepending(as_path)
    if is_prepending:
        alert_severity = max(alert_severity, prepending_config.get("severity", "LOW"), key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(s, 0))
        all_reasons.append(prepending_reason)

    # 6. Check Unusual Transit / Bad Actors in Path
    is_unusual_transit, transit_reasons = check_unusual_transit(as_path)
    if is_unusual_transit:
        # Bad actor in transit path is high severity
        alert_severity = max(alert_severity, "HIGH", key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(s, 0))
        all_reasons.extend(transit_reasons)

    # 7. Check for ML-based Anomalies
    ml_config = heuristics_config.get("ml_anomaly", {"enabled": True, "severity": "MEDIUM"})
    if ml_config.get("enabled", True):
        # Prepare data for feature extraction
        update_data_for_ml = {
            'timestamp': timestamp,
            'prefix': prefix,
            'as_path': as_path,
            # Add other relevant fields if needed by extract_features
        }
        features = anomaly_detector.extract_features(update_data_for_ml)
        if features is not None:
            prediction = anomaly_detector.predict(features)
            if prediction == -1: # -1 indicates anomaly
                ml_severity = ml_config.get("severity", "MEDIUM")
                alert_severity = max(alert_severity, ml_severity, key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(s, 0))
                all_reasons.append("ML Anomaly Detected (Isolation Forest)")
        else:
            logger.debug(f"Could not extract features for ML prediction for prefix {prefix}")


    # Combine reasons and determine overall severity (already done via max())

    if not all_reasons:
        return None # No suspicious patterns found

    # Create alert dictionary using the determined alert_severity
    alert = {
        'timestamp': timestamp, # Use the determined overall severity
        'prefix': prefix,
        'severity': alert_severity,
        'as_path': as_path,
        'peer_asn': peer_asn,
        'origin_as': origin_as, # Add origin AS to alert context
        'reasons': all_reasons, # Use the determined criticality
        'previous_origin_as': previous_origin_as, # Add previous origin for context
        'is_critical_prefix': is_critical
        # Removed UK Telecom field
    }
    return alert


def add_critical_prefix(prefix: str) -> bool:
    """Add a prefix to the critical list and save config."""
    try:
        # Validate prefix format
        ipaddress.ip_network(prefix)
        if prefix not in CRITICAL_PREFIXES: # Use the renamed global variable
            CRITICAL_PREFIXES.add(prefix) # Use the renamed global variable
            save_security_config()
            logger.info(f"Added critical prefix: {prefix}")
            return True
        else:
            logger.info(f"Prefix {prefix} already in critical list.")
            return False
    except ValueError:
        logger.error(f"Invalid prefix format: {prefix}")
        return False
    except Exception as e:
        logger.error(f"Error adding critical prefix {prefix}: {e}")
        return False


def add_bad_actor_asn(asn: int) -> bool:
    """Add an ASN to the known bad actors list and save config."""
    try:
        if not isinstance(asn, int) or asn <= 0:
             raise ValueError("Invalid ASN")
        if asn not in KNOWN_BAD_ACTORS:
            KNOWN_BAD_ACTORS.add(asn)
            save_security_config()
            logger.info(f"Added known bad actor ASN: {asn}")
            return True
        else:
            logger.info(f"ASN {asn} already in known bad actors list.")
            return False
    except ValueError:
        logger.error(f"Invalid ASN format: {asn}")
        return False
    except Exception as e:
        logger.error(f"Error adding bad actor ASN {asn}: {e}")
        return False

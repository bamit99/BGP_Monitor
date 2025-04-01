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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Path for security configuration
CONFIG_DIR = Path(__file__).parent.parent / "config"

# Load UK critical prefixes
UK_CRITICAL_PREFIXES = set()
UK_TELECOM_ASNS = set()
TRUSTED_TRANSIT_ASNS = set()
KNOWN_BAD_ACTORS = set()

# Create data directory for security config if it doesn't exist
CONFIG_DIR.mkdir(exist_ok=True)

# Default UK Telecom ASNs - Major UK providers
DEFAULT_UK_TELECOM_ASNS = {
    2856,    # British Telecom
    5089,    # Virgin Media
    5607,    # Sky Broadband
    12576,   # Vodafone UK
    13285,   # TalkTalk
    15412,   # Vodafone Group
    5378,    # Vodafone Enterprise
    3292,    # TDC/Three
    6871,    # Plusnet
    35228,   # O2 UK
    34173,   # NATS (Air Traffic Control)
}

# Try to load configuration, or create with defaults if not exists
def load_security_config():
    """Load security configuration or create with defaults if not exists."""
    global UK_CRITICAL_PREFIXES, UK_TELECOM_ASNS, TRUSTED_TRANSIT_ASNS, KNOWN_BAD_ACTORS
    
    config_file = CONFIG_DIR / "security_config.json"
    
    if config_file.exists():
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                
            UK_CRITICAL_PREFIXES = set(config.get("uk_critical_prefixes", []))
            UK_TELECOM_ASNS = set(config.get("uk_telecom_asns", []))
            TRUSTED_TRANSIT_ASNS = set(config.get("trusted_transit_asns", []))
            KNOWN_BAD_ACTORS = set(config.get("known_bad_actors", []))
            
            logger.info(f"Loaded security configuration: {len(UK_CRITICAL_PREFIXES)} critical prefixes, "
                       f"{len(UK_TELECOM_ASNS)} telecom ASNs")
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
    global UK_CRITICAL_PREFIXES, UK_TELECOM_ASNS, TRUSTED_TRANSIT_ASNS, KNOWN_BAD_ACTORS
    
    # Default critical prefixes (examples)
    UK_CRITICAL_PREFIXES = {
        "195.166.0.0/16",  # Example UK Government
        "194.159.0.0/16",  # Example UK financial
        "146.227.0.0/16",  # Example UK academic
        "62.172.0.0/16",   # Example UK telecom
        "194.36.0.0/16",   # Example UK telecom
    }
    
    # Default UK Telecom ASNs
    UK_TELECOM_ASNS = DEFAULT_UK_TELECOM_ASNS
    
    # Default trusted transit providers
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
    
    # Known BGP bad actors
    KNOWN_BAD_ACTORS = {
        # These would typically come from threat intelligence feeds
        # Empty by default - to be populated based on your threat intel
    }

def save_security_config():
    """Save the current security configuration to disk."""
    config_file = CONFIG_DIR / "security_config.json"
    
    config = {
        "uk_critical_prefixes": list(UK_CRITICAL_PREFIXES),
        "uk_telecom_asns": list(UK_TELECOM_ASNS),
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

def is_critical_prefix(prefix: str) -> bool:
    """Check if prefix is critical for UK infrastructure."""
    try:
        prefix_net = ipaddress.ip_network(prefix)
        
        # Check if this prefix is in our critical list
        for critical in UK_CRITICAL_PREFIXES:
            critical_net = ipaddress.ip_network(critical)
            
            # If the prefix contains or is contained within a critical prefix
            if prefix_net.subnet_of(critical_net) or critical_net.subnet_of(prefix_net):
                return True
                
        return False
    except Exception:
        return False

def involves_uk_asn(as_path: str) -> bool:
    """Check if AS path involves UK telecom ASNs."""
    if not as_path:
        return False
    
    try:
        asns = [int(asn) for asn in as_path.split(",")]
        return any(asn in UK_TELECOM_ASNS for asn in asns)
    except:
        return False

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

def check_path_prepending(as_path: str) -> bool:
    """Check for excessive AS path prepending."""
    if not as_path:
        return False
    
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
                
        # More than 3 prepends is suspicious
        return max_count > 3
    except:
        return False

def check_unusual_transit(as_path: str) -> Tuple[bool, List[str]]:
    """Check for unusual transit arrangements."""
    if not as_path:
        return False, []
    
    try:
        asns = [int(asn) for asn in as_path.split(",")]
        unusual = []
        
        # Check if UK telecom AS appears in transit position for another UK AS
        for i in range(len(asns) - 1):
            # If a UK telecom AS is providing transit for another UK telecom AS
            # that could be unusual depending on the providers
            # Skip if it's the same ASN (prepending)
            if asns[i] in UK_TELECOM_ASNS and asns[i+1] in UK_TELECOM_ASNS and asns[i] != asns[i+1]:
                unusual.append(f"Unusual UK transit: AS{asns[i]} -> AS{asns[i+1]}")
                
        # Check if a non-trusted AS is providing transit for a UK telecom AS
        for i in range(len(asns) - 1):
            if (asns[i] not in TRUSTED_TRANSIT_ASNS and 
                asns[i] not in UK_TELECOM_ASNS and
                asns[i+1] in UK_TELECOM_ASNS):
                unusual.append(f"Untrusted transit for UK telecom: AS{asns[i]} -> AS{asns[i+1]}")
                
        # Check if known bad actor is in path
        for asn in asns:
            if asn in KNOWN_BAD_ACTORS:
                unusual.append(f"Known problematic AS in path: AS{asn}")
                
        return len(unusual) > 0, unusual
    except:
        return False, []

def check_possible_hijack(prefix: str, origin_as: Optional[int], 
                         prefix_history: Dict) -> Tuple[bool, List[str]]:
    """Check if update suggests a possible prefix hijack."""
    if not prefix or not origin_as:
        return False, []
    
    reasons = []
    
    # Check prefix history for origin changes
    if prefix in prefix_history and len(prefix_history[prefix]) > 0:
        # Get the most recent update for comparison
        prev_update = prefix_history[prefix][-1]
        prev_origin = None
        
        if prev_update.get('as_path'):
            prev_origin = get_origin_as(prev_update['as_path'])
        
        # If current origin is different from previous origin, flag it
        if prev_origin and prev_origin != origin_as:
            # If this is a UK critical prefix, this is high severity
            if is_critical_prefix(prefix):
                reasons.append(f"CRITICAL: Origin change for UK critical prefix {prefix} "
                              f"from AS{prev_origin} to AS{origin_as}")
            else:
                reasons.append(f"Origin change for prefix {prefix} "
                              f"from AS{prev_origin} to AS{origin_as}")
    
    # Check for more-specific announcements of critical prefixes
    try:
        prefix_net = ipaddress.ip_network(prefix)
        
        for critical in UK_CRITICAL_PREFIXES:
            critical_net = ipaddress.ip_network(critical)
            
            # If this is a more specific of a critical prefix with different origin
            if (prefix_net.subnet_of(critical_net) and 
                prefix != critical and 
                prefix_net.prefixlen > critical_net.prefixlen + 3):  # Much more specific
                
                reasons.append(f"CRITICAL: Suspicious more-specific announcement of UK prefix: "
                              f"{prefix} (parent: {critical})")
    except:
        pass
    
    # Check if origin is a known problematic AS
    if origin_as in KNOWN_BAD_ACTORS:
        reasons.append(f"CRITICAL: Origin AS{origin_as} is a known problematic entity")
    
    return len(reasons) > 0, reasons

def check_route_leak(prefix: str, as_path: str, peer_asn: str) -> Tuple[bool, List[str]]:
    """Check for potential route leaks."""
    if not as_path:
        return False, []
    
    reasons = []
    
    try:
        # Parse AS path
        asns = [int(asn) for asn in as_path.split(",")]
        
        # Check for valley-free routing violations (potential route leaks)
        # This is a simplified check - in production you'd use a more sophisticated algorithm
        # and reference a database of AS relationships
        
        # Simple check: If a tier-1 provider appears after a non-tier-1
        # This may indicate improper route propagation
        tier1_asns = {174, 1299, 2914, 3257, 3356, 3491, 5511, 6453, 6461, 6762, 7018}
        
        for i in range(len(asns) - 1):
            if asns[i] not in tier1_asns and asns[i+1] in tier1_asns:
                reasons.append(f"Potential route leak: non-tier1 AS{asns[i]} announces to tier1 AS{asns[i+1]}")
                
        # Check for long AS paths which could indicate a leak
        if len(asns) > 15:  # Unusually long AS path
            reasons.append(f"Suspiciously long AS path ({len(asns)} hops)")
        
        # Check for paths containing private ASNs
        private_asns = []
        for asn in asns:
            if (asn >= 64512 and asn <= 65534) or (asn >= 4200000000 and asn <= 4294967294):
                private_asns.append(asn)
                
        if private_asns:
            reasons.append(f"Path contains private ASNs: {private_asns}")
        
        return len(reasons) > 0, reasons
    except:
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
        self.validator_url = "https://rpki-validator.ripe.net/api/v1/validity"
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
                "asn": f"AS{origin_as}"
            }
            response = requests.get(self.validator_url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()
            
            # Parse validation result
            validity = data.get("validity", {})
            state = validity.get("state", "UNKNOWN")
            reason = validity.get("description")
            roas = data.get("validating_roas", [])
            
            result = RPKIValidationResult(
                state=state,
                reason=reason,
                roa_prefixes=roas
            )
            
            # Cache the result
            self.cache[cache_key] = (result, datetime.now())
            return result
            
        except Exception as e:
            logger.error(f"RPKI validation error: {e}")
            return RPKIValidationResult(state="UNKNOWN", reason=str(e))

# Initialize RPKI validator
rpki_validator = RPKIValidator()

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
        reasons = [f"RPKI Invalid: {result.reason}"]
        if result.roa_prefixes:
            reasons.append("Valid ROAs found:")
            for roa in result.roa_prefixes:
                reasons.append(f"  - ASN: {roa.get('asn')}, Prefix: {roa.get('prefix')}")
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
                    'Peer ASN', 'Reasons', 'Critical Prefix', 'UK Telecom'
                ])
    
    def log_alert(self, alert, db_manager=None):
        """Log alert to both CSV and database if available."""
        # Always log to CSV first as fallback
        try:
            self._log_to_csv(alert)
        except Exception as e:
            logging.error(f"Failed to log alert to CSV: {e}")
        
        # Try to log to database if available
        if db_manager:
            try:
                db_manager.store_security_alert(alert)
            except Exception as e:
                logging.error(f"Failed to log alert to database: {e}")
    
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
                alert['timestamp'].isoformat() if isinstance(alert['timestamp'], datetime) else alert['timestamp'],
                alert['severity'],
                alert['prefix'],
                alert['as_path'],
                alert['peer_asn'],
                ';'.join(alert['reasons']),
                'Yes' if alert['is_critical_prefix'] else 'No',
                'Yes' if alert['involves_uk_telecom'] else 'No'
            ])

def check_suspicious_patterns(timestamp, prefix, as_path, peer_asn, prefix_history, db_manager):
    """
    Enhanced check for suspicious patterns in BGP updates.
    
    Parameters:
    - timestamp: When the update was received
    - prefix: IP prefix 
    - as_path: AS path as comma-separated string
    - peer_asn: ASN of the BGP peer
    - prefix_history: History of previous updates
    - db_manager: Neo4j database manager instance
    
    Returns:
    - None if no issues detected
    - Dict with alert details if suspicious
    """
    if not prefix:
        return None
        
    suspicious = False
    reasons = []
    severity = "LOW"
    
    # Extract origin AS from path
    origin_as = get_origin_as(as_path)
    
    # 1. Check if this is a critical UK prefix
    is_critical = is_critical_prefix(prefix)
    involves_uk = involves_uk_asn(as_path)
    
    # Set initial severity based on prefix criticality
    if is_critical:
        severity = "HIGH"
    elif involves_uk:
        severity = "MEDIUM"
    
    # 2. Check for AS path prepending
    if check_path_prepending(as_path):
        reasons.append(f"Excessive AS path prepending detected")
    
    # 3. Check for unusual transit relationships
    unusual_transit, transit_reasons = check_unusual_transit(as_path)
    if unusual_transit:
        reasons.extend(transit_reasons)
        if severity == "LOW":
            severity = "MEDIUM"
    
    # 4. Check for potential hijacking
    possible_hijack, hijack_reasons = check_possible_hijack(
        prefix, origin_as, prefix_history
    )
    if possible_hijack:
        reasons.extend(hijack_reasons)
        severity = "HIGH"  # Upgrade to high severity
    
    # 5. Check for route leaks
    route_leak, leak_reasons = check_route_leak(prefix, as_path, peer_asn)
    if route_leak:
        reasons.extend(leak_reasons)
        if severity == "LOW":
            severity = "MEDIUM"
    
    # 6. Check for RPKI validity
    rpki_invalid, rpki_reasons = check_rpki_validity(prefix, origin_as)
    if rpki_invalid:
        reasons.extend(rpki_reasons)
        severity = "HIGH"  # Invalid RPKI is serious
    
    # If any suspicious patterns were detected
    if reasons:
        suspicious = True
        
        # Create alert record and store in database
        alert = {
            'timestamp': timestamp,
            'prefix': prefix,
            'as_path': as_path,
            'origin_as': origin_as,
            'peer_asn': peer_asn,
            'reasons': reasons,
            'severity': severity,
            'is_critical_prefix': is_critical,
            'involves_uk_telecom': involves_uk
        }
        
        # Log the alert
        logger.warning(f"BGP Security Alert ({severity}):")
        logger.warning(f"  Prefix: {prefix}")
        logger.warning(f"  AS Path: {as_path}")
        for reason in reasons:
            logger.warning(f"  - {reason}")
        
        # Mark update as suspicious in database
        if db_manager:
            update_id = f"{timestamp.isoformat()}_{prefix}"
            db_manager.mark_suspicious_update(update_id, reasons)
        
        return alert
    
    return None

# Function to add a critical UK prefix to monitoring
def add_critical_prefix(prefix: str) -> bool:
    """Add a critical prefix to monitoring."""
    global UK_CRITICAL_PREFIXES
    
    try:
        # Validate it's a proper prefix
        ipaddress.ip_network(prefix)
        UK_CRITICAL_PREFIXES.add(prefix)
        save_security_config()
        return True
    except Exception as e:
        logger.error(f"Invalid prefix format: {e}")
        return False

# Function to add a UK telecom ASN to monitoring
def add_uk_telecom_asn(asn: int) -> bool:
    """Add a UK telecom ASN to monitoring."""
    global UK_TELECOM_ASNS
    
    try:
        UK_TELECOM_ASNS.add(int(asn))
        save_security_config()
        return True
    except Exception as e:
        logger.error(f"Invalid ASN format: {e}")
        return False

# Function to add a known bad actor ASN
def add_bad_actor_asn(asn: int) -> bool:
    """Add a known problematic ASN to monitoring."""
    global KNOWN_BAD_ACTORS
    
    try:
        KNOWN_BAD_ACTORS.add(int(asn))
        save_security_config()
        return True
    except Exception as e:
        logger.error(f"Invalid ASN format: {e}")
        return False
"""Utility functions for BGP data processing."""
import re
import logging
from datetime import datetime
from pathlib import Path
import bz2 # For handling .bz2 compressed files from CAIDA

def validate_as_number(as_number):
    """Validate AS number format."""
    try:
        as_num = int(as_number)
        return 1 <= as_num <= 4294967295
    except ValueError:
        return False

def parse_as_path(as_path):
    """Parse AS path string into list of AS numbers."""
    if not as_path:
        return []
    return [int(asn) for asn in as_path.split(',') if asn.isdigit()]

def format_timestamp(timestamp):
    """Format timestamp for display."""
    try:
        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(timestamp)

def validate_prefix(prefix):
    """Validate IP prefix format."""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    ipv6_pattern = r'^([0-9a-fA-F:]+:+)+[0-9a-fA-F]+/\d{1,3}$'
    return bool(re.match(ipv4_pattern, prefix) or re.match(ipv6_pattern, prefix))

def format_communities(communities):
    """Format BGP communities for display."""
    if not communities:
        return ""
    if isinstance(communities, str):
        communities = eval(communities)
    return ', '.join(f"{c[0]}:{c[1]}" if isinstance(c, (list, tuple)) else str(c) 
                    for c in communities)

# --- AS Relationship Data Handling ---

# Global dictionary to store relationships: {(asn1, asn2): relationship_code}
# Relationship codes (based on CAIDA format):
#  -1: Provider-to-Customer (p2c) (asn1 is provider, asn2 is customer)
#   0: Peer-to-Peer (p2p)
#   1: Customer-to-Provider (c2p) (asn1 is customer, asn2 is provider) - derived from p2c
#   2: Sibling-to-Sibling (s2s) - Often treated like p2p for valley-free
AS_RELATIONSHIPS = {}
P2C = -1
P2P = 0
C2P = 1
S2S = 2
UNKNOWN = 99

# Placeholder for the path to the relationship file
# This should ideally be configurable
DEFAULT_AS_REL_FILE_PATH = Path(__file__).parent.parent / "data" / "as_relationships.txt.bz2"

def load_as_relationships(filepath=DEFAULT_AS_REL_FILE_PATH):
    """
    Load AS relationship data from a CAIDA formatted file (e.g., YYYYMMDD.as-rel.txt.bz2).
    Format expected: asn1|asn2|relationship_code (# comments allowed)
    """
    global AS_RELATIONSHIPS
    AS_RELATIONSHIPS = {} # Clear previous data
    logging.info(f"Attempting to load AS relationships from: {filepath}")

    if not filepath.exists():
        logging.warning(f"AS relationship file not found: {filepath}. Route leak detection will be basic.")
        # Add a dummy entry for testing framework
        # AS_RELATIONSHIPS[(174, 3356)] = P2P # Example: Cogent peer Level3
        # AS_RELATIONSHIPS[(3356, 12345)] = P2C # Example: Level3 provider to Customer 12345
        return False

    try:
        open_func = bz2.open if str(filepath).endswith(".bz2") else open
        with open_func(filepath, "rt", encoding="utf-8") as f:
            for line in f:
                # Skip comment lines
                if line.startswith('#'):
                    continue

                parts = line.strip().split('|')
                if len(parts) == 3:
                    try:
                        asn1 = int(parts[0])
                        asn2 = int(parts[1])
                        rel_code = int(parts[2])

                        # Store the relationship (p2c or p2p)
                        # We derive c2p during lookup if needed
                        if rel_code == P2C or rel_code == P2P or rel_code == S2S:
                             # Ensure lower ASN is first for consistent key lookup? Maybe not necessary.
                             # key = tuple(sorted((asn1, asn2))) # Alternative key style
                             key = (asn1, asn2)
                             AS_RELATIONSHIPS[key] = rel_code

                    except ValueError:
                        logging.warning(f"Skipping invalid line in AS relationship file: {line.strip()}")
                        continue
        logging.info(f"Successfully loaded {len(AS_RELATIONSHIPS)} AS relationships.")
        return True
    except Exception as e:
        logging.error(f"Error loading AS relationship file {filepath}: {e}")
        AS_RELATIONSHIPS = {} # Ensure it's empty on error
        return False

def get_as_relationship(asn1: int, asn2: int) -> int:
    """
    Get the relationship between two ASNs.
    Returns P2C, P2P, C2P, S2S, or UNKNOWN.
    """
    if not AS_RELATIONSHIPS:
        # logging.debug("AS relationship data not loaded.") # Too noisy
        return UNKNOWN

    # Check direct relationship (asn1 -> asn2)
    rel = AS_RELATIONSHIPS.get((asn1, asn2))
    if rel is not None:
        return rel

    # Check reverse relationship (asn2 -> asn1)
    reverse_rel = AS_RELATIONSHIPS.get((asn2, asn1))
    if reverse_rel is not None:
        # Invert the relationship code if found in reverse
        if reverse_rel == P2C:
            return C2P # If asn2 is provider to asn1, then asn1 is customer of asn2
        elif reverse_rel == P2P:
            return P2P
        elif reverse_rel == S2S:
             return S2S
        # C2P shouldn't be stored directly based on CAIDA format, but handle defensively
        elif reverse_rel == C2P:
             return P2C

    # logging.debug(f"No relationship found between AS{asn1} and AS{asn2}")
    return UNKNOWN

# --- End AS Relationship Data Handling ---

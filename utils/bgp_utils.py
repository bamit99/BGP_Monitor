"""Utility functions for BGP data processing."""
import re
from datetime import datetime

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

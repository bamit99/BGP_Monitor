import logging
from ipaddress import ip_network

# Known legitimate ASNs and their prefixes
LEGITIMATE_PREFIXES = {
    # Format: 'ASN': ['prefix1', 'prefix2']
    '15169': ['8.8.8.0/24', '8.8.4.0/24'],  # Google DNS
    '32934': ['157.240.0.0/16'],  # Facebook
    '16509': ['52.0.0.0/11'],     # Amazon AWS
}

# Major transit providers
MAJOR_TRANSIT_ASES = {
    '174',   # Cogent
    '3356',  # Level3
    '1299',  # Telia
    '2914',  # NTT
    '3257',  # GTT
    '6461',  # Zayo
    '6762',  # Telecom Italia
    '7018'   # AT&T
}

def check_suspicious_patterns(timestamp, prefix, as_path, peer_asn, prefix_history, db_manager):
    """Check for potentially suspicious routing patterns and store alerts if found.

    Parameters:
        timestamp: datetime of the update
        prefix: BGP prefix being updated
        as_path: string representation of the AS path (e.g., '123,456,789')
        peer_asn: peer AS number
        prefix_history: dictionary containing update history for prefixes
        db_manager: instance of the database manager to store suspicious updates

    Returns:
        dict: alert dictionary if suspicious patterns are detected, otherwise None
    """
    try:
        path_ases = as_path.split(',')
        origin_asn = path_ases[-1] if path_ases else None
        
        # Initialize tracking
        suspicious = False
        reasons = []

        # 1. Check for BGP hijacking attempts
        try:
            prefix_ip = ip_network(prefix)
            for asn, legitimate_prefixes in LEGITIMATE_PREFIXES.items():
                for legit_prefix in legitimate_prefixes:
                    legit_network = ip_network(legit_prefix)
                    # Check if the announced prefix overlaps with known legitimate prefixes
                    if prefix_ip.overlaps(legit_network) and origin_asn != asn:
                        suspicious = True
                        reasons.append(f"Potential hijacking: AS{origin_asn} announcing prefix {prefix} " +
                                     f"which overlaps with AS{asn}'s legitimate prefix {legit_prefix}")
        except ValueError as e:
            logging.error(f"Error parsing prefix {prefix}: {e}")

        # 2. Check for path manipulation
        if len(path_ases) >= 2:
            for i in range(len(path_ases) - 1):
                if path_ases[i] == path_ases[i + 1]:
                    suspicious = True
                    reasons.append(f"AS path contains consecutive duplicate AS{path_ases[i]}")

        # 3. Check for unusual transit provider positions
        if len(path_ases) >= 3:  # Only check if path has at least 3 ASes
            for i, asn in enumerate(path_ases[1:-1], 1):  # Skip first and last AS
                if asn in MAJOR_TRANSIT_ASES and i > len(path_ases) - 3:
                    suspicious = True
                    reasons.append(f"Major transit AS{asn} in unusual position (near origin)")

        # 4. Check for multiple AS path changes in short time (5 minutes)
        recent_changes = len([
            c for c in prefix_history.get(prefix, [])
            if (timestamp - c['timestamp']).total_seconds() < 300
        ])

        if recent_changes > 5:
            suspicious = True
            reasons.append(f"Frequent changes ({recent_changes} in 5 minutes)")

        # 5. Check for unusually long AS path
        if len(path_ases) > 15:
            suspicious = True
            reasons.append(f"Unusually long AS path ({len(path_ases)} hops)")

        # 6. Check for origin AS changes
        if prefix in prefix_history and prefix_history[prefix]:
            last_origin = prefix_history[prefix][-1].get('as_path', '').split(',')[-1]
            if last_origin and last_origin != origin_asn:
                suspicious = True
                reasons.append(f"Origin AS change from AS{last_origin} to AS{origin_asn}")

        if suspicious:
            # Store suspicious update in Neo4j
            db_manager.store_suspicious_update(timestamp, prefix, as_path, reasons)

            alert = {
                'timestamp': timestamp,
                'prefix': prefix,
                'as_path': as_path,
                'reasons': reasons
            }
            logging.warning(f"Suspicious Update: {alert}")
            print("\n🚨 Suspicious Update Detected:")
            print(f"Prefix: {prefix}")
            print(f"AS Path: {as_path}")
            for reason in reasons:
                print(f"Reason: {reason}")
            return alert

        return None

    except Exception as e:
        logging.error(f"Error in check_suspicious_patterns: {e}")
        return None

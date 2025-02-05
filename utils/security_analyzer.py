import logging

def check_suspicious_patterns(timestamp, prefix, as_path, peer_asn, prefix_history, db_manager):
    """Check for potentially suspicious routing patterns and store alerts if found.

    Parameters:
        timestamp: datetime of the update
        prefix: BGP prefix being updated
        as_path: string representation of the AS path (e.g., '123,456,789')
        peer_asn: peer AS number (not used in current analysis)
        prefix_history: dictionary containing update history for prefixes
        db_manager: instance of the database manager to store suspicious updates

    Returns:
        dict: alert dictionary if suspicious patterns are detected, otherwise None
    """
    try:
        # 1. Check for multiple AS path changes in a short time (e.g., 5 minutes)
        recent_changes = len([
            c for c in prefix_history.get(prefix, [])
            if (timestamp - c['timestamp']).total_seconds() < 300
        ])

        # 2. Check for unusually long AS path
        path_length = len(as_path.split(','))

        suspicious = False
        reasons = []

        if recent_changes > 5:
            suspicious = True
            reasons.append(f"Frequent changes ({recent_changes} in 5 minutes)")

        if path_length > 15:
            suspicious = True
            reasons.append(f"Unusually long AS path ({path_length} hops)")

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

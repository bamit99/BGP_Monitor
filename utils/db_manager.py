from neo4j import GraphDatabase
from neo4j.exceptions import ClientError
import logging
import json # Import the json module
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Set

class BGPDatabaseManager:
    """Manages Neo4j database operations for BGP update data."""

    def __init__(self, uri, username, password):
        """Initialize the database manager with connection details."""
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        try:
            # Test connection
            with self.driver.session() as session:
                result = session.run("RETURN 1 as test")
                result.single()
            logging.info("Successfully connected to Neo4j database")

            # Initialize database schema
            self._init_schema()

        except Exception as e:
            logging.error(f"Failed to connect to Neo4j: {e}")
            raise

    def _cleanup_duplicates_tx(self, session):
        """Transaction function to clean up duplicate SecurityAlert nodes."""
        # Find duplicate alert_ids and keep only the node with the minimum internal ID for each
        # Note: Using deprecated id() function, replace if possible in future Neo4j versions
        cleanup_query = """
        MATCH (a:SecurityAlert)
        WITH a.alert_id AS alertId, collect(elementId(a)) AS nodeIds, count(a) AS cnt
        WHERE cnt > 1
        WITH alertId, nodeIds, min(nodeIds) as minId
        UNWIND nodeIds AS nodeId
        MATCH (n) WHERE elementId(n) = nodeId AND elementId(n) <> minId
        DETACH DELETE n
        """
        result = session.run(cleanup_query)
        summary = result.consume()
        if summary.counters.nodes_deleted > 0:
             logging.info(f"Cleaned up {summary.counters.nodes_deleted} duplicate SecurityAlert nodes.")
        else:
             logging.info("No duplicate SecurityAlert nodes found to clean up.")


    def _create_schema_tx(self, session):
        """Transaction function to create schema elements (constraints and indexes)."""
        # Ensure clean state for alert_id uniqueness: drop constraint by name and any index on the property
        session.run("DROP CONSTRAINT security_alert_id_unique IF EXISTS") # Drop by specific name
        session.run("DROP INDEX security_alert_id IF EXISTS") # Drop index by specific name

        # Now, create the unique constraint for alert_id (implicitly creates an index)
        # Use IF NOT EXISTS for idempotency, even after attempting drops
        session.run("CREATE CONSTRAINT security_alert_id_unique IF NOT EXISTS FOR (a:SecurityAlert) REQUIRE a.alert_id IS UNIQUE")

        # Create indexes for non-unique properties used in lookups
        session.run("""
            CREATE INDEX security_alert_timestamp IF NOT EXISTS
            FOR (a:SecurityAlert)
            ON (a.timestamp)
        """)
        session.run("""
            CREATE INDEX security_alert_severity IF NOT EXISTS
            FOR (a:SecurityAlert)
            ON (a.severity)
        """)

    def _drop_schema_tx(self, session):
        """Transaction function to drop potentially conflicting schema elements."""
        # Drop constraint by name and any index on the property
        session.run("DROP CONSTRAINT security_alert_id_unique IF EXISTS")
        session.run("DROP INDEX security_alert_id IF EXISTS")
        # Also drop the other indexes in case they need recreation (optional but safer)
        session.run("DROP INDEX security_alert_timestamp IF EXISTS")
        session.run("DROP INDEX security_alert_severity IF EXISTS")


    def _init_schema(self):
        """Initialize database schema using separate transactions for cleanup, drop, and create."""
        try:
            with self.driver.session() as session:
                # 1. Run cleanup in its own transaction first
                self._cleanup_duplicates_tx(session)
                # 2. Run drop operations in a separate transaction
                self._drop_schema_tx(session)
                # 3. Run create operations in a final transaction
                self._create_schema_tx(session)

            logging.info("Successfully initialized database schema")
        except ClientError as e:
            # Check if it's the specific "IndexAlreadyExists" or "ConstraintAlreadyExists" error
            # during the CREATE phase (should be less likely now but handle defensively)
            if "already exists" in str(e).lower():
                logging.warning(f"Schema initialization: Index/Constraint already exists ({e.code}), likely created concurrently or schema unchanged.")
            else:
                # Log other ClientErrors as errors
                logging.error(f"Error initializing database schema (ClientError): {e}")
        except Exception as e:
            # Log other unexpected exceptions as errors
            logging.error(f"Unexpected error initializing database schema: {e}")
            # Don't raise - schema initialization should not block application startup

    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()

    def store_bgp_update(self, timestamp, collector, peer_asn, prefix, as_path=None,
                          next_hop=None, communities=None, update_type="announcement",
                          origin=None, aggregator=None, host=None, id=None, raw_message=None): # Added new params
        """
        Store BGP update in Neo4j database.

        Parameters:
        - timestamp: When the update was received
        - collector: RRC collector ID
        - peer_asn: ASN of the BGP peer
        - prefix: IP prefix
        - as_path: Comma-separated AS path
        - next_hop: Next hop IP
        - communities: BGP communities
        - update_type: 'announcement' or 'withdrawal'
        - origin: Origin attribute
        - aggregator: Aggregator attribute
        - host: Collector host name
        - id: Message ID
        - raw_message: The raw JSON message as a string
        """
        try:
            with self.driver.session() as session:
                # Use isoformat() for timestamp consistency in ID
                update_id = f"{collector}_{timestamp.isoformat()}_{prefix}"

                # Create update record and connect to prefix
                session.run("""
                    MERGE (u:BGPUpdate {update_id: $update_id})
                    SET u.timestamp = $timestamp,
                        u.collector = $collector,
                        u.peer_asn = $peer_asn,
                        u.prefix = $prefix,
                        u.as_path = $as_path,
                        u.next_hop = $next_hop,
                        u.communities = $communities,
                        u.update_type = $update_type,
                        u.origin = $origin,
                        u.aggregator = $aggregator,
                        u.host = $host,
                        u.id = $id,
                        u.raw = $raw_message
                    WITH u
                    MERGE (p:Prefix {prefix: $prefix})
                    MERGE (u)-[:AFFECTS]->(p)
                    """,
                    update_id=update_id,
                    timestamp=timestamp, # Store as datetime object
                    collector=collector,
                    peer_asn=peer_asn,
                    prefix=prefix,
                    as_path=as_path,
                    next_hop=next_hop,
                    communities=str(communities) if communities else None,
                    update_type=update_type,
                    origin=origin,
                    aggregator=aggregator,
                    host=host,
                    id=id,
                    raw_message=json.dumps(raw_message) if raw_message else None # Store raw as JSON string
                )

                # Process AS path relationships if this is an announcement
                if update_type == "announcement" and as_path:
                    # Split AS path into individual ASNs
                    asns = as_path.split(",")

                    # Create ASN nodes
                    for asn in asns:
                         if asn.isdigit(): # Ensure it's a valid number before creating node
                            session.run("""
                                MERGE (a:AS {asn: toInteger($asn)})
                                """,
                                asn=asn
                            )

                    # Create AS path relationships
                    for i in range(len(asns) - 1):
                         if asns[i].isdigit() and asns[i+1].isdigit(): # Ensure both are valid numbers
                            session.run("""
                                MATCH (a1:AS {asn: toInteger($asn1)})
                                WITH a1
                                MATCH (a2:AS {asn: toInteger($asn2)})
                                MERGE (a1)-[:ANNOUNCES_TO]->(a2)
                                """,
                                asn1=asns[i],
                                asn2=asns[i+1]
                            )

                    # Connect origin AS to prefix if there are any ASNs
                    if asns and asns[-1].isdigit():
                        session.run("""
                            MATCH (a:AS {asn: toInteger($origin_asn)})
                            WITH a
                            MATCH (p:Prefix {prefix: $prefix})
                            MERGE (a)-[:ORIGINATES]->(p)
                            """,
                            origin_asn=asns[-1],
                            prefix=prefix
                        )

                # Connect update to collector
                session.run("""
                    MERGE (c:Collector {id: $collector})
                    WITH c
                    MATCH (u:BGPUpdate {update_id: $update_id})
                    MERGE (c)-[:REPORTED]->(u)
                    """,
                    collector=collector,
                    update_id=update_id
                )

            return True
        except Exception as e:
            logging.error(f"Error storing BGP update: {e}")
            return False

    def mark_suspicious_update(self, update_id, reasons):
        """Mark a BGP update as suspicious with reasons."""
        try:
            with self.driver.session() as session:
                session.run("""
                    MATCH (u:BGPUpdate {update_id: $update_id})
                    SET u.suspicious = true,
                        u.alert_reasons = $reasons
                    """,
                    update_id=update_id,
                    reasons=";".join(reasons)
                )
            return True
        except Exception as e:
            logging.error(f"Error marking suspicious update: {e}")
            return False

    def get_prefix_history(self, prefix, limit=10):
        """Get recent history for a specific prefix."""
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (u:BGPUpdate)-[:AFFECTS]->(p:Prefix {prefix: $prefix})
                    RETURN u.timestamp, u.as_path, u.peer_asn, u.update_type
                    ORDER BY u.timestamp DESC
                    LIMIT $limit
                    """,
                    prefix=prefix,
                    limit=limit
                )

                history = []
                for record in result:
                    history.append({
                        'timestamp': record['u.timestamp'],
                        'as_path': record['u.as_path'],
                        'peer_asn': record['u.peer_asn'],
                        'update_type': record['u.update_type']
                    })
                return history
        except Exception as e:
            logging.error(f"Error retrieving prefix history: {e}")
            return []

    def get_as_announcements(self, asn, limit=10):
        """Get recent announcements from a specific AS."""
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (a:AS {asn: toInteger($asn)})-[:ORIGINATES]->(p:Prefix)
                    MATCH (u:BGPUpdate)-[:AFFECTS]->(p)
                    WHERE u.update_type = 'announcement'
                    RETURN u.timestamp, u.prefix, u.as_path
                    ORDER BY u.timestamp DESC
                    LIMIT $limit
                    """,
                    asn=asn,
                    limit=limit
                )

                announcements = []
                for record in result:
                    announcements.append({
                        'timestamp': record['u.timestamp'],
                        'prefix': record['u.prefix'],
                        'as_path': record['u.as_path']
                    })
                return announcements
        except Exception as e:
            logging.error(f"Error retrieving AS announcements: {e}")
            return []

    def store_security_alert(self, alert):
        """
        Store a security alert in Neo4j. Creates the alert node first,
        then optionally links it to the triggering BGP update.
        """
        try:
            with self.driver.session() as session:
                # Step 1: Create/Merge the SecurityAlert node unconditionally
                # Ensure timestamp is in a compatible format for ID generation
                ts_str = alert['timestamp'].isoformat() if isinstance(alert['timestamp'], datetime) else str(alert['timestamp'])
                alert_id = f"{ts_str}_{alert['prefix']}"

                session.run("""
                    MERGE (a:SecurityAlert {alert_id: $alert_id})
                    ON CREATE SET
                        a.timestamp = $timestamp,
                        a.severity = $severity,
                        a.prefix = $prefix,
                        a.as_path = $as_path,
                        a.peer_asn = $peer_asn,
                        a.reasons = $reasons,
                        a.is_critical_prefix = $is_critical,
                        a.origin_as = $origin_as, // Store origin AS if available
                        a.previous_origin_as = $previous_origin_as // Store previous origin if available
                    ON MATCH SET
                        a.timestamp = $timestamp, // Update timestamp on match? Or keep first seen? Decide policy.
                        a.severity = $severity,   // Update severity if it changes?
                        a.reasons = $reasons      // Update reasons?
                    """,
                    alert_id=alert_id,
                    timestamp=alert['timestamp'], # Store original datetime object
                    severity=alert['severity'],
                    prefix=alert['prefix'],
                    as_path=alert.get('as_path'), # Use get() for optional fields
                    peer_asn=alert.get('peer_asn'),
                    reasons=";".join(alert.get('reasons', [])),
                    is_critical=alert.get('is_critical_prefix', False),
                    origin_as=alert.get('origin_as'),
                    previous_origin_as=alert.get('previous_origin_as')
                )

                # Step 2: Optionally match the BGPUpdate and create the relationship
                # Use the same ID construction logic as store_bgp_update
                update_id = alert_id # Assuming alert_id and update_id are constructed the same way
                result = session.run("""
                    MATCH (a:SecurityAlert {alert_id: $alert_id})
                    MATCH (u:BGPUpdate {update_id: $update_id})
                    MERGE (a)-[r:TRIGGERED_BY]->(u)
                    RETURN count(r) as link_count
                    """,
                    alert_id=alert_id,
                    update_id=update_id
                )
                # Check if the link was created or already existed
                link_summary = result.consume()
                # This part is tricky as MERGE doesn't directly tell you if it matched or created.
                # We could potentially log if the BGPUpdate node wasn't found, but that requires another query.
                # For now, we assume if the query runs without error, the alert node is saved.

                return True
        except Exception as e:
            logging.error(f"Error storing security alert: {e}")
            return False

    def get_recent_alerts(self, limit=100, min_severity="LOW"):
        """
        Get recent security alerts from Neo4j.

        Parameters:
        - limit: Maximum number of alerts to return
        - min_severity: Minimum severity level ("LOW", "MEDIUM", "HIGH")
        """
        severity_levels = {
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 2
        }
        min_level = severity_levels.get(min_severity.upper(), 0) # Ensure uppercase comparison

        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (a:SecurityAlert)
                    WHERE CASE a.severity
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 1
                        ELSE 0
                    END >= $min_level
                    RETURN a
                    ORDER BY a.timestamp DESC
                    LIMIT $limit
                    """,
                    min_level=min_level,
                    limit=limit
                )

                alerts = []
                for record in result:
                    alert_node = record['a']
                    # Convert Neo4j DateTime back to Python datetime if needed, or handle isoformat string
                    timestamp_val = alert_node['timestamp']
                    if hasattr(timestamp_val, 'to_native'): # Check if it's a Neo4j DateTime object
                         timestamp_dt = timestamp_val.to_native()
                    else: # Assume it might be stored as string already (though should be datetime)
                         try:
                              timestamp_dt = datetime.fromisoformat(str(timestamp_val))
                         except:
                              timestamp_dt = timestamp_val # Fallback

                    alerts.append({
                        'timestamp': timestamp_dt, # Return as datetime object
                        'severity': alert_node['severity'],
                        'prefix': alert_node['prefix'],
                        'as_path': alert_node.get('as_path'), # Use get for optional fields
                        'peer_asn': alert_node.get('peer_asn'),
                        'reasons': alert_node.get('reasons', '').split(';'),
                        'is_critical_prefix': alert_node.get('is_critical_prefix', False),
                        'origin_as': alert_node.get('origin_as'),
                        'previous_origin_as': alert_node.get('previous_origin_as')
                    })
                return alerts
        except Exception as e:
            logging.error(f"Error retrieving security alerts: {e}")
            return []

    def export_alerts_to_csv(self, filepath, start_date=None, end_date=None):
        """
        Export security alerts to CSV file.

        Parameters:
        - filepath: Path to save the CSV file
        - start_date: Optional start date filter (datetime)
        - end_date: Optional end date filter (datetime)
        """
        import csv
        # from datetime import datetime # Already imported

        try:
            with self.driver.session() as session:
                # Build query with optional date filters
                query = """
                    MATCH (a:SecurityAlert)
                    WHERE 1=1
                """
                params = {}

                if start_date:
                    query += " AND a.timestamp >= $start_date"
                    params['start_date'] = start_date

                if end_date:
                    query += " AND a.timestamp <= $end_date"
                    params['end_date'] = end_date

                query += """
                    RETURN
                        a.timestamp as timestamp,
                        a.severity as severity,
                        a.prefix as prefix,
                        a.as_path as as_path,
                        a.peer_asn as peer_asn,
                        a.reasons as reasons,
                        a.is_critical_prefix as is_critical,
                        a.origin_as as origin_as,
                        a.previous_origin_as as previous_origin_as
                    ORDER BY a.timestamp DESC
                """

                result = session.run(query, params)

                # Write to CSV
                with open(filepath, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write header
                    writer.writerow([
                        'Timestamp', 'Severity', 'Prefix', 'AS Path',
                        'Peer ASN', 'Reasons', 'Critical Prefix',
                        'Origin AS', 'Previous Origin AS' # Added new headers
                    ])

                    # Write data
                    for record in result:
                         # Handle potential Neo4j DateTime objects
                         timestamp_val = record['timestamp']
                         if hasattr(timestamp_val, 'isoformat'):
                              ts_str = timestamp_val.isoformat()
                         else:
                              ts_str = str(timestamp_val)

                         writer.writerow([
                            ts_str,
                            record['severity'],
                            record['prefix'],
                            record['as_path'],
                            record['peer_asn'],
                            record['reasons'],
                            'Yes' if record['is_critical'] else 'No',
                            record['origin_as'],
                            record['previous_origin_as']
                        ])

                return True

        except Exception as e:
            logging.error(f"Error exporting alerts to CSV: {e}")
            return False

    # --- EPISODE SUPPORT ---
    def store_episode(self, episode: Dict, final: bool = False) -> bool:
        """
        Store or update an episode in Neo4j.
        Args:
            episode: Dictionary representing the episode (see Episode.to_dict())
            final: Whether this is the final update (episode closed)
        """
        try:
            with self.driver.session() as session:
                # Serialize metadata as JSON
                metadata_json = json.dumps(episode.get("metadata", {}))
                # Use episode_id as unique key
                episode_id = episode.get("id")
                session.run("""
                    MERGE (e:Episode {episode_id: $episode_id})
                    SET e.prefix = $prefix,
                        e.origin_as = $origin_as,
                        e.start_time = $start_time,
                        e.end_time = $end_time,
                        e.max_severity = $max_severity,
                        e.score = $score,
                        e.event_count = $event_count,
                        e.metadata = $metadata,
                        e.status = $status
                    """,
                    episode_id=episode_id,
                    prefix=episode.get("prefix"),
                    origin_as=episode.get("origin_as"),
                    start_time=episode.get("start_time"),
                    end_time=episode.get("end_time"),
                    max_severity=episode.get("max_severity"),
                    score=episode.get("score"),
                    event_count=episode.get("event_count"),
                    metadata=metadata_json,
                    status=episode.get("status", "OPEN")
                )
            return True
        except Exception as e:
            logging.error(f"Error storing episode: {e}")
            return False

    def get_episode_by_id(self, episode_id: str) -> Optional[Dict]:
        """
        Retrieve an episode by its ID.
        """
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (e:Episode {episode_id: $episode_id})
                    RETURN e
                    """,
                    episode_id=episode_id
                )
                record = result.single()
                if record:
                    e = record["e"]
                    # Parse metadata JSON
                    metadata = json.loads(e.get("metadata", "{}"))
                    return {
                        "id": e["episode_id"],
                        "prefix": e.get("prefix"),
                        "origin_as": e.get("origin_as"),
                        "start_time": e.get("start_time"),
                        "end_time": e.get("end_time"),
                        "max_severity": e.get("max_severity"),
                        "score": e.get("score"),
                        "event_count": e.get("event_count"),
                        "metadata": metadata,
                        "status": e.get("status", "OPEN")
                    }
            return None
        except Exception as e:
            logging.error(f"Error retrieving episode by ID: {e}")
            return None

    def get_active_episodes(self) -> List[Dict]:
        """
        Retrieve all active (OPEN) episodes.
        """
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (e:Episode)
                    WHERE e.status = 'OPEN'
                    RETURN e
                    ORDER BY e.start_time DESC
                    """)
                episodes = []
                for record in result:
                    e = record["e"]
                    metadata = json.loads(e.get("metadata", "{}"))
                    episodes.append({
                        "id": e["episode_id"],
                        "prefix": e.get("prefix"),
                        "origin_as": e.get("origin_as"),
                        "start_time": e.get("start_time"),
                        "end_time": e.get("end_time"),
                        "max_severity": e.get("max_severity"),
                        "score": e.get("score"),
                        "event_count": e.get("event_count"),
                        "metadata": metadata,
                        "status": e.get("status", "OPEN")
                    })
                return episodes
        except Exception as e:
            logging.error(f"Error retrieving active episodes: {e}")
            return []

    def get_episodes_by_prefix(self, prefix: str, limit: int = 20) -> List[Dict]:
        """
        Retrieve episodes for a given prefix.
        """
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (e:Episode)
                    WHERE e.prefix = $prefix
                    RETURN e
                    ORDER BY e.start_time DESC
                    LIMIT $limit
                    """,
                    prefix=prefix,
                    limit=limit
                )
                episodes = []
                for record in result:
                    e = record["e"]
                    metadata = json.loads(e.get("metadata", "{}"))
                    episodes.append({
                        "id": e["episode_id"],
                        "prefix": e.get("prefix"),
                        "origin_as": e.get("origin_as"),
                        "start_time": e.get("start_time"),
                        "end_time": e.get("end_time"),
                        "max_severity": e.get("max_severity"),
                        "score": e.get("score"),
                        "event_count": e.get("event_count"),
                        "metadata": metadata,
                        "status": e.get("status", "OPEN")
                    })
                return episodes
        except Exception as e:
            logging.error(f"Error retrieving episodes by prefix: {e}")
            return []

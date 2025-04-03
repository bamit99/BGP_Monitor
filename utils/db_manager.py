from neo4j import GraphDatabase
from neo4j.exceptions import ClientError
import logging
import json # Import the json module
from datetime import datetime

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
            
    def _cleanup_duplicates_tx(self, tx):
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
        result = tx.run(cleanup_query)
        summary = result.consume()
        if summary.counters.nodes_deleted > 0:
             logging.info(f"Cleaned up {summary.counters.nodes_deleted} duplicate SecurityAlert nodes.")
        else:
             logging.info("No duplicate SecurityAlert nodes found to clean up.")


    def _create_schema_tx(self, tx):
        """Transaction function to create schema elements (constraints and indexes)."""
        # Ensure clean state for alert_id uniqueness: drop constraint by name and any index on the property
        tx.run("DROP CONSTRAINT security_alert_id_unique IF EXISTS") # Drop by specific name
        tx.run("DROP INDEX security_alert_id IF EXISTS") # Drop index by specific name

        # Now, create the unique constraint for alert_id (implicitly creates an index)
        # Use IF NOT EXISTS for idempotency, even after attempting drops
        tx.run("CREATE CONSTRAINT security_alert_id_unique IF NOT EXISTS FOR (a:SecurityAlert) REQUIRE a.alert_id IS UNIQUE")

        # Create indexes for non-unique properties used in lookups
        tx.run("""
            CREATE INDEX security_alert_timestamp IF NOT EXISTS
            FOR (a:SecurityAlert)
            ON (a.timestamp)
        """)
        tx.run("""
            CREATE INDEX security_alert_severity IF NOT EXISTS
            FOR (a:SecurityAlert)
            ON (a.severity)
        """)

    def _drop_schema_tx(self, tx):
        """Transaction function to drop potentially conflicting schema elements."""
        # Drop constraint by name and any index on the property
        tx.run("DROP CONSTRAINT security_alert_id_unique IF EXISTS")
        tx.run("DROP INDEX security_alert_id IF EXISTS")
        # Also drop the other indexes in case they need recreation (optional but safer)
        tx.run("DROP INDEX security_alert_timestamp IF EXISTS")
        tx.run("DROP INDEX security_alert_severity IF EXISTS")


    def _init_schema(self):
        """Initialize database schema using separate transactions for cleanup, drop, and create."""
        try:
            with self.driver.session() as session:
                # 1. Run cleanup in its own transaction first
                session.write_transaction(self._cleanup_duplicates_tx)
                # 2. Run drop operations in a separate transaction
                session.write_transaction(self._drop_schema_tx)
                # 3. Run create operations in a final transaction
                session.write_transaction(self._create_schema_tx)

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
                    timestamp=timestamp.isoformat(),
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
                        session.run("""
                            MERGE (a:AS {asn: $asn})
                            """,
                            asn=asn
                        )
                    
                    # Create AS path relationships
                    for i in range(len(asns) - 1):
                        session.run("""
                            MATCH (a1:AS {asn: $asn1})
                            WITH a1
                            MATCH (a2:AS {asn: $asn2})
                            MERGE (a1)-[:ANNOUNCES_TO]->(a2)
                            """,
                            asn1=asns[i],
                            asn2=asns[i+1]
                        )
                    
                    # Connect origin AS to prefix if there are any ASNs
                    if asns:
                        session.run("""
                            MATCH (a:AS {asn: $origin_asn})
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
                    MATCH (a:AS {asn: $asn})-[:ORIGINATES]->(p:Prefix)
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
        Store a security alert in Neo4j.
        
        Parameters:
        - alert: Dictionary containing alert details
        """
        try:
            with self.driver.session() as session:
                # Step 1: Create/Merge the SecurityAlert node unconditionally
                alert_id = f"{alert['timestamp'].isoformat()}_{alert['prefix']}"
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
                    timestamp=alert['timestamp'],
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
                session.run("""
                    MATCH (a:SecurityAlert {alert_id: $alert_id})
                    MATCH (u:BGPUpdate {update_id: $update_id})
                    MERGE (a)-[:TRIGGERED_BY]->(u)
                    """,
                    alert_id=alert_id,
                    update_id=update_id
                )
                # Note: If the MATCH for BGPUpdate fails, the MERGE relationship won't be created,
                # but the SecurityAlert node will still exist from Step 1.
                # We might want to log a warning if the MATCH fails.
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
        min_level = severity_levels.get(min_severity, 0)
        
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
                    alert = record['a']
                    alerts.append({
                        'timestamp': alert['timestamp'],
                        'severity': alert['severity'],
                        'prefix': alert['prefix'],
                        'as_path': alert['as_path'],
                        'peer_asn': alert['peer_asn'],
                        'reasons': alert['reasons'].split(';'),
                        'is_critical_prefix': alert['is_critical_prefix'],
                        # Field removed from dictionary construction
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
        from datetime import datetime
        
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
                        a.is_critical_prefix as is_critical
                    ORDER BY a.timestamp DESC
                """
                
                result = session.run(query, params)
                
                # Write to CSV
                with open(filepath, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write header
                    writer.writerow([
                        'Timestamp', 'Severity', 'Prefix', 'AS Path', 
                        'Peer ASN', 'Reasons', 'Critical Prefix'
                    ])
                    
                    # Write data
                    for record in result:
                        writer.writerow([
                            record['timestamp'].isoformat() if isinstance(record['timestamp'], datetime) else record['timestamp'],
                            record['severity'],
                            record['prefix'],
                            record['as_path'],
                            record['peer_asn'],
                            record['reasons'],
                            'Yes' if record['is_critical'] else 'No',
                            # Removed corresponding value write
                        ])
                
                return True
                
        except Exception as e:
            logging.error(f"Error exporting alerts to CSV: {e}")
            return False

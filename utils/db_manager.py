from neo4j import GraphDatabase
import logging
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
            
    def _init_schema(self):
        """Initialize database schema with indexes and constraints."""
        try:
            with self.driver.session() as session:
                # Create indexes
                session.run("""
                    CREATE INDEX security_alert_id IF NOT EXISTS
                    FOR (a:SecurityAlert)
                    ON (a.alert_id)
                """)
                
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
                
                # Create constraints
                session.run("""
                    CREATE CONSTRAINT security_alert_id_unique IF NOT EXISTS
                    FOR (a:SecurityAlert)
                    REQUIRE a.alert_id IS UNIQUE
                """)
                
            logging.info("Successfully initialized database schema")
            
        except Exception as e:
            logging.error(f"Error initializing database schema: {e}")
            # Don't raise - schema initialization should not block application startup
    
    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()
    
    def store_bgp_update(self, timestamp, collector, peer_asn, prefix, as_path=None, 
                          next_hop=None, communities=None, update_type="announcement"):
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
                        u.update_type = $update_type
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
                    update_type=update_type
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
                # Create alert node
                session.run("""
                    MERGE (a:SecurityAlert {
                        alert_id: $alert_id,
                        timestamp: $timestamp,
                        severity: $severity,
                        prefix: $prefix,
                        as_path: $as_path,
                        peer_asn: $peer_asn,
                        reasons: $reasons,
                        is_critical_prefix: $is_critical,
                        involves_uk_telecom: $involves_uk
                    })
                    WITH a
                    MATCH (u:BGPUpdate {update_id: $update_id})
                    MERGE (a)-[:TRIGGERED_BY]->(u)
                    """,
                    alert_id=f"{alert['timestamp'].isoformat()}_{alert['prefix']}",
                    timestamp=alert['timestamp'],
                    severity=alert['severity'],
                    prefix=alert['prefix'],
                    as_path=alert['as_path'],
                    peer_asn=alert['peer_asn'],
                    reasons=";".join(alert['reasons']),
                    is_critical=alert['is_critical_prefix'],
                    involves_uk=alert['involves_uk_telecom'],
                    update_id=f"{alert['timestamp'].isoformat()}_{alert['prefix']}"
                )
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
                        'involves_uk_telecom': alert['involves_uk_telecom']
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
                        a.is_critical_prefix as is_critical,
                        a.involves_uk_telecom as involves_uk
                    ORDER BY a.timestamp DESC
                """
                
                result = session.run(query, params)
                
                # Write to CSV
                with open(filepath, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write header
                    writer.writerow([
                        'Timestamp', 'Severity', 'Prefix', 'AS Path', 
                        'Peer ASN', 'Reasons', 'Critical Prefix', 'UK Telecom'
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
                            'Yes' if record['involves_uk'] else 'No'
                        ])
                
                return True
                
        except Exception as e:
            logging.error(f"Error exporting alerts to CSV: {e}")
            return False

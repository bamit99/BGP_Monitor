from neo4j import GraphDatabase
import logging
from pathlib import Path
import pandas as pd
import json
from datetime import datetime

class BGPDatabaseManager:
    def __init__(self, uri="bolt://localhost:7687", username="neo4j", password="password"):
        """Initialize the database manager with Neo4j connection details."""
        self.uri = uri
        self.username = username
        self.password = password
        self.driver = None
        self.connect()

    def connect(self):
        """Establish connection to Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.username, self.password))
            # Verify connection
            with self.driver.session() as session:
                result = session.run("RETURN 1")
                result.single()
            logging.info("✓ Successfully connected to Neo4j database")
            
            # Initialize schema
            self._init_schema()
            
        except Exception as e:
            logging.error(f"✗ Failed to connect to Neo4j: {e}")
            self.driver = None

    def _init_schema(self):
        """Initialize Neo4j schema with necessary indexes and constraints."""
        try:
            with self.driver.session() as session:
                # Create constraints
                session.run("""
                    CREATE CONSTRAINT prefix_unique IF NOT EXISTS
                    FOR (p:Prefix) REQUIRE p.prefix IS UNIQUE
                """)
                
                # Create indexes
                session.run("""
                    CREATE INDEX update_timestamp IF NOT EXISTS
                    FOR (u:Update) ON (u.timestamp)
                """)
                session.run("""
                    CREATE INDEX update_type IF NOT EXISTS
                    FOR (u:Update) ON (u.update_type)
                """)
                
                logging.info("✓ Neo4j schema initialized")
        except Exception as e:
            logging.error(f"✗ Failed to initialize Neo4j schema: {e}")

    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()

    def ensure_connection(self):
        """Ensure that the database connection is active; if not, attempt to reconnect. Returns True if connection is active."""
        if self.driver is None:
            logging.info("Driver is None, attempting to reconnect...")
            self.connect()
        return self.driver is not None

    def store_bgp_update(self, timestamp, collector, peer_asn, prefix, as_path=None, next_hop=None, communities=None, update_type="announcement"):
        """Store BGP update in Neo4j."""
        if not self.ensure_connection():
            logging.error("No active database connection available in store_bgp_update")
            raise Exception("Database connection not available")
        
        try:
            # Convert collections to strings for Neo4j storage
            if communities:
                if isinstance(communities, list):
                    communities = ','.join(map(str, communities))
                else:
                    communities = str(communities)
            
            if as_path and isinstance(as_path, list):
                as_path = ','.join(map(str, as_path))
            
            # Create properties map
            update_props = {
                "timestamp": timestamp.isoformat(),
                "collector": collector,
                "peer_asn": str(peer_asn),
                "prefix": prefix,
                "update_type": update_type
            }
            
            # Add optional properties if present
            if as_path:
                update_props["as_path"] = as_path
            if next_hop:
                update_props["next_hop"] = next_hop
            if communities:
                update_props["communities"] = communities
            
            # Create or merge prefix node and update node
            query = """
            MERGE (p:Prefix {prefix: $prefix})
            CREATE (u:Update)
            SET u = $update_props
            CREATE (p)-[:HAS_UPDATE]->(u)
            """
            
            with self.driver.session() as session:
                session.run(query, prefix=prefix, update_props=update_props)
                logging.info(f"✓ Stored {update_type} for {prefix}")
                
        except Exception as e:
            logging.error(f"✗ Failed to store {update_type} for {prefix}: {e}")
            raise

    def store_suspicious_update(self, timestamp, prefix, as_path, reasons):
        """Store suspicious BGP updates in Neo4j."""
        if not self.ensure_connection():
            logging.error("No active database connection available in store_suspicious_update")
            return

        with self.driver.session() as session:
            try:
                cypher_query = """
                MERGE (p:Prefix {prefix: $prefix})
                CREATE (s:SuspiciousUpdate {
                    timestamp: datetime($timestamp),
                    as_path: $as_path,
                    reasons: $reasons
                })
                CREATE (s)-[:AFFECTS]->(p)
                """
                
                session.run(
                    cypher_query,
                    prefix=prefix,
                    timestamp=timestamp.isoformat(),
                    as_path=as_path,
                    reasons=reasons
                )
                logging.info(f"✓ Successfully stored suspicious update for prefix {prefix}")
                
            except Exception as e:
                logging.error(f"Error storing suspicious update in Neo4j: {e}")
                raise

    def get_prefix_history(self, prefix, limit=10):
        """Retrieve history of updates for a specific prefix."""
        if not self.ensure_connection():
            logging.error("No active database connection available in get_prefix_history")
            return []

        with self.driver.session() as session:
            try:
                result = session.run("""
                MATCH (u:Update)-[:ANNOUNCES]->(p:Prefix {prefix: $prefix})
                RETURN u.timestamp as timestamp, u.peer_asn as peer_asn,
                       u.next_hop as next_hop, u.communities as communities
                ORDER BY u.timestamp DESC
                LIMIT $limit
                """, prefix=prefix, limit=limit)
                
                return [dict(record) for record in result]
            except Exception as e:
                logging.error(f"Error retrieving prefix history from Neo4j: {e}")
                raise

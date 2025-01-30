from neo4j import GraphDatabase
import logging
from pathlib import Path
import pandas as pd
import json

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
        except Exception as e:
            logging.error(f"✗ Failed to connect to Neo4j: {e}")
            self.driver = None

    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()

    def store_bgp_update(self, timestamp, collector, peer_asn, prefix, as_path, next_hop, communities=None):
        """Store BGP update in Neo4j database."""
        if not self.driver:
            logging.error("No database connection available")
            return

        with self.driver.session() as session:
            try:
                # Create or update nodes and relationships
                cypher_query = """
                // Create prefix node first
                MERGE (p:Prefix {prefix: $prefix})
                
                // Create collector node
                MERGE (c:Collector {name: $collector})
                
                // Create update node and link it
                CREATE (u:Update {
                    timestamp: datetime($timestamp),
                    peer_asn: $peer_asn,
                    next_hop: $next_hop,
                    communities: $communities
                })
                CREATE (u)-[:ANNOUNCES]->(p)
                CREATE (c)-[:RECEIVED]->(u)
                
                // Create AS path
                WITH u, $as_path as path
                UNWIND range(0, size(path)-1) as i
                MERGE (as1:AS {asn: path[i]})
                WITH u, as1, i, path
                WHERE i < size(path)-1
                MERGE (as2:AS {asn: path[i+1]})
                CREATE (as1)-[:PEERS_WITH {update_id: id(u)}]->(as2)
                """
                
                # Convert AS path to list if it's a string
                as_path_list = as_path.split(',') if isinstance(as_path, str) else as_path
                
                # Execute the query
                session.run(
                    cypher_query,
                    prefix=prefix,
                    collector=collector,
                    timestamp=timestamp.isoformat(),
                    peer_asn=peer_asn,
                    next_hop=next_hop,
                    communities=json.dumps(communities) if communities else None,
                    as_path=as_path_list
                )
                logging.info(f"✓ Successfully stored BGP update for prefix {prefix}")
                
            except Exception as e:
                logging.error(f"Error storing BGP update in Neo4j: {e}")
                raise

    def store_suspicious_update(self, timestamp, prefix, as_path, reasons):
        """Store suspicious BGP updates in Neo4j."""
        if not self.driver:
            logging.error("No database connection available")
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
        if not self.driver:
            logging.error("No database connection available")
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

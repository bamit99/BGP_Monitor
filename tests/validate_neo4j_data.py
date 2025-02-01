"""Validate Neo4j data storage for BGP updates."""
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG

def print_db_stats(session):
    """Print database statistics."""
    print("\nDatabase Statistics and Analysis")
    print("=" * 50)
    
    # Count by node type
    queries = [
        ("Total Updates", "MATCH (u:Update) RETURN count(u) as count"),
        ("Total Prefixes", "MATCH (p:Prefix) RETURN count(p) as count"),
        ("Total Relationships", "MATCH (u:Update)-[r:AFFECTS]->(p:Prefix) RETURN count(r) as count"),
        ("Updates in last hour", """
            MATCH (u:Update)
            WHERE datetime(toString(u.timestamp)) > datetime() - duration('PT1H')
            RETURN count(u) as count
        """),
        ("Updates in last 24h", """
            MATCH (u:Update)
            WHERE datetime(toString(u.timestamp)) > datetime() - duration('P1D')
            RETURN count(u) as count
        """),
        ("Most Active Peer ASNs (Top 5)", """
            MATCH (u:Update)
            WITH u.peer_asn as asn, count(u) as count
            ORDER BY count DESC
            LIMIT 5
            RETURN asn, count
        """),
        ("Most Active Prefixes (Top 5)", """
            MATCH (u:Update)-[:AFFECTS]->(p:Prefix)
            WITH p.prefix as prefix, count(u) as updates
            ORDER BY updates DESC
            LIMIT 5
            RETURN prefix, updates
        """),
        ("Updates by Collector", """
            MATCH (u:Update)
            WITH u.collector as collector, count(u) as count
            ORDER BY count DESC
            RETURN collector, count
        """),
        ("Recent Updates (Last 5)", """
            MATCH (u:Update)-[:AFFECTS]->(p:Prefix)
            RETURN 
                u.timestamp as time,
                u.collector as collector,
                u.peer_asn as peer_asn,
                p.prefix as prefix
            ORDER BY u.timestamp DESC
            LIMIT 5
        """)
    ]
    
    for description, query in queries:
        print(f"\n{description}:")
        try:
            result = session.run(query)
            records = list(result)
            
            if description == "Recent Updates (Last 5)":
                for record in records:
                    print(f"  - Time: {record['time']}")
                    print(f"    Collector: {record['collector']}")
                    print(f"    Peer ASN: {record['peer_asn']}")
                    print(f"    Prefix: {record['prefix']}")
                    print()
            elif description.endswith("(Top 5)"):
                if "Prefix" in description:
                    for record in records:
                        print(f"  - Prefix: {record['prefix']}, Updates: {record['updates']}")
                else:
                    for record in records:
                        print(f"  - ASN: {record['asn']}, Count: {record['count']}")
            elif "by" in description:
                for record in records:
                    name = record['collector']
                    name = name if name else 'unknown'
                    print(f"  - {name}: {record['count']}")
            else:
                if records:
                    print(f"  {records[0]['count']}")
        except Exception as e:
            print(f"  Error getting {description}: {str(e)}")

def run_connection_test(session):
    """Run a test to verify database connection and operations."""
    print("\nRunning Database Connection Test")
    print("=" * 50)
    
    try:
        # Clear any previous test data
        print("\n1. Clearing previous test data...")
        session.run("""
            MATCH (u:Update {is_test: true})-[r]->(p:Prefix)
            WHERE p.is_test = true
            DETACH DELETE u, p
        """)
        print("✓ Previous test data cleared")
        
        # Test storing a sample update
        print("\n2. Testing update storage...")
        test_update = {
            "timestamp": datetime.now(),
            "collector": "test-collector",
            "peer_asn": "12345",
            "prefix": "192.0.2.0/24",
            "as_path": "12345,23456",
            "next_hop": "192.0.2.1",
            "message_type": "announcement",
            "is_test": True
        }
        
        # Store test update with test marker
        with session.begin_transaction() as tx:
            query = """
            MERGE (p:Prefix {prefix: $prefix})
            ON CREATE SET p.is_test = true
            WITH p
            CREATE (u:Update)
            SET u = $update_props
            CREATE (u)-[:AFFECTS]->(p)
            """
            tx.run(query, 
                prefix=test_update['prefix'],
                update_props={
                    'timestamp': test_update['timestamp'],
                    'collector': test_update['collector'],
                    'peer_asn': test_update['peer_asn'],
                    'as_path': test_update['as_path'],
                    'next_hop': test_update['next_hop'],
                    'message_type': test_update['message_type'],
                    'is_test': True
                }
            )
            tx.commit()
            print("✓ Test update stored successfully")
        
        # Verify the stored test data
        print("\n3. Verifying stored test data...")
        query = """
        MATCH (u:Update {is_test: true})-[:AFFECTS]->(p:Prefix)
        WHERE u.collector = 'test-collector'
        RETURN u, p
        """
        result = session.run(query)
        records = list(result)
        if records:
            print("✓ Test data verified successfully")
            update = records[0]['u']
            prefix = records[0]['p']
            print("\nTest Update Details:")
            print(f"- Collector: {update['collector']}")
            print(f"- Peer ASN: {update['peer_asn']}")
            print(f"- AS Path: {update['as_path']}")
            print(f"- Prefix: {prefix['prefix']}")
        else:
            print("✗ No test data found")
        
        # Clean up test data
        print("\n4. Cleaning up test data...")
        session.run("""
            MATCH (u:Update {is_test: true})-[r]->(p:Prefix)
            WHERE p.is_test = true
            DETACH DELETE u, p
        """)
        print("✓ Test data cleaned up")
        
        print("\nConnection Test Completed Successfully!")
        
    except Exception as e:
        print(f"\n✗ Error during test: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        if hasattr(e, 'message'):
            print(f"Error message: {e.message}")
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()

def main(args=None):
    """Main function that can be called directly or via command line."""
    if args is None:
        # When called from UI, create default arguments
        from argparse import Namespace
        args = Namespace()
        args.test = False  # Don't just run test
        args.stats_only = False  # Don't just show stats
    
    db_manager = None
    try:
        print("\nConnecting to Neo4j database...")
        db_manager = BGPDatabaseManager(**NEO4J_CONFIG)
        
        with db_manager.driver.session() as session:
            # Show statistics first
            print_db_stats(session)
            
            # Then run the test unless stats_only is True
            if not args.stats_only:
                run_connection_test(session)
        
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        if db_manager:
            db_manager.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Validate Neo4j BGP data storage')
    parser.add_argument('--test', action='store_true', help='Run connection test')
    parser.add_argument('--stats-only', action='store_true', help='Show only database statistics')
    args = parser.parse_args()
    main(args)

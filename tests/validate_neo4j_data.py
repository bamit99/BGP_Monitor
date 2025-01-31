"""Validate Neo4j data storage for BGP updates."""
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG

def validate_neo4j_data():
    """Validate the data stored in Neo4j database."""
    db_manager = None
    try:
        print("\nTesting Neo4j Connection...")
        db_manager = BGPDatabaseManager(**NEO4J_CONFIG)
        
        # Test connection with a simple query
        with db_manager.driver.session() as session:
            result = session.run("RETURN 1 as test")
            test_value = result.single()["test"]
            print(f"Connection successful! Test query returned: {test_value}")
        
        print("\nValidating Neo4j BGP Data Storage...")
        print("=" * 50 + "\n")
        
        with db_manager.driver.session() as session:
            # Clear any existing data
            session.run("MATCH (n) DETACH DELETE n")
            print("Cleared existing data")
            
            # Test storing a sample update
            print("\nTesting update storage...")
            test_update = {
                "timestamp": datetime.now(),
                "collector": "test-collector",
                "peer_asn": "12345",
                "prefix": "192.0.2.0/24",
                "as_path": "12345,23456",
                "next_hop": "192.0.2.1",
                "update_type": "announcement"
            }
            
            success = db_manager.store_bgp_update(**test_update)
            print(f"Test update storage {'successful' if success else 'failed'}")
            
            # 1. Count updates by type
            print("\n1. BGP Updates by Type:")
            query = """
            MATCH (u:Update)
            WITH u.update_type as type, COUNT(u) as count
            ORDER BY count DESC
            RETURN type, count
            """
            result = session.run(query)
            for record in result:
                print(f"- {record['type'] or 'unknown'}: {record['count']}")
            
            print("\n2. Updates in last hour by type:")
            current_time = datetime.now()
            one_hour_ago = (current_time - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
            query = """
            MATCH (u:Update)
            WHERE u.timestamp > $one_hour_ago
            WITH u.update_type as type, COUNT(u) as count
            ORDER BY count DESC
            RETURN type, count
            """
            result = session.run(query, one_hour_ago=one_hour_ago)
            for record in result:
                print(f"- {record['type'] or 'unknown'}: {record['count']}")
            
            # 3. Count unique prefixes
            print("\n3. Total Prefix Nodes:")
            query = """
            MATCH (p:Prefix)
            RETURN COUNT(p) as count
            """
            result = session.run(query)
            count = result.single()["count"]
            print(f"{count}")
            
            # 4. Most active prefixes
            print("\n4. Most Active Prefixes:")
            query = """
            MATCH (u:Update)-[:AFFECTS]->(p:Prefix)
            WITH p.prefix as prefix,
                 COUNT(u) as total,
                 COLLECT(DISTINCT u.update_type) as types,
                 COUNT(CASE WHEN u.update_type = 'announcement' THEN u END) as announcements,
                 COUNT(CASE WHEN u.update_type = 'withdrawal' THEN u END) as withdrawals
            ORDER BY total DESC
            LIMIT 5
            RETURN prefix, announcements, withdrawals, total, types
            """
            result = session.run(query)
            for record in result:
                print(f"\n   Prefix: {record['prefix']}")
                print(f"   - Announcements: {record['announcements']}")
                print(f"   - Withdrawals: {record['withdrawals']}")
                print(f"   - Total Updates: {record['total']}")
                print(f"   - Update Types: {', '.join(record['types'])}")
            
            # 5. Recent updates
            print("\nMost Recent Updates (last 10 seconds):")
            ten_seconds_ago = (current_time - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%S")
            query = """
            MATCH (u:Update)-[:AFFECTS]->(p:Prefix)
            WHERE u.timestamp > $ten_seconds_ago
            WITH u, p
            ORDER BY u.timestamp DESC
            LIMIT 5
            RETURN u.timestamp as timestamp,
                   u.collector as collector,
                   u.update_type as type,
                   p.prefix as prefix,
                   u.as_path as as_path
            """
            result = session.run(query, ten_seconds_ago=ten_seconds_ago)
            for record in result:
                print(f"\n   Update:")
                print(f"   - Time: {record['timestamp']}")
                print(f"   - Collector: {record['collector']}")
                print(f"   - Type: {record['type']}")
                print(f"   - Prefix: {record['prefix']}")
                if record['as_path']:
                    print(f"   - AS Path: {record['as_path']}")
            
        print("\nValidation Complete!")
        
    except Exception as e:
        print(f"\nError during validation: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        if hasattr(e, 'message'):
            print(f"Error message: {e.message}")
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()
    finally:
        if db_manager:
            db_manager.close()

if __name__ == "__main__":
    validate_neo4j_data()

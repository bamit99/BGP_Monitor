"""Validate Neo4j data storage for BGP updates."""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG
import datetime

def validate_neo4j_data():
    """Check if BGP data is being stored in Neo4j."""
    print("\nValidating Neo4j BGP Data Storage...")
    print("=" * 50)
    
    db_manager = BGPDatabaseManager(
        uri=NEO4J_CONFIG['uri'],
        username=NEO4J_CONFIG['username'],
        password=NEO4J_CONFIG['password']
    )
    
    try:
        with db_manager.driver.session() as session:
            # 1. Check total number of updates
            result = session.run("""
                MATCH (u:Update)
                RETURN count(u) as update_count
            """)
            update_count = result.single()["update_count"]
            print(f"\n1. Total BGP Updates: {update_count}")
            
            # 2. Check updates in the last hour
            result = session.run("""
                MATCH (u:Update)
                WHERE u.timestamp > datetime() - duration({hours: 1})
                RETURN count(u) as recent_count
            """)
            recent_count = result.single()["recent_count"]
            print(f"2. Updates in last hour: {recent_count}")
            
            # 3. Check prefixes
            result = session.run("""
                MATCH (p:Prefix)
                RETURN count(p) as prefix_count
            """)
            prefix_count = result.single()["prefix_count"]
            print(f"\n3. Total Prefix Nodes: {prefix_count}")
            
            # 4. Sample prefixes with their updates
            result = session.run("""
                MATCH (p:Prefix)<-[:ANNOUNCES]-(u:Update)
                WITH p, count(u) as update_count
                RETURN p.prefix as prefix, update_count
                ORDER BY update_count DESC
                LIMIT 5
            """)
            print("\n4. Most Active Prefixes:")
            for record in result:
                print(f"   - {record['prefix']}: {record['update_count']} updates")
            
            # 5. Check AS numbers
            result = session.run("""
                MATCH (as:AS)
                RETURN count(as) as as_count
            """)
            as_count = result.single()["as_count"]
            print(f"\n5. Total AS Nodes: {as_count}")
            
            # 6. Check collectors
            result = session.run("""
                MATCH (c:Collector)-[:RECEIVED]->(u:Update)
                WITH c.name as collector, count(u) as updates
                RETURN collector, updates
                ORDER BY updates DESC
            """)
            print("\n6. Updates per Collector:")
            for record in result:
                print(f"   - {record['collector']}: {record['updates']} updates")
            
            # 7. Get sample of recent updates
            result = session.run("""
                MATCH (c:Collector)-[:RECEIVED]->(u:Update)-[:ANNOUNCES]->(p:Prefix)
                RETURN c.name as collector, u.timestamp as timestamp, 
                       p.prefix as prefix, u.peer_asn as peer_asn
                ORDER BY u.timestamp DESC
                LIMIT 5
            """)
            print("\n7. Most Recent Updates:")
            for record in result:
                print(f"   - [{record['collector']}] {record['timestamp']}: "
                      f"Prefix {record['prefix']} from AS{record['peer_asn']}")
            
            print("\nValidation Complete!")
            
    except Exception as e:
        print(f"\n✗ Error during validation: {e}")
    finally:
        db_manager.close()

if __name__ == "__main__":
    validate_neo4j_data()

"""Test Neo4j database connection."""
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG
import datetime

def test_connection():
    """Test Neo4j connection and basic operations."""
    print("Testing Neo4j connection...")
    
    # Create database manager instance
    db_manager = BGPDatabaseManager(
        uri=NEO4J_CONFIG['uri'],
        username=NEO4J_CONFIG['username'],
        password=NEO4J_CONFIG['password']
    )
    
    try:
        # First, test basic connection
        with db_manager.driver.session() as session:
            result = session.run("RETURN 1 as test")
            test_value = result.single()["test"]
            print("✓ Basic connection test successful")
            
            # Clear any existing test data
            print("\nClearing any existing test data...")
            session.run("""
                MATCH (u:Update {is_test: true})-[r]->(p:Prefix)
                WHERE p.is_test = true
                DETACH DELETE u, p
            """)
            print("✓ Test data cleared")
        
        # Test data
        test_data = {
            'timestamp': datetime.datetime.now(),
            'collector': 'test_collector',
            'peer_asn': '12345',
            'prefix': '192.168.0.0/24',
            'as_path': '12345,67890',
            'next_hop': '10.0.0.1',
            'communities': ['100:200', '300:400'],
            'is_test': True  # Mark as test data
        }
        
        # Try to store test data
        print("\nStoring test data...")
        with db_manager.driver.session() as session:
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
                    prefix=test_data['prefix'],
                    update_props={
                        'timestamp': test_data['timestamp'],
                        'collector': test_data['collector'],
                        'peer_asn': test_data['peer_asn'],
                        'as_path': test_data['as_path'],
                        'next_hop': test_data['next_hop'],
                        'communities': test_data['communities'],
                        'is_test': True
                    }
                )
                tx.commit()
                print("✓ Successfully stored test data")
        
        # Try to retrieve data
        print("\nRetrieving test data...")
        with db_manager.driver.session() as session:
            result = session.run("""
                MATCH (u:Update {is_test: true})-[:AFFECTS]->(p:Prefix)
                WHERE u.collector = 'test_collector'
                RETURN u, p
            """)
            records = list(result)
            if records:
                print("✓ Successfully retrieved test data")
                update = records[0]['u']
                prefix = records[0]['p']
                print(f"\nRetrieved update details:")
                print(f"- Collector: {update['collector']}")
                print(f"- Peer ASN: {update['peer_asn']}")
                print(f"- AS Path: {update['as_path']}")
                print(f"- Prefix: {prefix['prefix']}")
            else:
                print("✗ No test data found")
        
        print("\nConnection test completed successfully!")
        
    except Exception as e:
        print(f"✗ Error during test: {str(e)}")
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()
    
    finally:
        print("\nCleaning up...")
        try:
            with db_manager.driver.session() as session:
                session.run("""
                    MATCH (u:Update {is_test: true})-[r]->(p:Prefix)
                    WHERE p.is_test = true
                    DETACH DELETE u, p
                """)
                print("✓ Test data cleaned up")
        except Exception as e:
            print(f"✗ Error during cleanup: {str(e)}")
        
        db_manager.close()
        print("Connection closed")

if __name__ == "__main__":
    test_connection()

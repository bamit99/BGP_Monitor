"""Test Neo4j database connection."""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

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
        # Test data
        test_data = {
            'timestamp': datetime.datetime.now(),
            'collector': 'test_collector',
            'peer_asn': '12345',
            'prefix': '192.168.0.0/24',
            'as_path': '12345,67890',
            'next_hop': '10.0.0.1',
            'communities': ['100:200', '300:400']
        }
        
        # Try to store test data
        db_manager.store_bgp_update(**test_data)
        print("✓ Successfully stored test data")
        
        # Try to retrieve data
        history = db_manager.get_prefix_history(test_data['prefix'])
        print("✓ Successfully retrieved prefix history")
        print(f"Found {len(history)} records for prefix {test_data['prefix']}")
        
        print("\nConnection test completed successfully!")
        
    except Exception as e:
        print(f"✗ Error during test: {e}")
    
    finally:
        db_manager.close()

if __name__ == "__main__":
    test_connection()

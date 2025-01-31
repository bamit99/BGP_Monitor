from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

def test_connection():
    # Create database manager instance
    db = BGPDatabaseManager(
        uri=NEO4J_CONFIG['uri'],
        username=NEO4J_CONFIG['username'],
        password=NEO4J_CONFIG['password']
    )
    
    try:
        # Test basic connection
        with db.driver.session() as session:
            # Count total nodes
            result = session.run("MATCH (n) RETURN count(n) as count")
            count = result.single()["count"]
            print(f"Total nodes in database: {count}")
            
            # Get recent BGP updates
            result = session.run("""
                MATCH (u:BGPUpdate)
                RETURN u.timestamp, u.prefix, u.as_path
                ORDER BY u.timestamp DESC
                LIMIT 5
            """)
            
            print("\nRecent BGP Updates:")
            for record in result:
                print(f"Time: {record['u.timestamp']}")
                print(f"Prefix: {record['u.prefix']}")
                print(f"AS Path: {record['u.as_path']}")
                print("-" * 50)
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    test_connection()

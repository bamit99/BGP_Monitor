from neo4j import GraphDatabase
from config.database_config import NEO4J_CONFIG
import datetime

def query_suspicious_updates():
    uri = NEO4J_CONFIG['uri']
    username = NEO4J_CONFIG['username']
    password = NEO4J_CONFIG['password']
    
    driver = GraphDatabase.driver(uri, auth=(username, password))
    
    with driver.session() as session:
        # Query suspicious updates
        result = session.run("""
            MATCH (s:SuspiciousUpdate)
            RETURN s.timestamp as timestamp, s.prefix as prefix, 
                   s.as_path as as_path, s.reasons as reasons
            ORDER BY s.timestamp DESC
            LIMIT 5
        """)
        
        records = list(result)
        
        if not records:
            print("No suspicious updates found in the database.")
        else:
            print("\nFound suspicious updates:")
            print("=" * 80)
            for record in records:
                print(f"\nTimestamp: {record['timestamp']}")
                print(f"Prefix: {record['prefix']}")
                print(f"AS Path: {record['as_path']}")
                print(f"Reasons: {record['reasons']}")
                print("-" * 40)
    
    driver.close()

if __name__ == "__main__":
    query_suspicious_updates()

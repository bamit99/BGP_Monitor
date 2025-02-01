"""Neo4j database configuration."""

import os
import json

# Load default configuration with empty credentials for sensitive info
default_config = {
    'uri': 'bolt://localhost:7687',
    'username': '',
    'password': ''
}

# Attempt to load connection settings from db_config.json
config_path = os.path.join(os.path.dirname(__file__), 'db_config.json')
if os.path.exists(config_path):
    try:
        with open(config_path, 'r') as f:
            loaded_config = json.load(f)
        # Update default_config with loaded_config values if they exist
        default_config.update(loaded_config)
    except Exception as e:
        # Could log the error here, but we fall back to defaults
        pass

NEO4J_CONFIG = default_config

def check_connection():
    """Check connection to Neo4j using settings from NEO4J_CONFIG."""
    try:
        # Import neo4j driver; ensure neo4j package is installed
        from neo4j import GraphDatabase
        uri = NEO4J_CONFIG.get('uri')
        username = NEO4J_CONFIG.get('username')
        password = NEO4J_CONFIG.get('password')
        if not uri or not username or not password:
            return False
        driver = GraphDatabase.driver(uri, auth=(username, password))
        with driver.session() as session:
            result = session.run('RETURN 1 AS result')
            record = result.single()
            if record and record.get('result') == 1:
                driver.close()
                return True
        driver.close()
        return False
    except Exception as e:
        return False

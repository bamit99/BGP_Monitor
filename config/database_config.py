"""
Configuration module for database connections.
Uses ConfigManager to handle different config formats and locations.
"""
import logging
import sys
import os

# Add project root to path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import from utils
from utils.config_manager import config_manager

# Set up logging
logger = logging.getLogger(__name__)

# Load Neo4j configuration
try:
    NEO4J_CONFIG = config_manager.load_neo4j_config()
    logger.info(f"Neo4j connection: {NEO4J_CONFIG['uri']} with user {NEO4J_CONFIG['username']}")
except Exception as e:
    logger.critical(f"Failed to load database configuration: {e}")
    # Provide fallback for testing only
    NEO4J_CONFIG = {
        'uri': 'bolt://localhost:7687',
        'username': 'neo4j',
        'password': 'password'
    }
    logger.warning("Using fallback configuration for testing purposes only!")

# Function to update configuration
def update_neo4j_config(uri=None, username=None, password=None):
    """
    Update Neo4j configuration and save to config files.
    
    Args:
        uri: Neo4j connection URI
        username: Neo4j username
        password: Neo4j password
        
    Returns:
        bool: Success or failure
    """
    global NEO4J_CONFIG
    
    # Update only the provided values
    updated_config = NEO4J_CONFIG.copy()
    if uri is not None:
        updated_config['uri'] = uri
    if username is not None:
        updated_config['username'] = username
    if password is not None:
        updated_config['password'] = password
    
    # Save the configuration
    success = config_manager.save_config(updated_config, format_type='both')
    
    # Update the global variable if save was successful
    if success:
        NEO4J_CONFIG = updated_config
        logger.info(f"Updated Neo4j config: {NEO4J_CONFIG['uri']} with user {NEO4J_CONFIG['username']}")
    else:
        logger.error("Failed to update Neo4j configuration")
    
    return success

def check_connection():
    """
    Check connection to Neo4j database.
    
    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        # Import here to avoid circular imports
        from neo4j import GraphDatabase
        
        uri = NEO4J_CONFIG.get('uri')
        username = NEO4J_CONFIG.get('username')
        password = NEO4J_CONFIG.get('password')
        
        if not uri or not username or not password:
            logger.warning("Missing Neo4j configuration")
            return False
        
        # Create a driver instance
        driver = GraphDatabase.driver(uri, auth=(username, password))
        
        # Verify connection
        driver.verify_connectivity()
        
        # Close the driver
        driver.close()
        
        # logger.info("Successfully connected to Neo4j database") # Removed to reduce log noise
        return True
        
    except Exception as e:
        logger.error(f"Failed to connect to Neo4j database: {e}")
        return False

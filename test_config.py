"""
Test script to verify the database configuration is loading correctly.
"""
import logging
from config.database_config import NEO4J_CONFIG

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_config():
    """Test that configuration is loaded correctly."""
    try:
        # Print configuration (without password)
        print("\nNeo4j Configuration:")
        print(f"URI: {NEO4J_CONFIG['uri']}")
        print(f"Username: {NEO4J_CONFIG['username']}")
        print(f"Password: {'*' * len(NEO4J_CONFIG['password'])}")
        
        print("\nConfiguration loaded successfully!")
        return True
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return False

if __name__ == "__main__":
    test_config()

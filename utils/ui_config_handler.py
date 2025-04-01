"""
UI Configuration Handler for BGP Monitor.
Provides functions to save and load configurations via the UI.
"""
import os
import json
import logging
from pathlib import Path
import sys

# Add project root to path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import our configuration modules
from config.database_config import update_neo4j_config, NEO4J_CONFIG
from utils.config_manager import config_manager

# Set up logging
logger = logging.getLogger(__name__)

class UIConfigHandler:
    """Handles configuration operations from the UI."""
    
    def __init__(self):
        """Initialize with common paths the UI might use."""
        # Check various potential paths
        self.config_paths = [
            Path('E:/BGP_Monitor/config'),
            Path('C:/BGP_Monitor/config'),
            Path(os.path.expanduser('~/BGP_Monitor/config')),
            Path('D:/ClaudeProjects/bgp_monitor/config')
        ]
        
    def save_db_config(self, uri, username, password):
        """
        Save database configuration from UI inputs.
        
        Args:
            uri: Neo4j connection URI
            username: Neo4j username
            password: Neo4j password
            
        Returns:
            tuple: (success, message)
        """
        try:
            # Use our central update function
            success = update_neo4j_config(uri, username, password)
            
            if success:
                return True, "Database configuration saved successfully"
            else:
                # If central update failed, try direct save to expected UI paths
                success = self._save_direct_json(uri, username, password)
                if success:
                    return True, "Database configuration saved in alternate location"
                else:
                    return False, "Failed to save configuration in any location"
        
        except Exception as e:
            logger.error(f"Error saving database configuration: {e}")
            return False, f"Error: {str(e)}"
    
    def _save_direct_json(self, uri, username, password):
        """
        Try to save directly to JSON in various locations.
        This is a fallback in case the main config manager fails.
        """
        config_data = {
            'uri': uri,
            'username': username,
            'password': password
        }
        
        for base_path in self.config_paths:
            try:
                # Create directory if it doesn't exist
                os.makedirs(base_path, exist_ok=True)
                
                # Try to save the file
                config_file = base_path / 'db_config.json'
                with open(config_file, 'w') as f:
                    json.dump(config_data, f, indent=4)
                
                logger.info(f"Saved database config directly to {config_file}")
                return True
            
            except Exception as e:
                logger.warning(f"Failed to save config to {base_path}: {e}")
        
        return False
    
    def get_current_config(self):
        """
        Get the current database configuration.
        
        Returns:
            dict: Current Neo4j configuration
        """
        return NEO4J_CONFIG
    
    def load_gui_settings(self):
        """
        Load GUI settings.
        
        Returns:
            dict: GUI settings
        """
        return config_manager.load_settings()
    
    def save_gui_settings(self, settings):
        """
        Save GUI settings.
        
        Args:
            settings: Dictionary with GUI settings
            
        Returns:
            bool: Success or failure
        """
        return config_manager.save_settings(settings)

# Create a shared instance
ui_handler = UIConfigHandler()

# Function for the UI to call
def save_database_config(uri, username, password):
    """
    Function for the UI to call to save database configuration.
    
    Returns:
        tuple: (success, message)
    """
    return ui_handler.save_db_config(uri, username, password)

def load_gui_settings():
    """
    Function for the UI to call to load GUI settings.
    
    Returns:
        dict: GUI settings
    """
    return ui_handler.load_gui_settings()

def save_gui_settings(settings):
    """
    Function for the UI to call to save GUI settings.
    
    Returns:
        bool: Success or failure
    """
    return ui_handler.save_gui_settings(settings)

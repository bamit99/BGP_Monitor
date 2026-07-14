"""
Configuration Manager for BGP Monitor.
Handles loading/saving configuration across different formats and locations.
"""
import configparser
import json
import os
import logging
from pathlib import Path
import logging.handlers # Import SysLogHandler

# Set up logging
logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages configuration across different formats and locations."""

    def __init__(self):
        """Initialize config manager with default paths."""
        # Get the actual project directory (where the script is running from)
        self.project_dir = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

        # Alternative paths the UI might use (only for reading)
        self.alt_paths = [
            Path('E:/BGP_Monitor'),
            Path('C:/BGP_Monitor'),
            Path(os.path.expanduser('~/BGP_Monitor'))
        ]

        # Ensure config directory exists in project directory
        self.config_dir = self.project_dir / 'config'
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # INI config paths
        self.ini_config_path = self.config_dir / 'database_config.ini'
        self.ini_template_path = self.config_dir / 'database_config_template.ini'

        # JSON config path (primary)
        self.json_config_path = self.config_dir / 'db_config.json'

        # Additional JSON paths for reading only
        self.alt_json_paths = [
            path / 'config' / 'db_config.json' for path in self.alt_paths
        ]

        # GUI settings path (specific to UI state)
        self.gui_settings_path = self.config_dir / 'gui_settings.json'

        # General application settings path (for logging, etc.)
        self.app_settings_path = self.config_dir / 'app_settings.json'

    def load_neo4j_config(self):
        """
        Load Neo4j configuration from available sources.
        Tries both INI and JSON formats across multiple paths.
        """
        env_config = {
            'uri': os.getenv('BGP_MONITOR_NEO4J_URI', ''),
            'username': os.getenv('BGP_MONITOR_NEO4J_USERNAME', ''),
            'password': os.getenv('BGP_MONITOR_NEO4J_PASSWORD', '')
        }
        if any(env_config.values()):
            if not all(env_config.values()):
                logger.warning("Neo4j environment configuration is incomplete.")
            return env_config

        # First try to load from our INI file
        config = self._load_from_ini()
        if config:
            return config

        # If not found, try JSON format
        config = self._load_from_json()
        if config:
            return config

        # Fallback to defaults
        logger.warning("No configuration found. Using fallback defaults.")
        return {
            'uri': 'bolt://localhost:7687',
            'username': 'neo4j',
            'password': ''
        }

    def load_gui_settings(self):
        """
        Load GUI settings from the specific GUI settings file.
        Returns default GUI settings if file not found.
        """
        # Load from the dedicated GUI settings path
        if self.gui_settings_path.exists():
            try:
                with open(self.gui_settings_path, 'r') as f:
                    settings = json.load(f)
                logger.info(f"Loaded GUI settings from {self.gui_settings_path}")
                return settings
            except Exception as e:
                logger.error(f"Error loading GUI settings from {self.gui_settings_path}: {e}")

        # Return default settings if no file found
        default_settings = {
            "region": "Europe",
            "collectors": [],
            "as_filters": []
        }

        logger.info("Using default GUI settings")
        return default_settings

    def save_gui_settings(self, settings):
        """
        Save GUI settings to the specific GUI settings file.

        Args:
            settings: Dictionary with GUI settings

        Returns:
            bool: Success or failure
        """
        try:
            # Write to the dedicated GUI settings file
            with open(self.gui_settings_path, 'w') as f:
                json.dump(settings, f, indent=4)

            logger.info(f"Saved GUI settings to {self.gui_settings_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save GUI settings to {self.gui_settings_path}: {e}")
            return False

    def _load_from_ini(self):
        """Load configuration from INI format."""
        if self.ini_config_path.exists():
            try:
                config = configparser.ConfigParser()
                config.read(self.ini_config_path)
                logger.info(f"Loaded INI configuration from {self.ini_config_path}")

                return {
                    'uri': config.get('neo4j', 'uri'),
                    'username': config.get('neo4j', 'username'),
                    'password': config.get('neo4j', 'password')
                }
            except Exception as e:
                logger.error(f"Error loading INI config: {e}")

        return None

    def _load_from_json(self):
        """Load configuration from JSON format across multiple paths."""
        for path in [self.json_config_path] + self.alt_json_paths:
            if path.exists():
                try:
                    with open(path, 'r') as f:
                        config = json.load(f)
                    logger.info(f"Loaded JSON configuration from {path}")

                    # Map JSON keys to our standard format if needed
                    return {
                        'uri': config.get('uri', config.get('url', '')),
                        'username': config.get('username', config.get('user', '')),
                        'password': config.get('password', config.get('pass', ''))
                    }
                except Exception as e:
                    logger.error(f"Error loading JSON config from {path}: {e}")

        return None

    def save_config(self, config, format_type='both'):
        """
        Save configuration to file.

        Args:
            config: Dictionary with configuration values
            format_type: 'ini', 'json', or 'both'
        """
        success = False

        if format_type in ['ini', 'both']:
            success = self._save_ini_config(config) or success

        if format_type in ['json', 'both']:
            success = self._save_json_config(config) or success

        return success

    def _save_ini_config(self, config):
        """Save configuration in INI format."""
        try:
            # Create config parser and add values
            parser = configparser.ConfigParser()
            parser['neo4j'] = {
                'uri': config.get('uri', ''),
                'username': config.get('username', ''),
                'password': config.get('password', '')
            }

            # Write to file
            with open(self.ini_config_path, 'w') as f:
                parser.write(f)

            logger.info(f"Saved INI configuration to {self.ini_config_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save INI configuration: {e}")
            return False

    def _save_json_config(self, config):
        """
        Save configuration in JSON format.
        Tries to save to the first path in json_config_paths.
        """
        try:
            # Create JSON data
            json_data = {
                'uri': config.get('uri', ''),
                'username': config.get('username', ''),
                'password': config.get('password', '')
            }

            # Write to file
            with open(self.json_config_path, 'w') as f:
                json.dump(json_data, f, indent=4)

            logger.info(f"Saved JSON configuration to {self.json_config_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save JSON configuration to {self.json_config_path}: {e}")
            return False

    def load_app_settings(self):
        """
        Load general application settings (e.g., logging, heuristics) from config file.
        Returns default settings if file not found or invalid.
        """
        defaults = {
            "logging": {
                "level": "INFO",
                "syslog": {
                    "enabled": False,
                    "host": "localhost",
                    "port": 514,
                    "protocol": "UDP" # UDP or TCP
                }
            },
            "security_analysis": {
                "heuristics": {
                    "long_path": {
                        "enabled": True,
                        "threshold": 30, # Default increased from 20
                        "severity": "LOW"
                    },
                    "prepending": {
                        "enabled": True,
                        "threshold": 5, # Default increased from 3
                        "severity": "LOW"
                    },
                    "more_specific": {
                        "enabled": True,
                        "prefix_length_diff": 4, # Default increased from 3
                        "severity": "MEDIUM" # Keep medium for critical prefix specifics
                    }
                }
            }
        }

        if self.app_settings_path.exists():
            try:
                with open(self.app_settings_path, 'r') as f:
                    settings = json.load(f)
                logger.info(f"Loaded application settings from {self.app_settings_path}")

                # Deep merge strategy to handle nested dictionaries like logging/security
                def deep_update(source, overrides):
                    for key, value in overrides.items():
                        if isinstance(value, dict) and key in source and isinstance(source[key], dict):
                            deep_update(source[key], value)
                        else:
                            source[key] = value
                    return source

                defaults = deep_update(defaults, settings)
                return defaults
            except Exception as e:
                logger.error(f"Error loading application settings from {self.app_settings_path}: {e}. Using defaults.")
                return defaults
        else:
            logger.info(f"Application settings file not found ({self.app_settings_path}). Using default settings.")
            # Save defaults if file doesn't exist
            self.save_app_settings(defaults)
            return defaults

    def save_app_settings(self, settings):
        """
        Save general application settings to configuration file.

        Args:
            settings: Dictionary with application settings

        Returns:
            bool: Success or failure
        """
        try:
            with open(self.app_settings_path, 'w') as f:
                json.dump(settings, f, indent=4)
            logger.info(f"Saved application settings to {self.app_settings_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save application settings to {self.app_settings_path}: {e}")
            return False

# Create a shared instance
config_manager = ConfigManager()

import json
import os
from pathlib import Path
from datetime import datetime

class ConfigManager:
    def __init__(self, config_dir="config"):
        """Initialize the configuration manager."""
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "user_settings.json"
        self.ensure_config_dir()
        
    def ensure_config_dir(self):
        """Ensure the configuration directory exists."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def load_settings(self):
        """Load user settings from JSON file."""
        default_settings = {
            "region": "Asia Pacific",
            "collectors": [],
            "as_filters": [],
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    settings = json.load(f)
                    # Update with any missing default settings
                    for key, value in default_settings.items():
                        if key not in settings:
                            settings[key] = value
                    return settings
        except Exception as e:
            print(f"Error loading settings: {e}")
        
        return default_settings
    
    def save_settings(self, settings):
        """Save user settings to JSON file."""
        try:
            settings["last_updated"] = datetime.now().isoformat()
            with open(self.config_file, 'w') as f:
                json.dump(settings, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False

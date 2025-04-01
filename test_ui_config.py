"""
Test script for UI configuration.
"""
import tkinter as tk
from gui.config_dialog import DatabaseConfigDialog
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)

def main():
    """Main function to test UI configuration."""
    root = tk.Tk()
    root.title("BGP Monitor Configuration Test")
    root.geometry("500x300")
    
    # Add some informational text
    info_text = """
    BGP Monitor Configuration Test
    
    This window tests the database configuration dialog.
    Click the button below to open the configuration dialog.
    
    The dialog will try to save to multiple locations including:
    - D:/ClaudeProjects/bgp_monitor/config/database_config.ini
    - D:/ClaudeProjects/bgp_monitor/config/db_config.json
    - E:/BGP_Monitor/config/db_config.json (if accessible)
    - C:/BGP_Monitor/config/db_config.json (if accessible)
    - ~/BGP_Monitor/config/db_config.json (in user home)
    """
    
    info_label = tk.Label(root, text=info_text, justify=tk.LEFT, padx=20, pady=20)
    info_label.pack(fill=tk.BOTH, expand=True)
    
    # Button to open configuration dialog
    config_button = tk.Button(
        root, 
        text="Open Database Configuration", 
        command=lambda: DatabaseConfigDialog(root).show(),
        padx=10,
        pady=5
    )
    config_button.pack(pady=20)
    
    root.mainloop()

if __name__ == "__main__":
    main()

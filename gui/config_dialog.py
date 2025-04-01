"""
Database Configuration Dialog for BGP Monitor GUI.
"""
import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys

# Add project root to path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import configuration handler
from utils.ui_config_handler import save_database_config, ui_handler

class DatabaseConfigDialog:
    """Dialog for configuring Neo4j database connection."""
    
    def __init__(self, parent):
        """
        Initialize the dialog.
        
        Args:
            parent: Parent tkinter window
        """
        self.parent = parent
        self.dialog = None
        
    def show(self):
        """Show the configuration dialog."""
        # Create a new top-level window
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Database Configuration")
        self.dialog.geometry("400x250")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        # Create frame with padding
        main_frame = ttk.Frame(self.dialog, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Get current configuration
        current_config = ui_handler.get_current_config()
        
        # Connection URI
        ttk.Label(main_frame, text="Neo4j URI:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.uri_var = tk.StringVar(value=current_config.get('uri', ''))
        uri_entry = ttk.Entry(main_frame, textvariable=self.uri_var, width=30)
        uri_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Username
        ttk.Label(main_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar(value=current_config.get('username', ''))
        username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=30)
        username_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Password
        ttk.Label(main_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar(value=current_config.get('password', ''))
        password_entry = ttk.Entry(main_frame, textvariable=self.password_var, width=30, show="*")
        password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Info text
        info_text = "Changes to database configuration will take effect after restarting the application."
        ttk.Label(main_frame, text=info_text, wraplength=350).grid(row=3, column=0, columnspan=2, pady=10)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Test Connection", command=self.test_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save", command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def save_config(self):
        """Save the configuration."""
        uri = self.uri_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        
        # Validate inputs
        if not uri:
            messagebox.showerror("Error", "Neo4j URI is required")
            return
        
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
        
        # Save the configuration
        success, message = save_database_config(uri, username, password)
        
        if success:
            messagebox.showinfo("Success", message)
            self.dialog.destroy()
        else:
            messagebox.showerror("Error", message)
    
    def test_connection(self):
        """Test the Neo4j connection."""
        uri = self.uri_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        
        # Validate inputs
        if not uri or not username or not password:
            messagebox.showerror("Error", "All fields are required for testing connection")
            return
        
        # Test connection (this would normally use Neo4j driver)
        try:
            # This is a placeholder - in a real app, you would actually test the connection
            # from neo4j import GraphDatabase
            # driver = GraphDatabase.driver(uri, auth=(username, password))
            # driver.verify_connectivity()
            # driver.close()
            
            # For demo purposes only
            if "localhost" in uri and username == "neo4j":
                messagebox.showinfo("Success", "Connection successful")
            else:
                messagebox.showerror("Error", "Failed to connect to database. Check your credentials.")
        
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")

# Demo code
if __name__ == "__main__":
    root = tk.Tk()
    root.title("BGP Monitor")
    root.geometry("500x300")
    
    def open_config():
        dialog = DatabaseConfigDialog(root)
        dialog.show()
    
    ttk.Button(root, text="Configure Database", command=open_config).pack(pady=20)
    
    root.mainloop()

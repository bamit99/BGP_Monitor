"""Main GUI window for BGP Monitor."""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import threading
from datetime import datetime
from src.bgp_monitor import BGPMonitor
from src.connection_manager import ConnectionManager
from utils.data_manager import DataManager
from utils.analysis import BGPAnalyzer
from utils.as_lookup import ASLookup
from config.collectors import get_collectors_by_region, get_all_regions, get_collector_location
import json
import re
import os
import subprocess
from pathlib import Path
from utils.config_manager import ConfigManager
import logging
import config.database_config as db_config
from utils.security_analyzer import SecurityAlertLogger
import time

class BGPMonitorGUI:
    def __init__(self, root):
        """Initialize the GUI."""
        self.root = root
        self.root.title("BGP Monitor")
        self.root.geometry("1000x800")  # Increased width for security panel
        
        # Initialize configuration manager
        self.config_manager = ConfigManager()
        self.settings = self.config_manager.load_settings()
        
        # Initialize security alert logger
        self.alert_logger = SecurityAlertLogger()
        
        # Create main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create left and right frames
        self.left_frame = ttk.Frame(self.main_frame)
        self.left_frame.pack(side="left", fill="both", expand=True)
        
        self.right_frame = ttk.Frame(self.main_frame)
        self.right_frame.pack(side="right", fill="both", expand=True, padx=(5,0))
        
        self.filtered_as_numbers = set()
        self.data_manager = DataManager("data")
        self.as_lookup = ASLookup()
        self.filter_var = tk.StringVar(value="")
        
        # Import collectors configuration
        self.get_collectors_by_region = get_collectors_by_region
        self.get_all_regions = get_all_regions
        self.get_collector_location = get_collector_location
        
        # Initialize BGP Monitor with database support enabled
        try:
            self.bgp_monitor = BGPMonitor(use_db=True)
            logging.info("BGP Monitor initialized with database support")
        except Exception as e:
            logging.warning(f"Failed to initialize BGP Monitor with database: {e}")
            self.bgp_monitor = BGPMonitor(use_db=False)
            messagebox.showwarning("Database Connection", "Failed to initialize database connection. Some features may be unavailable.")
        
        # Initialize variables
        self.selected_collectors = set()
        self.is_monitoring = False
        self.monitor_thread = None
        self.current_data_file = None
        self.connection_manager = None
        
        # Create the GUI components
        self.create_control_panel()
        self.create_security_panel()
        
        # Set default region if available
        if self.get_all_regions():
            self.region_var.set(self.settings.get("region", self.get_all_regions()[0]))
            self.update_collectors()
        
        # Create status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief="sunken", padding=(5, 2))
        self.status_bar.pack(side="bottom", fill="x")
        
        # Add Neo4j Connection Status LED with IP and DB info
        self.db_status_led = tk.Label(root, text="DB: Disconnected", bg="red", fg="white", width=40)
        self.db_status_led.pack(side=tk.BOTTOM, pady=5)
        
        # Add Connect DB button
        self.connect_db_button = tk.Button(root, text="Connect DB", command=self.open_db_config_window, width=15)
        self.connect_db_button.pack(side=tk.BOTTOM, pady=5)
        
        # Add a label to display the count of Update entries
        self.entries_label = tk.Label(root, text="Entry Count: 0", bg="white", fg="black", width=30)
        self.entries_label.pack(side=tk.BOTTOM, pady=5)
        
        # Start initial checks
        self.check_db_connection()
        self.update_entries_count()
        
        # Load recent alerts
        self.load_recent_alerts()

    def create_control_panel(self):
        """Create the control panel with filters and buttons."""
        control_panel = ttk.LabelFrame(self.left_frame, text="Control Panel", padding="5 5 5 5")
        control_panel.pack(side="left", fill="both", padx=5, pady=5)
        
        # Create AS Number Filtering frame first
        filter_frame = ttk.LabelFrame(control_panel, text="AS Number Filtering", padding="5 5 5 5")
        filter_frame.pack(fill="x", padx=5, pady=5)
        
        # AS Number entry and buttons
        entry_frame = ttk.Frame(filter_frame)
        entry_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Label(entry_frame, text="AS Numbers:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(entry_frame, textvariable=self.filter_var)
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # Filter buttons
        button_frame = ttk.Frame(filter_frame)
        button_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Button(button_frame, text="Add Filter", 
                  command=self.add_as_filter).pack(side="left", padx=2)
        ttk.Button(button_frame, text="Remove Filter", 
                  command=self.remove_as_filter).pack(side="left", padx=2)
        ttk.Button(button_frame, text="Clear All", 
                  command=self.clear_as_filters).pack(side="left", padx=2)
        ttk.Button(button_frame, text="AS Info", 
                  command=self.show_as_info).pack(side="left", padx=2)
        
        # AS Listbox
        self.as_listbox = tk.Listbox(filter_frame, height=10)
        self.as_listbox.pack(fill="both", expand=True, padx=5, pady=2)
        
        # Load saved AS filters
        saved_filters = self.settings.get("as_filters", [])
        for as_filter in saved_filters:
            self.as_listbox.insert(tk.END, as_filter)
        
        # Collector Selection frame
        collector_frame = ttk.LabelFrame(control_panel, text="Collector Selection", padding="5 5 5 5")
        collector_frame.pack(fill="x", padx=5, pady=5)
        
        # Region selection
        region_frame = ttk.Frame(collector_frame)
        region_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Label(region_frame, text="Region:").pack(side="left", padx=5)
        self.region_var = tk.StringVar(value=self.settings.get("region", "Asia Pacific"))
        region_combo = ttk.Combobox(region_frame, textvariable=self.region_var, state="readonly")
        region_combo["values"] = list(self.get_all_regions())
        region_combo.pack(side="left", fill="x", expand=True, padx=5)
        region_combo.bind("<<ComboboxSelected>>", self.update_collectors)
        
        # Collector listbox
        self.collector_listbox = tk.Listbox(collector_frame, height=5, selectmode=tk.MULTIPLE)
        self.collector_listbox.pack(fill="x", padx=5, pady=2)
        
        # Bind selection event to update button state
        self.collector_listbox.bind('<<ListboxSelect>>', self.update_start_button_state)
        
        # Load saved collectors after creating listbox
        self.update_collectors(None)  # Update list for current region
        saved_collectors = self.settings.get("collectors", [])
        if saved_collectors:
            for i, item in enumerate(self.collector_listbox.get(0, tk.END)):
                if item in saved_collectors:
                    self.collector_listbox.selection_set(i)
                    
        # Update start button state after loading saved selections
        self.update_start_button_state()
        
        # Status label for AS lookup
        self.status_label = ttk.Label(filter_frame, text="")
        self.status_label.pack(fill="x", padx=5, pady=2)
        
        # Progress bar for AS lookup
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(filter_frame, mode='determinate', variable=self.progress_var)
        self.progress_bar.pack(fill="x", padx=5, pady=2)
        self.progress_bar.pack_forget()  # Hide initially
        
        # Control buttons at the bottom
        control_button_frame = ttk.Frame(control_panel)
        control_button_frame.pack(fill="x", padx=5, pady=5)
        
        # Create Start Monitoring button (initially disabled)
        self.start_button = ttk.Button(control_button_frame, text="Start Monitoring",
                                     command=self.start_monitoring, state="disabled")
        self.start_button.pack(side="left", padx=5)
        
        # Add a clear log button
        self.clear_log_button = ttk.Button(control_button_frame, text="Clear Log",
                                         command=self.clear_log)
        self.clear_log_button.pack(side="right", padx=5)
        
        # Add Open Data button
        self.open_data_button = ttk.Button(control_button_frame, text="Open Data",
                                         command=self.open_data_folder)
        self.open_data_button.pack(side="right", padx=5)
        
        # Right panel for log display
        right_panel = ttk.Frame(self.left_frame)
        right_panel.pack(side="left", fill="both", expand=True, padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(right_panel, text="BGP Updates")
        log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_security_panel(self):
        """Create the security alerts panel."""
        # Create security frame
        security_frame = ttk.LabelFrame(self.right_frame, text="Security Alerts")
        security_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create alerts treeview
        columns = ("Time", "Severity", "Type", "Details")
        self.alerts_tree = ttk.Treeview(security_frame, columns=columns, show="headings")
        
        # Configure columns
        self.alerts_tree.heading("Time", text="Time")
        self.alerts_tree.heading("Severity", text="Severity")
        self.alerts_tree.heading("Type", text="Type")
        self.alerts_tree.heading("Details", text="Details")
        
        self.alerts_tree.column("Time", width=100)
        self.alerts_tree.column("Severity", width=70)
        self.alerts_tree.column("Type", width=100)
        self.alerts_tree.column("Details", width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(security_frame, orient="vertical", command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)
        
        # Create button frame
        button_frame = ttk.Frame(security_frame)
        button_frame.pack(side="bottom", fill="x", padx=5, pady=5)
        
        # Add export button
        export_button = ttk.Button(button_frame, text="Export Alerts", command=self.export_alerts)
        export_button.pack(side="left", padx=5)
        
        # Pack widgets
        self.alerts_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Configure tag colors
        self.alerts_tree.tag_configure("HIGH", foreground="red")
        self.alerts_tree.tag_configure("MEDIUM", foreground="orange")
        self.alerts_tree.tag_configure("LOW", foreground="blue")
        
    def update_collectors(self, event=None):
        """Update the collectors list based on selected region."""
        region = self.region_var.get()
        self.collector_listbox.delete(0, tk.END)
        
        if region in self.get_all_regions():
            collectors = self.get_collectors_by_region(region)
            for collector_id in collectors:
                location = self.get_collector_location(collector_id)
                self.collector_listbox.insert(tk.END, f"{collector_id} ({location})")
        
        self.save_current_settings()  # Save after updating region

    def update_start_button_state(self, event=None):
        """Update the state of the Start Monitoring button based on collector selection."""
        if not hasattr(self, 'start_button') or not hasattr(self, 'collector_listbox'):
            return
            
        if self.collector_listbox.curselection():
            self.start_button.configure(state="normal")
        else:
            self.start_button.configure(state="disabled")

    def add_as_filter(self):
        """Add AS number to filter list."""
        as_input = self.filter_var.get().strip()
        if not as_input:
            return
            
        # Clean and validate AS numbers
        as_numbers = []
        for asn in as_input.split(','):
            asn = asn.strip().upper()
            # Remove AS prefix if present
            if asn.startswith('AS'):
                asn = asn[2:]
            # Validate it's a number
            if asn.isdigit():
                as_numbers.append(f"AS{asn}")
        
        # Add unique AS numbers to listbox
        for asn in as_numbers:
            # Check if AS number is already in the list
            existing_items = self.as_listbox.get(0, tk.END)
            if asn not in existing_items:
                self.as_listbox.insert(tk.END, asn)
        
        # Clear the entry field
        self.filter_var.set("")
        self.save_current_settings()  # Save after adding filter

    def remove_as_filter(self):
        """Remove selected AS numbers from the filter list."""
        selected_indices = self.as_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select one or more AS numbers to remove.")
            return
            
        # Remove in reverse order to avoid index shifting
        for index in sorted(selected_indices, reverse=True):
            self.as_listbox.delete(index)
        self.save_current_settings()  # Save after removing filter

    def clear_as_filters(self):
        """Clear all AS filters."""
        self.filtered_as_numbers.clear()
        self.filter_var.set("")
        self.update_as_listbox()
        self.log_message("Cleared all AS filters")
        self.save_current_settings()  # Save after clearing filters

    def update_as_listbox(self):
        """Update the AS number listbox with current filters."""
        self.as_listbox.delete(0, tk.END)  # Clear current items
        for asn in sorted(self.filtered_as_numbers):
            self.as_listbox.insert(tk.END, f"AS{asn}")
            
    def start_monitoring(self):
        """Start BGP monitoring."""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.status_var.set("Monitoring started")
        
    def _monitor_loop(self):
        """Main monitoring loop with reconnection logic."""
        retry_delay = 5  # Initial retry delay in seconds
        max_retry_delay = 60  # Maximum retry delay
        
        while self.is_monitoring:
            try:
                # Create new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                # Start monitoring
                self.log_message("Connecting to BGP data feed...")
                loop.run_until_complete(self._monitor_with_reconnect(loop))
                
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
                if self.is_monitoring:  # Only if we haven't stopped monitoring
                    self.log_message(f"Connection error: {e}")
                    self.log_message(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    # Exponential backoff with max delay
                    retry_delay = min(retry_delay * 2, max_retry_delay)
            finally:
                try:
                    loop.close()
                except:
                    pass
                    
    async def _monitor_with_reconnect(self, loop):
        """Monitor BGP updates with automatic reconnection."""
        while self.is_monitoring:
            try:
                # Get selected collectors
                collectors = [item[0] for item in self.collectors_tree.selection()]
                if not collectors:
                    self.log_message("No collectors selected")
                    return
                    
                # Start monitoring with keepalive settings
                await self.bgp_monitor.monitor_updates(
                    collectors=collectors,
                    callback=self.process_update,
                    keepalive_interval=30,  # Send keepalive every 30 seconds
                    keepalive_timeout=35    # Allow 35 seconds for keepalive response
                )
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.is_monitoring:  # Only log if we haven't stopped monitoring
                    logging.error(f"WebSocket error: {e}")
                    self.log_message(f"Connection lost: {e}")
                    self.log_message("Attempting to reconnect...")
                    await asyncio.sleep(5)  # Wait before reconnecting
                else:
                    break
                    
    def stop_monitoring(self):
        """Stop BGP monitoring."""
        if not self.is_monitoring:
            return
            
        self.is_monitoring = False
        if self.monitor_thread:
            self.bgp_monitor.stop_monitoring()
            self.monitor_thread.join(timeout=5)
            self.monitor_thread = None
            
        self.status_var.set("Monitoring stopped")
        
    def log_message(self, message):
        """Add message to log in a thread-safe way."""
        if not isinstance(message, str):
            message = str(message)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def update_status(self, message):
        """Update status label in a thread-safe way."""
        self.status_var.set(message)

    def clear_log(self):
        """Clear the log display."""
        self.log_text.delete(1.0, tk.END)

    def open_data_folder(self):
        """Open the data folder in the system's file explorer."""
        if self.data_manager:
            data_path = str(self.data_manager.base_dir.absolute())
            try:
                if os.name == 'nt':  # Windows
                    subprocess.run(['explorer', data_path], check=True)
                else:  # Linux/Mac
                    subprocess.run(['xdg-open', data_path], check=True)
                self.log_message(f"Opening data folder: {data_path}")
            except subprocess.SubprocessError as e:
                self.log_message(f"Error opening data folder: {str(e)}")
        else:
            self.log_message("Data manager not initialized")

    def save_current_settings(self):
        """Save current settings to configuration file."""
        current_settings = {
            "region": self.region_var.get() if hasattr(self, 'region_var') else "",
            "collectors": [],
            "as_filters": []
        }
        
        # Save collectors if listbox exists and has selections
        if hasattr(self, 'collector_listbox'):
            selected = self.collector_listbox.curselection()
            current_settings["collectors"] = [self.collector_listbox.get(i) for i in selected] if selected else []
            
        # Save AS filters if listbox exists
        if hasattr(self, 'as_listbox'):
            current_settings["as_filters"] = list(self.as_listbox.get(0, tk.END))
            
        self.config_manager.save_settings(current_settings)

    def on_closing(self):
        """Handle window closing."""
        try:
            self.stop_monitoring()
        finally:
            self.root.quit()
            self.root.destroy()

    def show_as_info(self):
        """Show information about AS numbers from either selection or entry field."""
        as_numbers = []
        
        # First check if there's any input in the entry field
        as_input = self.filter_var.get().strip()
        if as_input:
            # Parse AS numbers from input
            for asn in as_input.split(','):
                asn = asn.strip().upper()
                # Remove AS prefix if present
                if asn.startswith('AS'):
                    asn = asn[2:]
                # Validate it's a number
                if asn.isdigit():
                    as_numbers.append(asn)
        else:
            # If no input, check listbox selection
            selected_indices = self.as_listbox.curselection()
            if selected_indices:
                for index in selected_indices:
                    as_text = self.as_listbox.get(index)
                    match = re.match(r'AS(\d+)', as_text)
                    if match:
                        as_numbers.append(match.group(1))
        
        if not as_numbers:
            messagebox.showwarning("No Selection", "Please enter an AS number or select one from the list.")
            return
            
        # Show progress bar and reset it
        self.progress_bar.pack(fill="x", padx=5, pady=2)
        self.progress_var.set(0)
        total_as = len(as_numbers)
        
        results = {}
        for i, asn in enumerate(as_numbers, 1):
            # Update status and progress
            self.status_label.config(text=f"Looking up AS{asn}...")
            self.progress_var.set((i / total_as) * 100)
            self.root.update()  # Force GUI update
            
            try:
                result = self.as_lookup.get_as_info(asn)
                results[asn] = result
            except Exception as e:
                results[asn] = {"error": str(e)}
        
        # Hide progress bar and clear status
        self.progress_bar.pack_forget()
        self.status_label.config(text="")
        
        # Show results in a formatted dialog
        result_text = ""
        for asn, info in results.items():
            result_text += f"\nAS{asn}:\n"
            result_text += "=" * (len(asn) + 3) + "\n"
            if info:
                if "error" in info:
                    result_text += f"Error: {info['error']}\n"
                else:
                    result_text += f"Source: {info.get('source', 'N/A')}\n"
                    result_text += f"Name: {info.get('name', 'N/A')}\n"
                    
                    if info.get('description'):
                        result_text += f"Description: {info['description']}\n"
                    
                    # Network Information
                    if info.get('info_type') or info.get('info_scope'):
                        result_text += "\nNetwork Information:\n"
                        result_text += f"Type: {info.get('info_type', 'N/A')}\n"
                        result_text += f"Scope: {info.get('info_scope', 'N/A')}\n"
                        if info.get('traffic_levels'):
                            result_text += f"Traffic Levels: {info['traffic_levels']}\n"
                    
                    # Location Information
                    if any(info.get(k) for k in ['country', 'city', 'state']):
                        result_text += "\nLocation:\n"
                        if info.get('country'):
                            result_text += f"Country: {info['country']}\n"
                        if info.get('city'):
                            result_text += f"City: {info['city']}\n"
                        if info.get('state'):
                            result_text += f"State: {info['state']}\n"
                    
                    # Peering Policy
                    if any(info.get(k) for k in ['policy_general', 'policy_locations', 'policy_ratio']):
                        result_text += "\nPeering Policy:\n"
                        if info.get('policy_general'):
                            result_text += f"General: {info['policy_general']}\n"
                        if info.get('policy_locations'):
                            result_text += f"Locations: {info['policy_locations']}\n"
                        if 'policy_ratio' in info:
                            result_text += f"Ratio Required: {'Yes' if info['policy_ratio'] else 'No'}\n"
                    
                    # Contact Information
                    if info.get('website'):
                        result_text += f"\nWebsite: {info['website']}\n"
                    
                    # Cache Information
                    if info.get('timestamp'):
                        cache_time = datetime.fromtimestamp(info['timestamp'])
                        result_text += f"\nCache Timestamp: {cache_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            else:
                result_text += "No information found\n"
            
            result_text += "\n" + "=" * 50 + "\n"
        
        # Create a custom dialog with a scrollable text area
        dialog = tk.Toplevel(self.root)
        dialog.title("AS Information")
        dialog.geometry("500x400")
        
        # Make dialog modal
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Add scrolled text widget
        text_widget = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
        text_widget.pack(expand=True, fill="both", padx=10, pady=10)
        text_widget.insert("1.0", result_text.strip())
        text_widget.config(state="disabled")  # Make read-only
        
        # Add close button
        close_button = ttk.Button(dialog, text="Close", command=dialog.destroy)
        close_button.pack(pady=5)
        
        # Center the dialog on the parent window
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

    def show_about(self):
        """Show information about the application and author."""
        about_text = """BGP Monitor

Version: 1.0.0
Release Date: January 2025

Author Information:
-----------------
Name: Amit Bhatnagar
Email: Amit.Bhatnagar@outlook.com
Website: 
GitHub: https://github.com/bamit99

For commercial licensing and support:
Amit.Bhatnagar@outlook.com

This application is licensed under CC BY-NC 4.0. Commercial use requires explicit permission.
 2025 All Rights Reserved."""

        # Create about dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("About BGP Monitor")
        dialog.geometry("400x450")
        
        # Make dialog modal
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Add application icon/logo if exists
        try:
            logo_label = ttk.Label(dialog, text="BGP\nMonitor", font=("Arial", 16, "bold"))
            logo_label.pack(pady=10)
        except Exception:
            pass
        
        # Add scrolled text widget
        text_widget = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, height=15)
        text_widget.pack(expand=True, fill="both", padx=10, pady=10)
        text_widget.insert("1.0", about_text)
        text_widget.config(state="disabled")  # Make read-only
        
        # Add buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        def open_license():
            """Open license file."""
            license_path = Path("LICENSE")
            if license_path.exists():
                with open(license_path, 'r') as f:
                    license_text = f.read()
                    
                # Create license dialog
                license_dialog = tk.Toplevel(dialog)
                license_dialog.title("License")
                license_dialog.geometry("600x400")
                
                # Add scrolled text widget
                license_text_widget = scrolledtext.ScrolledText(license_dialog, wrap=tk.WORD)
                license_text_widget.pack(expand=True, fill="both", padx=10, pady=10)
                license_text_widget.insert("1.0", license_text)
                license_text_widget.config(state="disabled")
                
                # Add close button
                ttk.Button(license_dialog, text="Close", 
                          command=license_dialog.destroy).pack(pady=5)
        
        ttk.Button(button_frame, text="View License", 
                  command=open_license).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Close", 
                  command=dialog.destroy).pack(side="right", padx=5)
        
        # Center the dialog on the parent window
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

    async def process_update(self, message):
        """Process BGP update message."""
        try:
            if not message or not isinstance(message, dict):
                return
            
            data = message.get("data", {})
            if not data:
                return
                
            # Get list of AS numbers from the listbox for filtering
            as_filters = set()
            for i in range(self.as_listbox.size()):
                as_text = self.as_listbox.get(i)
                match = re.match(r'AS(\d+)', as_text)
                if match:
                    as_filters.add(match.group(1))
                    
            # Extract message components
            timestamp = datetime.fromtimestamp(data.get("timestamp", 0))
            peer = data.get("peer", "")
            peer_asn = data.get("peer_asn", "")
            path = data.get("path", [])
            communities = data.get("communities", [])
            
            # Convert path to strings for comparison
            path_str = [str(asn) for asn in path]
            
            # If there are AS filters, check if any filtered AS is in the path
            if as_filters and not any(str(asn) in path_str for asn in as_filters):
                return  # Skip if no filtered AS in path
                
            # Get prefix from either withdrawals or announcements
            prefix = None
            update_type = None
            if "withdrawals" in data and data["withdrawals"]:
                prefix = data["withdrawals"][0]
                update_type = "withdrawal"
            elif "announcements" in data:
                for announcement in data["announcements"]:
                    if "prefixes" in announcement and announcement["prefixes"]:
                        prefix = announcement["prefixes"][0]
                        update_type = "announcement"
                        break
            
            if not prefix:
                return
                
            # Format message for display
            message = f"Type: {update_type.capitalize()}, Prefix: {prefix}, Peer: {peer} (AS{peer_asn}), Path: {' > '.join(map(str, path))}"
            if communities:
                message += f", Communities: {communities}"
            
            # Add to log
            self.log_message(message)
            
            # Store in database if available
            if self.bgp_monitor and self.bgp_monitor.db_manager:
                try:
                    self.bgp_monitor.db_manager.store_bgp_update(
                        timestamp=timestamp,
                        collector=data.get("collector", "unknown"),
                        peer_asn=peer_asn,
                        prefix=prefix,
                        as_path=",".join(map(str, path)) if path else None,
                        communities=communities,
                        update_type=update_type
                    )
                    # Update entry count immediately after storing
                    self.update_entries_count()
                    
                    # Check for security issues
                    from utils.security_analyzer import check_suspicious_patterns
                    alert = check_suspicious_patterns(
                        timestamp=timestamp,
                        prefix=prefix,
                        as_path=",".join(map(str, path)) if path else None,
                        peer_asn=peer_asn,
                        prefix_history=self.bgp_monitor.db_manager.get_prefix_history(prefix),
                        db_manager=self.bgp_monitor.db_manager
                    )
                    
                    # Add alert to security panel if suspicious
                    if alert:
                        self.add_security_alert(alert)
                        
                except Exception as e:
                    logging.error(f"Failed to store update in database: {e}")
            
        except Exception as e:
            logging.error(f"Error processing update: {e}")

    def update_db_status_led(self, connected, status_text=None):
        """Update the database status LED and text."""
        if status_text is None:
            status_text = "DB: Connected" if connected else "DB: Disconnected"
            
        self.db_status_led.config(
            text=status_text,
            bg="green" if connected else "red",
            fg="white"
        )
        
        # Enable/disable DB-dependent features
        if hasattr(self, 'connect_db_button'):
            self.connect_db_button.config(
                text="Disconnect DB" if connected else "Connect DB"
            )

    def check_db_connection(self):
        """Check database connection status and update UI accordingly."""
        try:
            # First check if BGP Monitor has database support
            if not hasattr(self.bgp_monitor, 'db_manager') or self.bgp_monitor.db_manager is None:
                connected = False
                status_text = "DB: Disabled"
            else:
                # Then check actual connection
                connected = db_config.check_connection()
                status_text = f"DB: Connected to {db_config.NEO4J_CONFIG['uri']}" if connected else "DB: Connection Failed"
                
        except Exception as e:
            connected = False
            status_text = f"DB: Error ({str(e)})"
            logging.error(f"Database connection check failed: {e}")
            
        # Update UI
        self.update_db_status_led(connected, status_text)
        
        # Schedule next check
        self.root.after(5000, self.check_db_connection)

    def update_entries_count(self):
        """Query the database for the count of 'BGPUpdate' nodes and update the label."""
        try:
            # First check if db_manager is available
            if not self.bgp_monitor.db_manager:
                self.entries_label.config(text="Entry Count: N/A (No DB)")
                return
                
            from config.database_config import NEO4J_CONFIG
            from neo4j import GraphDatabase
            uri = NEO4J_CONFIG.get("uri")
            username = NEO4J_CONFIG.get("username")
            password = NEO4J_CONFIG.get("password")
            if not uri or not username or not password:
                self.entries_label.config(text="Entry Count: N/A")
                return
            driver = GraphDatabase.driver(uri, auth=(username, password))
            with driver.session() as session:
                result = session.run("MATCH (u:BGPUpdate) RETURN count(u) AS count")
                record = result.single()
                count = record.get("count") if record else 0
            driver.close()
            self.entries_label.config(text=f"Entry Count: {count}")
        except Exception as e:
            self.entries_label.config(text="Entry Count: Error")
            print(f"Error updating entry count: {e}")
        finally:
            # Schedule next update in 5 seconds (5000 milliseconds)
            self.root.after(5000, self.update_entries_count)

    def open_db_config_window(self):
        """Handle database connection/disconnection."""
        # If already connected, disconnect
        if self.connect_db_button.cget('text') == "Disconnect DB":
            # Reinitialize BGP Monitor without database
            self.bgp_monitor = BGPMonitor(use_db=False)
            logging.info("Disconnected from database")
            self.update_db_status_led(False, "DB: Disconnected")
            return

        # If not connected, show configuration window
        self.db_config_win = tk.Toplevel(self.root)
        self.db_config_win.title("Configure Neo4j Connection")
        self.db_config_win.geometry("400x200")
        
        # Get current config
        current_config = db_config.NEO4J_CONFIG
        
        # Create and pack widgets with current values
        ttk.Label(self.db_config_win, text="Neo4j URI:").pack(pady=5)
        uri_entry = ttk.Entry(self.db_config_win, width=40)
        uri_entry.insert(0, current_config.get('uri', ''))
        uri_entry.pack(pady=5)
        
        ttk.Label(self.db_config_win, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(self.db_config_win, width=40)
        username_entry.insert(0, current_config.get('username', ''))
        username_entry.pack(pady=5)
        
        ttk.Label(self.db_config_win, text="Password:").pack(pady=5)
        password_entry = ttk.Entry(self.db_config_win, width=40, show="*")
        password_entry.insert(0, current_config.get('password', ''))
        password_entry.pack(pady=5)
        
        # Save button
        save_button = ttk.Button(
            self.db_config_win,
            text="Save and Connect",
            command=lambda: self.save_db_config(
                uri_entry.get(),
                username_entry.get(),
                password_entry.get()
            )
        )
        save_button.pack(pady=20)

    def save_db_config(self, uri, username, password):
        """Save database configuration."""
        # Build configuration dictionary
        config_data = {
            "uri": uri,
            "username": username,
            "password": password
        }

        try:
            # Update Neo4j configuration using the config manager
            if db_config.update_neo4j_config(uri=uri, username=username, password=password):
                # Try to connect with new settings
                connected = db_config.check_connection()
                self.update_db_status_led(connected)
                
                if connected:
                    # Stop the current BGP Monitor if it's running
                    if self.is_monitoring:
                        self.stop_monitoring()
                    
                    # Clean up old BGP Monitor
                    if hasattr(self, 'bgp_monitor'):
                        # Stop any active connections
                        if hasattr(self.bgp_monitor, 'connection_manager') and self.bgp_monitor.connection_manager:
                            self.bgp_monitor.connection_manager.stop()
                    
                    # Reinitialize BGP Monitor with database support
                    self.bgp_monitor = BGPMonitor(use_db=True)
                    logging.info("Reinitialized BGP Monitor with new database configuration")
                
                self.db_config_win.destroy()
            else:
                raise Exception("Failed to update configuration")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

    def add_security_alert(self, alert):
        """Add a security alert to the alerts panel and database."""
        if not alert:
            return
            
        # Log alert to both CSV and database
        self.alert_logger.log_alert(alert, self.bgp_monitor.db_manager if self.bgp_monitor else None)
            
        timestamp = alert.get("timestamp", datetime.now()).strftime("%H:%M:%S")
        severity = alert.get("severity", "LOW")
        
        # Determine alert type
        alert_type = "Unknown"
        if "RPKI Invalid" in str(alert.get("reasons", [])):
            alert_type = "RPKI Invalid"
        elif "hijack" in str(alert.get("reasons", [])).lower():
            alert_type = "Possible Hijack"
        elif "leak" in str(alert.get("reasons", [])).lower():
            alert_type = "Route Leak"
        elif "prepending" in str(alert.get("reasons", [])).lower():
            alert_type = "Path Manipulation"
        
        # Format details
        details = "; ".join(alert.get("reasons", []))
        if len(details) > 100:
            details = details[:97] + "..."
        
        # Insert at top of tree with appropriate tag
        self.alerts_tree.insert("", 0, values=(timestamp, severity, alert_type, details), tags=(severity,))
        
        # Keep only last 100 alerts in tree
        if len(self.alerts_tree.get_children()) > 100:
            self.alerts_tree.delete(self.alerts_tree.get_children()[-1])

    def load_recent_alerts(self):
        """Load recent alerts from database into the alerts panel."""
        if not self.bgp_monitor or not self.bgp_monitor.db_manager:
            return
            
        alerts = self.bgp_monitor.db_manager.get_recent_alerts()
        for alert in alerts:
            self.add_security_alert(alert)

    def export_alerts(self):
        """Export security alerts to CSV file."""
        if not self.bgp_monitor or not self.bgp_monitor.db_manager:
            messagebox.showerror("Error", "Database connection required to export alerts")
            return
            
        try:
            # Get file path from user
            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                title="Export Security Alerts"
            )
            
            if not filepath:  # User cancelled
                return
                
            # Export alerts
            if self.bgp_monitor.db_manager.export_alerts_to_csv(filepath):
                messagebox.showinfo("Success", f"Alerts exported to {filepath}")
            else:
                messagebox.showerror("Error", "Failed to export alerts")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export alerts: {str(e)}")

def main():
    root = tk.Tk()
    app = BGPMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()

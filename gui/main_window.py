"""Main GUI window for BGP Monitor."""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
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

class BGPMonitorGUI:
    def __init__(self, root):
        """Initialize the GUI."""
        self.root = root
        self.root.title("BGP Monitor")
        self.root.geometry("800x600")
        
        # Initialize configuration manager
        self.config_manager = ConfigManager()
        self.settings = self.config_manager.load_settings()
        
        # Create main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.filtered_as_numbers = set()  # Initialize before creating panels
        self.data_manager = DataManager("data")
        self.as_lookup = ASLookup()
        self.filter_var = tk.StringVar(value="")  # Initialize filter variable
        
        # Import collectors configuration
        self.get_collectors_by_region = get_collectors_by_region
        self.get_all_regions = get_all_regions
        self.get_collector_location = get_collector_location
        
        # Initialize BGP Monitor
        self.bgp_monitor = BGPMonitor()
        
        # Initialize variables
        self.selected_collectors = set()
        self.is_monitoring = False
        self.monitor_thread = None
        self.current_data_file = None
        self.connection_manager = None
        
        # Create the GUI
        self.create_control_panel()
        
        # Set default region if available
        if self.get_all_regions():
            self.region_var.set(self.settings.get("region", self.get_all_regions()[0]))
            self.update_collectors()  # Will call with None event
        
        # Create status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief="sunken", padding=(5, 2))
        self.status_bar.pack(side="bottom", fill="x")
        
        # Create About button at the bottom
        about_frame = ttk.Frame(root)
        about_frame.pack(side="bottom", fill="x", padx=5, pady=(0, 5))
        about_button = ttk.Button(about_frame, text="About", command=self.show_about, width=10)
        about_button.pack(side="left", padx=5)

    def create_control_panel(self):
        """Create the control panel with filters and buttons."""
        control_panel = ttk.LabelFrame(self.main_frame, text="Control Panel", padding="5 5 5 5")
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
                                     command=self.toggle_monitoring, state="disabled")
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
        right_panel = ttk.Frame(self.main_frame)
        right_panel.pack(side="left", fill="both", expand=True, padx=5)
        
        # Log display
        log_frame = ttk.LabelFrame(right_panel, text="BGP Updates")
        log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

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
            
    def toggle_monitoring(self):
        """Start or stop BGP monitoring."""
        if not self.is_monitoring:
            # Start monitoring
            self.is_monitoring = True
            self.start_button.config(text="Stop Monitoring")
            self.update_status("Starting BGP monitoring...")
            
            # Create and start monitor thread
            self.monitor_thread = threading.Thread(target=self._run_monitoring_loop)
            self.monitor_thread.daemon = True  # Thread will be killed when main thread exits
            self.monitor_thread.start()
            
        else:
            # Stop monitoring
            self.stop_monitoring()

    def _run_monitoring_loop(self):
        """Run the monitoring loop in a separate thread."""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run the monitoring
            loop.run_until_complete(self.start_monitoring())
            
        except Exception as e:
            self.log_message(f"Error in monitoring: {e}")
        finally:
            # Schedule stop_monitoring to run in the main thread
            self.root.after(0, self.stop_monitoring)
            try:
                # Cancel all remaining tasks
                for task in asyncio.all_tasks(loop):
                    task.cancel()
                # Run loop one last time to clean up
                loop.run_until_complete(asyncio.sleep(0))
            except Exception as e:
                logging.error(f"Error cleaning up loop: {e}")
            finally:
                loop.close()

    async def start_monitoring(self):
        """Start BGP monitoring."""
        try:
            # Get selected collectors
            selected_indices = self.collector_listbox.curselection()
            if not selected_indices:
                self.log_message("Please select at least one collector")
                return
            
            selected_collectors = [self.collector_listbox.get(i).split()[0] for i in selected_indices]
            
            # Initialize connection manager with callback
            self.connection_manager = ConnectionManager(self.process_update)
            
            # Connect to RIPE RIS
            if not await self.connection_manager.connect():
                self.log_message("Failed to connect to RIPE RIS")
                return
            
            # Subscribe to selected collectors
            for collector in selected_collectors:
                if await self.connection_manager.subscribe(collector):
                    self.log_message(f" Subscribed to {collector}")
                else:
                    self.log_message(f" Failed to subscribe to {collector}")
            
            # Start listening for updates
            self.log_message("Listening for BGP updates...")
            await self.connection_manager.listen()
            
        except Exception as e:
            self.log_message(f"Error in monitoring: {e}")
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop BGP monitoring."""
        if self.is_monitoring:
            self.is_monitoring = False
            self.start_button.config(text="Start Monitoring")
            self.update_status("Stopping monitoring...")
            
            # Stop the connection manager first
            if self.connection_manager:
                try:
                    self.connection_manager.stop()
                except Exception as e:
                    logging.error(f"Error stopping connection manager: {e}")
                finally:
                    self.connection_manager = None
            
            # Wait for monitor thread to finish
            if self.monitor_thread and self.monitor_thread.is_alive():
                try:
                    self.monitor_thread.join(timeout=2.0)  # Wait up to 2 seconds
                    if self.monitor_thread.is_alive():
                        logging.warning("Monitor thread did not stop cleanly")
                except Exception as e:
                    logging.error(f"Error joining monitor thread: {e}")
                finally:
                    self.monitor_thread = None
            
            self.update_status("Monitoring stopped")
            self.log_message("✓ Monitoring stopped")

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
            # Parse message if it's a string, otherwise use as is
            if isinstance(message, str):
                data = json.loads(message)
            else:
                data = message

            if 'type' in data and data['type'] == 'ris_message':
                update = data['data']
                
                # Get list of AS numbers from the listbox
                as_filters = set()
                for i in range(self.as_listbox.size()):
                    as_text = self.as_listbox.get(i)
                    match = re.match(r'AS(\d+)', as_text)
                    if match:
                        as_filters.add(match.group(1))
                
                # If there are AS filters, check if the update matches any
                if as_filters:
                    # Extract AS path from the update
                    as_path = []
                    if 'path' in update:
                        as_path = [str(asn) for asn in update['path']]
                    
                    # Skip if none of the filtered AS numbers are in the path
                    if not any(asn in as_path for asn in as_filters):
                        return
                
                # Format timestamp
                timestamp = datetime.fromtimestamp(update.get('timestamp', 0))
                collector = update.get('host', 'unknown')
                peer_asn = update.get('peer_asn', '')
                
                # Process announcements
                if update.get('announcements'):
                    # Get AS path and communities
                    as_path = update.get('path', [])  # Keep as list, db_manager will handle conversion
                    communities = update.get('community', [])  # Keep as list, db_manager will handle conversion
                    
                    for announcement in update['announcements']:
                        next_hop = announcement.get('next_hop', '')
                        prefixes = announcement.get('prefixes', [])
                        if not prefixes:
                            prefix = announcement.get('prefix')
                            if prefix:
                                prefixes = [prefix]
                        
                        for prefix in prefixes:
                            if not prefix:
                                continue
                            
                            # Store in Neo4j
                            try:
                                self.bgp_monitor.db_manager.store_bgp_update(
                                    timestamp=timestamp,
                                    collector=collector,
                                    peer_asn=peer_asn,
                                    prefix=prefix,
                                    as_path=as_path,
                                    next_hop=next_hop,
                                    communities=communities,
                                    update_type="announcement"
                                )
                            except Exception as e:
                                self.log_message(f"Error storing announcement: {e}")
                
                # Process withdrawals
                if update.get('withdrawals'):
                    for prefix in update['withdrawals']:
                        try:
                            # Store withdrawal in Neo4j
                            self.bgp_monitor.db_manager.store_bgp_update(
                                timestamp=timestamp,
                                collector=collector,
                                peer_asn=peer_asn,
                                prefix=prefix,
                                update_type="withdrawal"
                            )
                        except Exception as e:
                            self.log_message(f"Error storing withdrawal: {e}")
                
                # Create log message for display
                formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                peer = f"{update.get('peer', 'N/A')} (AS{peer_asn})"
                path = ' > '.join(str(asn) for asn in update.get('path', []))
                
                # Get prefixes for display
                prefixes = []
                if update.get('announcements'):
                    for announcement in update['announcements']:
                        if announcement.get('prefixes'):
                            prefixes.extend(announcement['prefixes'])
                        elif announcement.get('prefix'):
                            prefixes.append(announcement['prefix'])
                
                log_msg = (
                    f"{formatted_time} - "
                    f"Type: {'Announcement' if update.get('announcements') else 'Withdrawal'}, "
                    f"Prefix: {', '.join(prefixes) if prefixes else 'N/A'}, "
                    f"Peer: {peer}, "
                    f"Path: {path}"
                )
                
                # Add withdrawals to log message if any
                if update.get('withdrawals'):
                    withdrawals = ', '.join(update['withdrawals'])
                    log_msg += f"\nWithdrawals: {withdrawals}"
                
                self.log_message(log_msg)
                
                # Save to file if data manager is initialized
                if self.data_manager:
                    self.data_manager.save_update(update)
                    
        except json.JSONDecodeError:
            self.log_message("Error: Invalid message format")
        except Exception as e:
            self.log_message(f"Error processing message: {str(e)}")

def main():
    root = tk.Tk()
    app = BGPMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()

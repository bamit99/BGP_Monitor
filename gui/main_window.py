"""Main GUI window for BGP Monitor."""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import threading
from datetime import datetime
from src.bgp_monitor import BGPMonitor
from src.connection_manager import ConnectionManager
from utils.data_manager import DataManager
# from utils.analysis import BGPAnalyzer # BGPAnalyzer seems unused in this file
from utils.as_lookup import ASLookup
import logging # Import the logging module
from config.collectors import get_collectors_by_region, get_all_regions, get_collector_location
import json
import re
import os
import subprocess
from pathlib import Path
from utils.config_manager import config_manager # Use the shared instance
import logging
# Import the BGPDatabaseManager class directly from the correct module
from utils.db_manager import BGPDatabaseManager
# Keep the import for NEO4J_CONFIG if it's used elsewhere, or remove if not needed
import config.database_config as db_config_module
from utils.security_analyzer import SecurityAlertLogger, get_origin_as, check_suspicious_patterns # Import necessary functions
from utils.episode_manager import get_episode_manager # Import episode manager factory
from utils.security_analyzer import RPKIValidator # Import RPKIValidator
import time

class BGPMonitorGUI:
    # Attributes for sorting alerts treeview
    _alerts_sort_col = "Timestamp"
    _alerts_sort_reverse = False
    def __init__(self, root):
        """Initialize the GUI."""
        self.root = root
        self.root.title("BGP Monitor")
        self.root.geometry("1000x800")  # Increased width for security panel

        # Initial App Log Message
        # Note: app_log_text widget doesn't exist yet, log later in init

        # --- Menu Bar ---
        self.menu_bar = tk.Menu(root)
        root.config(menu=self.menu_bar)

        # Help Menu
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About BGP Monitor", command=self.show_about)
        # --- End Menu Bar ---

        # Initialize configuration manager
        # Use the shared config_manager instance
        self.config_manager = config_manager
        self.gui_settings = self.config_manager.load_gui_settings() # Load GUI specific settings
        self.app_settings = self.config_manager.load_app_settings() # Load app settings (incl. logging)

        # Moved alert_logger initialization down

        # Create main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Create a PanedWindow to manage left and right frames
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill="both", expand=True)

        # Create left and right frames (add them to the PanedWindow)
        self.left_frame = ttk.Frame(self.paned_window, padding=5)
        self.paned_window.add(self.left_frame, weight=1) # Add left frame with weight

        # Create right frame which will contain a notebook
        self.right_frame = ttk.Frame(self.paned_window, padding=5)
        self.paned_window.add(self.right_frame, weight=2) # Give right frame more initial weight

        # Create the Notebook widget within the right frame
        self.notebook = ttk.Notebook(self.right_frame)
        self.notebook.pack(fill="both", expand=True)

        # Create frames for each tab
        self.alerts_tab_frame = ttk.Frame(self.notebook)
        self.episodes_tab_frame = ttk.Frame(self.notebook)
        self.app_log_tab_frame = ttk.Frame(self.notebook) # Frame for application log

        self.notebook.add(self.alerts_tab_frame, text='Security Alerts')
        self.notebook.add(self.episodes_tab_frame, text='Episodes')
        self.notebook.add(self.app_log_tab_frame, text='Application Log')

        # --- Create Application Log Panel ---
        app_log_frame = ttk.LabelFrame(self.app_log_tab_frame, text="Application Log")
        app_log_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.app_log_text = scrolledtext.ScrolledText(app_log_frame, wrap=tk.WORD, height=15) # Use self.
        self.app_log_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.app_log_text.config(state=tk.DISABLED) # Make read-only initially
        # ------------------------------------

        self.filtered_as_numbers = set()
        self.data_manager = DataManager("data")
        self.as_lookup = ASLookup()
        self.filter_var = tk.StringVar(value="")
        self.prefix_origin_cache = {} # Cache for last seen origin AS per prefix
        self.MAX_PREFIX_CACHE_SIZE = 100000 # Simple size limit for the cache

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

        # Initialize Episode Manager (pass db_manager if available)
        self.episode_manager = get_episode_manager(db_manager=self.bgp_monitor.db_manager)

        # Initialize RPKI Validator instance for the GUI
        self.rpki_validator = RPKIValidator()

        # Initialize security alert logger (NOW we have episode_manager)
        self.alert_logger = SecurityAlertLogger(episode_manager=self.episode_manager)

        # Initialize variables
        self.selected_collectors = set()
        self.is_monitoring = False
        self.monitor_thread = None
        self.current_data_file = None
        self.connection_manager = None

        # Create the GUI components
        self.create_control_panel()
        self.create_security_panel() # Creates the alerts tab content
        self.create_episodes_panel() # Creates the episodes tab content

        # Set default region if available
        if self.get_all_regions():
            self.region_var.set(self.gui_settings.get("region", self.get_all_regions()[0]))
            self.update_collectors()

        # Create status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief="sunken", padding=(5, 2))
        self.status_bar.pack(side="bottom", fill="x")

        # Add Neo4j Connection Status LED with IP and DB info
        self.db_status_led = tk.Label(root, text="DB: Disconnected", bg="red", fg="white", width=40)
        self.db_status_led.pack(side=tk.BOTTOM, pady=5)

        # --- Configuration Buttons ---
        config_button_frame = ttk.Frame(root)
        config_button_frame.pack(side=tk.BOTTOM, pady=5)

        # Add Connect DB button
        self.connect_db_button = tk.Button(config_button_frame, text="Connect DB", command=self.open_db_config_window, width=15)
        self.connect_db_button.pack(side=tk.LEFT, padx=5)

        # Add Syslog Settings button
        self.syslog_button = tk.Button(config_button_frame, text="Syslog Settings", command=self.open_syslog_config_window, width=15)
        self.syslog_button.pack(side=tk.LEFT, padx=5)

        # Add RPKI Settings button
        self.rpki_button = tk.Button(config_button_frame, text="RPKI Settings", command=self.open_rpki_config_window, width=15)
        self.rpki_button.pack(side=tk.LEFT, padx=5)
        # ---------------------------

        # Add a label to display the count of Update entries
        self.entries_label = tk.Label(root, text="Entry Count: 0", bg="white", fg="black", width=30)
        self.entries_label.pack(side=tk.BOTTOM, pady=5)

        # Start initial checks
        self.check_db_connection()
        self.update_entries_count()

        # Load recent alerts
        self.load_recent_alerts()

        # Schedule periodic episode cleanup (e.g., every hour = 3600000 ms)
        self._schedule_episode_cleanup()

        # Initial population of episodes display
        self.refresh_episodes_display()

        # Log GUI initialization complete
        self.log_app_message("GUI Initialized Successfully.")

    def _schedule_episode_cleanup(self):
        """Handles the periodic execution of episode cleanup."""
        try:
            if self.episode_manager:
                logging.info("Running periodic episode cleanup...")
                self.episode_manager.cleanup_old_episodes()
        except Exception as e:
            logging.error(f"Error during scheduled episode cleanup: {e}")
        finally:
            # Reschedule itself (e.g., every 60 minutes)
            cleanup_interval_ms = 60 * 60 * 1000 # 1 hour
            self.root.after(cleanup_interval_ms, self._schedule_episode_cleanup)


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
        saved_filters = self.gui_settings.get("as_filters", [])
        for as_filter in saved_filters:
            self.as_listbox.insert(tk.END, as_filter)

        # Collector Selection frame
        collector_frame = ttk.LabelFrame(control_panel, text="Collector Selection", padding="5 5 5 5")
        collector_frame.pack(fill="x", padx=5, pady=5)

        # Region selection
        region_frame = ttk.Frame(collector_frame)
        region_frame.pack(fill="x", padx=5, pady=2)

        ttk.Label(region_frame, text="Region:").pack(side="left", padx=5)
        self.region_var = tk.StringVar(value=self.gui_settings.get("region", "Asia Pacific"))
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
        saved_collectors = self.gui_settings.get("collectors", [])
        if saved_collectors:
            # Compare only the ID part when loading saved collectors
            for i, item_text in enumerate(self.collector_listbox.get(0, tk.END)):
                item_id = item_text.split(" ")[0] # Extract ID
                if item_id in saved_collectors:
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

        # --- Define Text Tags for Color Coding ---
        self.log_text.tag_configure("withdrawal", foreground="blue")
        self.log_text.tag_configure("alert_trigger", foreground="orange")
        self.log_text.tag_configure("filtered_as", foreground="green", font=('TkDefaultFont', 9, 'bold')) # Make filtered AS bold green

    def create_security_panel(self):
        """Create the security alerts panel within its dedicated tab frame."""
        # Target the alerts_tab_frame instead of self.right_frame
        security_frame = ttk.LabelFrame(self.alerts_tab_frame, text="Security Alerts")
        security_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Create alerts treeview
        columns = ("Timestamp", "Severity", "Type", "Details") # Renamed first column
        self.alerts_tree = ttk.Treeview(security_frame, columns=columns, show="headings")

        # Configure columns
        # Setup heading commands for sorting
        for col in columns:
            self.alerts_tree.heading(col, text=col, command=lambda _col=col: self._on_alerts_header_click(_col))
        self.alerts_tree.heading("Severity", text="Severity")
        self.alerts_tree.heading("Type", text="Type")
        self.alerts_tree.heading("Details", text="Details")

        self.alerts_tree.column("Timestamp", width=150) # Renamed and increased width
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

    def create_episodes_panel(self):
        """Create the episodes panel within its dedicated tab frame."""
        # Target the episodes_tab_frame
        episodes_frame = ttk.LabelFrame(self.episodes_tab_frame, text="Aggregated Episodes")
        episodes_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Define columns for the episodes treeview
        episode_columns = ("ID", "Prefix", "Origin AS", "Start Time", "End Time", "Score", "Events", "Severity", "Status")
        self.episodes_tree = ttk.Treeview(episodes_frame, columns=episode_columns, show="headings")

        # Configure episode columns and headings
        self.episodes_tree.heading("ID", text="ID")
        self.episodes_tree.heading("Prefix", text="Prefix")
        self.episodes_tree.heading("Origin AS", text="Origin AS")
        self.episodes_tree.heading("Start Time", text="Start Time")
        self.episodes_tree.heading("End Time", text="End Time")
        self.episodes_tree.heading("Score", text="Score")
        self.episodes_tree.heading("Events", text="Events")
        self.episodes_tree.heading("Severity", text="Max Sev")
        self.episodes_tree.heading("Status", text="Status")

        # Set column widths (adjust as needed)
        self.episodes_tree.column("ID", width=100, anchor='w')
        self.episodes_tree.column("Prefix", width=150, anchor='w')
        self.episodes_tree.column("Origin AS", width=80, anchor='center')
        self.episodes_tree.column("Start Time", width=140, anchor='center')
        self.episodes_tree.column("End Time", width=140, anchor='center')
        self.episodes_tree.column("Score", width=60, anchor='e')
        self.episodes_tree.column("Events", width=60, anchor='center')
        self.episodes_tree.column("Severity", width=60, anchor='center')
        self.episodes_tree.column("Status", width=60, anchor='center')

        # Add scrollbar
        ep_scrollbar = ttk.Scrollbar(episodes_frame, orient="vertical", command=self.episodes_tree.yview)
        self.episodes_tree.configure(yscrollcommand=ep_scrollbar.set)

        # Create button frame (for potential future actions like 'View Details')
        ep_button_frame = ttk.Frame(episodes_frame)
        ep_button_frame.pack(side="bottom", fill="x", padx=5, pady=5)

        # Add Refresh button (placeholder for now)
        refresh_button = ttk.Button(ep_button_frame, text="Refresh Episodes", command=self.refresh_episodes_display)
        refresh_button.pack(side="left", padx=5)

        # Pack widgets
        self.episodes_tree.pack(side="left", fill="both", expand=True)
        ep_scrollbar.pack(side="right", fill="y")

        # Configure tag colors (similar to alerts)
        self.episodes_tree.tag_configure("HIGH", foreground="red")
        self.episodes_tree.tag_configure("MEDIUM", foreground="orange")
        self.episodes_tree.tag_configure("LOW", foreground="blue")

    def refresh_episodes_display(self):
        """Fetches episodes from the manager and updates the display."""
        try:
            # Clear existing items
            for item in self.episodes_tree.get_children():
                self.episodes_tree.delete(item)

            if self.episode_manager:
                # Fetch active episodes (or could fetch all/recent based on need)
                episodes = self.episode_manager.get_active_episodes()
                logging.info(f"Refreshing episodes display, found {len(episodes)} active episodes.")
                for episode_data in episodes:
                    self.add_episode_to_treeview(episode_data)
            else:
                logging.warning("Episode manager not available, cannot refresh episodes display.")
        except Exception as e:
            logging.error(f"Error refreshing episodes display: {e}", exc_info=True)

    def add_episode_to_treeview(self, episode_data: dict):
        """Adds or updates a single episode in the episodes treeview."""
        if not episode_data or not isinstance(episode_data, dict):
            return

        episode_id = episode_data.get("id", "")
        if not episode_id:
            return

        # Format values for display
        values = (
            episode_id[:8] + "...", # Shorten ID for display
            episode_data.get("prefix", "N/A"),
            f"AS{episode_data.get('origin_as', 'N/A')}" if episode_data.get('origin_as') else "N/A",
            episode_data.get("start_time", ""), # Keep as ISO string for now
            episode_data.get("end_time", ""),   # Keep as ISO string for now
            f"{episode_data.get('score', 0):.1f}", # Format score
            episode_data.get("event_count", 0),
            episode_data.get("max_severity", "LOW"),
            episode_data.get("status", "OPEN")
        )

        severity_tag = episode_data.get("max_severity", "LOW").upper()

        # Check if item exists, update if it does, insert if not
        # Use full episode_id as the item ID (iid) for reliable updates/checks
        if self.episodes_tree.exists(episode_id):
            self.episodes_tree.item(episode_id, values=values, tags=(severity_tag,))
        else:
            # Insert new item
            self.episodes_tree.insert("", tk.END, iid=episode_id, values=values, tags=(severity_tag,))

    def update_collectors(self, event=None):
        """Update the collectors list based on selected region."""
        region = self.region_var.get()
        self.collector_listbox.delete(0, tk.END)

        collectors = self.get_collectors_by_region(region)
        for collector in collectors:
            location = self.get_collector_location(collector)
            display_text = f"{collector} ({location})"
            self.collector_listbox.insert(tk.END, display_text)

        # Update button state
        self.update_start_button_state()

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
        self.save_gui_settings()  # Save GUI settings

    def remove_as_filter(self):
        """Remove selected AS numbers from the filter list."""
        selected_indices = self.as_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select one or more AS numbers to remove.")
            return

        # Remove in reverse order to avoid index shifting
        for index in sorted(selected_indices, reverse=True):
            self.as_listbox.delete(index)
        self.save_gui_settings()  # Save GUI settings

    def clear_as_filters(self):
        """Clear all AS filters."""
        # Note: self.filtered_as_numbers seems unused, the listbox itself holds the state
        self.as_listbox.delete(0, tk.END)
        self.filter_var.set("")
        # self.update_as_listbox() # Not needed as we directly modify listbox
        self.log_message("Cleared all AS filters")
        self.save_gui_settings()  # Save GUI settings

    def update_as_listbox(self):
        """Update the AS number listbox with current filters."""
        # This method seems redundant now as filters are added/removed directly
        pass
        # self.as_listbox.delete(0, tk.END)  # Clear current items
        # for asn in sorted(self.filtered_as_numbers): # self.filtered_as_numbers is not maintained
        #     self.as_listbox.insert(tk.END, f"AS{asn}")

    def start_monitoring(self):
        """Start BGP monitoring."""
        if self.is_monitoring:
            return

        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        # Schedule UI update on main thread
        self.root.after(0, self.update_ui_for_monitoring_start)
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
                # If loop exited unexpectedly while still supposed to be monitoring
                if self.is_monitoring:
                    self.is_monitoring = False # Mark as stopped
                    # Schedule UI reset on main thread
                    self.root.after(0, self.update_ui_for_monitoring_stop)
                try:
                    loop.close()
                except:
                    pass
    async def _monitor_with_reconnect(self, loop):
        """Monitor BGP updates with automatic reconnection."""
        while self.is_monitoring:
            try:
                # Get selected collectors
                # Extract only the collector ID from the selected display text
                selected_indices = self.collector_listbox.curselection()
                collectors = [self.collector_listbox.get(idx).split(" ")[0] for idx in selected_indices]
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
            # Ensure the monitor loop knows to stop
            # self.bgp_monitor.stop_monitoring() # Called above already
            self.monitor_thread.join(timeout=5)
            self.monitor_thread = None

        # Schedule UI update on main thread
        self.root.after(0, self.update_ui_for_monitoring_stop)

    def log_message(self, message, line_tags=None):
        """Add message to log, applying color coding tags."""
        if not isinstance(message, str):
            message = str(message)

        # Disable text widget temporarily for bulk operations
        self.log_text.config(state=tk.NORMAL)

        # Get start index before insertion
        start_index = self.log_text.index(f"{tk.END}-1c") # Get index of the beginning of the last line

        # Insert the message with primary line tags (e.g., withdrawal, alert_trigger)
        self.log_text.insert(tk.END, message + "\n", line_tags)

        # Get end index after insertion
        end_index = self.log_text.index(f"{tk.END}-1c") # Get index of the beginning of the *new* last line

        # Apply filtered AS highlighting only if it's not an alert line
        # Check if 'alert_trigger' is NOT in the applied tags for the new line
        current_tags = self.log_text.tag_names(start_index)
        if "alert_trigger" not in current_tags:
            active_as_filters_raw = self.as_listbox.get(0, tk.END)
            # Extract just the number part for searching within the text
            active_as_filters_nums = set()
            for f in active_as_filters_raw:
                if f.startswith("AS"):
                    num_part = f[2:]
                    if num_part.isdigit():
                        active_as_filters_nums.add(num_part)
                elif f.isdigit(): # Allow filtering by just number
                     active_as_filters_nums.add(f)


            if active_as_filters_nums:
                # Iterate through the newly inserted line content
                line_content = self.log_text.get(start_index, end_index)
                for as_num_str in active_as_filters_nums:
                    # Define search patterns for the AS number
                    # Search for "ASxxxx" and variations like " xxxx,", ",xxxx,", " xxxx "
                    search_patterns = [f"AS{as_num_str}", f" {as_num_str},", f",{as_num_str},", f" {as_num_str} ", f",{as_num_str} "]

                    for pattern in search_patterns:
                        start_search = start_index
                        while True:
                            # Search within the range of the newly added line
                            match_start = self.log_text.search(pattern, start_search, stopindex=end_index, nocase=True)
                            if not match_start:
                                break

                            # Calculate match end index
                            match_end = f"{match_start}+{len(pattern)}c"

                            # Apply the 'filtered_as' tag
                            self.log_text.tag_add("filtered_as", match_start, match_end)

                            # Move search start past the current match
                            start_search = match_end
        # Scroll to the end
        self.log_text.see(tk.END)
        # Re-enable text widget if needed (or keep it normal)
        # self.log_text.config(state=tk.DISABLED) # If you want it read-only

    # New methods for thread-safe UI updates
    def update_ui_for_monitoring_start(self):
        """Update UI elements when monitoring starts."""
        self.start_button.configure(text="Stop Monitoring", command=self.stop_monitoring, state="normal")
        self.status_var.set("Monitoring...")

    def update_ui_for_monitoring_stop(self):
        """Update UI elements when monitoring stops."""
        self.start_button.configure(text="Start Monitoring", command=self.start_monitoring)
        self.status_var.set("Monitoring stopped")
        # Re-evaluate button state based on collector selection
        self.update_start_button_state()

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

    def save_gui_settings(self): # Renamed method
        """Save current GUI settings to configuration file."""
        current_settings = {
            "region": self.region_var.get() if hasattr(self, 'region_var') else "",
            "collectors": [],
            "as_filters": []
        }

        # Save collectors if listbox exists and has selections
        if hasattr(self, 'collector_listbox'):
            selected = self.collector_listbox.curselection()
            # Extract only the collector ID when saving settings
            current_settings["collectors"] = [self.collector_listbox.get(i).split(" ")[0] for i in selected] if selected else []

        # Save AS filters if listbox exists
        if hasattr(self, 'as_listbox'):
            current_settings["as_filters"] = list(self.as_listbox.get(0, tk.END))

        self.config_manager.save_gui_settings(current_settings) # Call renamed method in config_manager

    def on_closing(self): # Save GUI settings on close
        """Handle window closing event."""
        if self.is_monitoring:
            self.stop_monitoring()
        self.save_gui_settings() # Save GUI settings
        if self.bgp_monitor and self.bgp_monitor.db_manager:
            self.bgp_monitor.db_manager.close()
        self.root.destroy()

    def show_as_info(self):
        """Show information about selected AS numbers."""
        selected_indices = self.as_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select an AS number from the list.")
            return

        # Get the first selected AS number
        selected_asn_str = self.as_listbox.get(selected_indices[0])

        # Extract just the number part if it starts with "AS"
        if selected_asn_str.startswith("AS"):
            asn_to_lookup = selected_asn_str[2:]
        else:
            asn_to_lookup = selected_asn_str

        # Validate it's a number
        if not asn_to_lookup.isdigit():
            messagebox.showerror("Invalid AS", f"'{selected_asn_str}' is not a valid AS number.")
            return

        # Show loading indicator
        self.status_label.config(text=f"Looking up AS{asn_to_lookup} info...")
        self.progress_bar.pack(fill="x", padx=5, pady=2)
        self.progress_bar.start()
        self.root.update_idletasks() # Force UI update

        # Perform lookup in a separate thread to avoid blocking GUI
        def lookup_thread():
            try:
                info = self.as_lookup.get_as_info(asn_to_lookup)
                # Schedule result display back on main thread
                self.root.after(0, display_result, info)
            except Exception as e:
                # Schedule error display back on main thread
                self.root.after(0, display_error, e)
            finally:
                # Schedule progress bar stop back on main thread
                self.root.after(0, stop_progress)

        def display_result(info):
            if info:
                info_str = f"AS{asn_to_lookup} Information:\n\n"
                # General Info (prioritize non-PDB if available, fallback to PDB)
                info_str += f"Name: {info.get('name', info.get('pdb_name', 'N/A'))}\n"
                info_str += f"Country: {info.get('country', 'N/A')}\n"
                info_str += f"Description: {info.get('description', 'N/A')}\n"
                info_str += f"Website: {info.get('website', info.get('pdb_website', 'N/A'))}\n" # Use PDB website if general one missing
                info_str += f"Looking Glass: {info.get('looking_glass', 'N/A')}\n" # No PDB equivalent
                info_str += f"Abuse Contact: {info.get('abuse_contact', 'N/A')}\n" # No PDB equivalent
                info_str += "\n--- PeeringDB Info ---\n"
                info_str += f"  PDB Name: {info.get('pdb_name', 'N/A')}\n"
                info_str += f"  Network Type: {info.get('pdb_type', 'N/A')}\n"
                info_str += f"  Traffic Levels: {info.get('pdb_traffic', 'N/A')}\n"
                info_str += f"  IX Count: {info.get('pdb_ix_count', 'N/A')}\n"
                info_str += f"  Facility Count: {info.get('pdb_fac_count', 'N/A')}\n"
                info_str += f"  PDB Created: {info.get('pdb_created', 'N/A')}\n"
                info_str += "\n--- Source Info ---\n"
                info_str += f"  Sources Found: {', '.join(info.get('sources_found', ['N/A']))}\n"
                info_str += f"  Result Timestamp: {datetime.fromtimestamp(info.get('timestamp_combined', 0)).isoformat() if info.get('timestamp_combined') else 'N/A'}\n"
                messagebox.showinfo(f"AS{asn_to_lookup} Info", info_str)
            else:
                messagebox.showwarning("Not Found", f"Information for AS{asn_to_lookup} not found.")

        def display_error(e):
            messagebox.showerror("Lookup Error", f"Error looking up AS info: {e}")

        def stop_progress():
            self.progress_bar.stop()
            self.progress_bar.pack_forget()
            self.status_label.config(text="") # Clear status

        # Start the lookup thread
        thread = threading.Thread(target=lookup_thread)
        thread.daemon = True
        thread.start()

    def show_about(self):
        """Show information about the application and author."""
        about_text = """
        BGP Monitor v1.1

        Developed by: Amit Bhatnagar @ Amit.Bhatnagar@outlook.com

        This tool monitors BGP updates from RIPE RIS,
        analyzes them for security threats, and stores
        data in Neo4j and CSV files.

        Features:
        - Real-time monitoring
        - Security analysis (Hijacking, Leaks, RPKI)
        - Neo4j integration
        - Configurable filtering
        - GUI interface

        Libraries Used: tkinter, websockets, neo4j, requests, pandas
        """

        about_win = tk.Toplevel(self.root)
        about_win.title("About BGP Monitor")
        about_win.geometry("350x300")
        about_win.transient(self.root)
        about_win.grab_set()

        text_area = scrolledtext.ScrolledText(about_win, wrap=tk.WORD, padx=10, pady=10)
        text_area.insert(tk.INSERT, about_text)
        text_area.config(state=tk.DISABLED) # Make read-only
        text_area.pack(fill="both", expand=True)

        # Add License button
        def open_license():
            license_path = Path(__file__).parent.parent / "LICENSE"
            if license_path.exists():
                try:
                    if os.name == 'nt': # Windows
                        os.startfile(license_path)
                    else: # Linux/Mac
                        subprocess.run(['xdg-open', str(license_path)], check=True)
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open LICENSE file: {e}", parent=about_win)
            else:
                messagebox.showwarning("Not Found", "LICENSE file not found.", parent=about_win)

        license_button = ttk.Button(about_win, text="View License", command=open_license)
        license_button.pack(pady=10)

        close_button = ttk.Button(about_win, text="Close", command=about_win.destroy)
        close_button.pack(pady=5)


    async def process_update(self, message):
        """Process a single BGP update message."""
        try:
            # Basic parsing
            data = message.get("data", {})
            msg_type = message.get("type")

            if msg_type != "ris_message":
                # Log other message types if needed (e.g., ris_error)
                if msg_type == "ris_error":
                    logging.error(f"RIPE RIS Error: {data.get('message', 'Unknown error')}")
                return # Ignore non-update messages

            # Extract common fields
            timestamp_unix = data.get("timestamp")
            timestamp_dt = datetime.fromtimestamp(timestamp_unix) if timestamp_unix else datetime.now()
            collector = data.get("host", "unknown")
            peer_asn_str = data.get("peer_asn")
            peer_ip = data.get("peer")
            as_path_list = data.get("path", [])
            as_path_str = ",".join(map(str, as_path_list)) if as_path_list else ""
            origin_as = get_origin_as(as_path_str) # Use helper
            communities = data.get("community", [])
            next_hop = data.get("next_hop") # Can be None

            # --- AS Path Filtering ---
            # Get the currently configured filters from the listbox
            active_as_filters = set(self.as_listbox.get(0, tk.END))
            # Convert path list to set of strings for efficient checking
            path_as_set = set(map(str, as_path_list))
            # Add "AS" prefix for comparison with listbox format
            path_as_set_formatted = {f"AS{asn}" for asn in path_as_set}

            # If filters are active, check if any filtered AS is in the path
            if active_as_filters:
                # Check for intersection between the path and the filters
                if not path_as_set_formatted.intersection(active_as_filters):
                    # logging.debug(f"Skipping message due to AS filter. Path: {as_path_str}, Filters: {active_as_filters}")
                    return # Skip processing this message if no filtered AS is found in the path
            # -------------------------

            # Process Announcements
            announcements = data.get("announcements", [])
            for ann in announcements:
                prefixes = ann.get("prefixes", [])
                # Sometimes next_hop is per-announcement
                current_next_hop = ann.get("next_hop", next_hop)

                for prefix in prefixes:
                    # --- Get previous state from cache ---
                    previous_origin_info = self.prefix_origin_cache.get(prefix)
                    previous_origin_as = previous_origin_info['origin_as'] if previous_origin_info else None
                    # -------------------------------------

                    # --- Security Analysis ---
                    # Pass the actual previous origin AS from cache
                    alert = check_suspicious_patterns(
                        timestamp=timestamp_dt,
                        prefix=prefix,
                        as_path=as_path_str,
                        peer_asn=peer_asn_str,
                        # Pass the retrieved previous origin
                        previous_origin_as=previous_origin_as,
                        db_manager=self.bgp_monitor.db_manager # Pass db_manager if available
                    )

                    # --- Determine Line Tag ---
                    line_tag = None
                    if alert:
                        line_tag = "alert_trigger"
                    # --------------------------

                    # Log the raw update with appropriate tag
                    log_entry = f"{timestamp_dt.isoformat()} | Announce | {prefix} | Path: {as_path_str} | Peer: AS{peer_asn_str} ({peer_ip}) | NextHop: {current_next_hop} | Collector: {collector}"
                    self.root.after(0, self.log_message, log_entry, line_tag) # Schedule UI update with tag

                    # --- Process Alert (if any) ---
                    if alert:
                        # Log the alert using SecurityAlertLogger (handles DB/CSV/Standard Logging)
                        self.alert_logger.log_alert(alert, db_manager=self.bgp_monitor.db_manager)
                        # Schedule UI update for the security panel
                        self.root.after(0, self.add_security_alert, alert)
                    # ----------------------------

                    # --- Update prefix origin cache ---
                    if origin_as is not None: # Only cache if we have a valid origin
                        # Basic cache eviction (remove oldest if full)
                        if len(self.prefix_origin_cache) >= self.MAX_PREFIX_CACHE_SIZE:
                            try:
                                # Convert to list and remove the first item (oldest insertion order in Python 3.7+)
                                oldest_key = next(iter(self.prefix_origin_cache))
                                del self.prefix_origin_cache[oldest_key]
                            except StopIteration: # Should not happen if size >= MAX_SIZE > 0
                                pass
                            except Exception as cache_err:
                                logging.warning(f"Error during cache eviction: {cache_err}")

                        self.prefix_origin_cache[prefix] = {
                            'origin_as': origin_as,
                            'timestamp': timestamp_dt # Store timestamp for potential LRU logic later
                        }
                    # --------------------------------

                    # Store in DB if enabled
                    if self.bgp_monitor.db_manager:
                        try:
                            # Pass more details to db storage
                            self.bgp_monitor.db_manager.store_bgp_update(
                                timestamp=timestamp_dt,
                                collector=collector,
                                peer_asn=peer_asn_str,
                                prefix=prefix,
                                as_path=as_path_str,
                                next_hop=current_next_hop,
                                communities=communities,
                                update_type="announcement",
                                origin=data.get("origin"), # Add origin attribute
                                aggregator=data.get("aggregator"), # Add aggregator
                                host=collector, # Use collector as host
                                id=data.get("id"), # Add message ID
                                raw_message=message # Store raw message
                            )
                        except Exception as db_err:
                            logging.error(f"DB Error (Announce): {db_err}")

            # Process Withdrawals
            withdrawals = data.get("withdrawals", [])
            for wd in withdrawals: # Withdrawals might be dicts or just prefixes
                prefix = None
                if isinstance(wd, dict):
                    prefix = wd.get("prefix")
                elif isinstance(wd, str):
                    prefix = wd

                if prefix:
                    # --- Remove prefix from origin cache on withdrawal ---
                    if prefix in self.prefix_origin_cache:
                        del self.prefix_origin_cache[prefix]
                        # Optionally log cache removal
                        # logging.debug(f"Removed {prefix} from origin cache due to withdrawal.")
                    # -----------------------------------------------------

                    # Log the withdrawal with the "withdrawal" tag
                    log_entry = f"{timestamp_dt.isoformat()} | Withdraw | {prefix} | Peer: AS{peer_asn_str} ({peer_ip}) | Collector: {collector}"
                    self.root.after(0, self.log_message, log_entry, "withdrawal") # Schedule UI update with tag

                    # Store in DB if enabled
                    if self.bgp_monitor.db_manager:
                        try:
                            self.bgp_monitor.db_manager.store_bgp_update(
                                timestamp=timestamp_dt,
                                collector=collector,
                                peer_asn=peer_asn_str,
                                prefix=prefix,
                                update_type="withdrawal",
                                host=collector, # Use collector as host
                                id=data.get("id"), # Add message ID
                                raw_message=message # Store raw message
                            )
                        except Exception as db_err:
                            logging.error(f"DB Error (Withdraw): {db_err}")

            # Update entry count (consider doing this less frequently if performance is an issue)
            self.root.after(100, self.update_entries_count) # Schedule update slightly delayed

        except Exception as e:
            logging.error(f"Error processing update message: {e}")
            self.root.after(0, self.log_message, f"Error processing message: {e}")


    def update_db_status_led(self, connected, status_text=None):
        """Update the database connection status indicator."""
        if connected:
            self.db_status_led.config(text=status_text or "DB: Connected", bg="green")
        else:
            self.db_status_led.config(text=status_text or "DB: Disconnected", bg="red")

    def check_db_connection(self):
        """Check Neo4j connection status and update LED."""
        if self.bgp_monitor and self.bgp_monitor.db_manager:
            try:
                # Use a simple query to verify connection
                with self.bgp_monitor.db_manager.driver.session() as session:
                    result = session.run("RETURN 1")
                    result.single() # Consume the result

                # Get connection details for display
                uri = self.bgp_monitor.db_manager.driver.address.host
                # Note: Getting DB name might require specific query depending on Neo4j version/setup
                db_name = "neo4j" # Assuming default, adjust if needed
                status_text = f"DB: Connected ({uri} - {db_name})"
                self.update_db_status_led(True, status_text)
                return True
            except Exception as e:
                logging.warning(f"Database connection check failed: {e}")
                self.update_db_status_led(False, f"DB: Error ({e})")
                return False
        else:
            self.update_db_status_led(False)
            return False

    def update_entries_count(self):
        """Update the label showing the number of BGP updates stored in Neo4j."""
        if self.bgp_monitor and self.bgp_monitor.db_manager:
            try:
                with self.bgp_monitor.db_manager.driver.session() as session:
                    result = session.run("MATCH (n:BGPUpdate) RETURN count(n) AS count")
                    count = result.single()["count"]
                    self.entries_label.config(text=f"DB Entries: {count}")
            except Exception as e:
                # Don't log excessively if DB is down, just update label
                self.entries_label.config(text="DB Entries: Error")
                # Optionally log the first time or less frequently
                # logging.warning(f"Could not get DB entry count: {e}")
        else:
            self.entries_label.config(text="DB Entries: N/A")

        # Schedule next update (e.g., every 30 seconds)
        self.root.after(30000, self.update_entries_count)


    def open_db_config_window(self):
        """Open the database configuration dialog."""
        db_win = tk.Toplevel(self.root)
        db_win.title("Database Configuration")
        db_win.geometry("350x150")
        db_win.transient(self.root) # Keep on top of main window
        db_win.grab_set() # Modal behavior

        # Load current config for display
        current_config = self.config_manager.load_neo4j_config()

        # Variables
        uri_var = tk.StringVar(value=current_config.get('uri', ''))
        user_var = tk.StringVar(value=current_config.get('username', ''))
        pass_var = tk.StringVar(value=current_config.get('password', ''))

        # --- Widgets ---
        main_frame = ttk.Frame(db_win, padding="10")
        main_frame.pack(fill="both", expand=True)

        # URI
        ttk.Label(main_frame, text="URI:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(main_frame, textvariable=uri_var, width=30).grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        # Username
        ttk.Label(main_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(main_frame, textvariable=user_var, width=30).grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        # Password
        ttk.Label(main_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(main_frame, textvariable=pass_var, show="*", width=30).grid(row=2, column=1, sticky="ew", padx=5, pady=2)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=15)

        save_button = ttk.Button(
            button_frame,
            text="Save & Test",
            command=lambda: self.save_db_config(
                db_win, uri_var.get(), user_var.get(), pass_var.get()
            )
        )
        save_button.pack(side="left", padx=10)

        cancel_button = ttk.Button(button_frame, text="Cancel", command=db_win.destroy)
        cancel_button.pack(side="left", padx=10)

        main_frame.columnconfigure(1, weight=1) # Allow entry fields to expand


    def save_db_config(self, window, uri, username, password):
        """Save database configuration and test connection."""
        new_config = {
            'uri': uri,
            'username': username,
            'password': password
        }

        # Attempt to save config first
        if not self.config_manager.save_config(new_config, format_type='both'):
            messagebox.showerror("Save Error", "Failed to save configuration files.", parent=window)
            return

        # Update the global config dictionary if it's still used elsewhere (e.g., initial load)
        # Check if db_config_module.NEO4J_CONFIG exists and is used before updating
        if hasattr(db_config_module, 'NEO4J_CONFIG'):
            db_config_module.NEO4J_CONFIG.update(new_config)
        else:
             logging.warning("config.database_config.NEO4J_CONFIG not found, skipping update.")


        # Try to re-initialize the db_manager with new credentials
        try:
            # Close existing connection if any
            if self.bgp_monitor and self.bgp_monitor.db_manager:
                self.bgp_monitor.db_manager.close()

            # Create new manager instance using the correctly imported class
            self.bgp_monitor.db_manager = BGPDatabaseManager(uri, username, password)

            # Check connection status immediately
            if self.check_db_connection():
                 messagebox.showinfo("Success", "Database configuration saved and connection successful.", parent=window)
                 window.destroy()
            else:
                 # Error message handled by check_db_connection updating the LED
                 messagebox.showwarning("Connection Failed", "Configuration saved, but failed to connect to the database with the new settings.", parent=window)
                 # Keep window open for user to correct

        except Exception as e:
            logging.error(f"Failed to re-initialize database connection: {e}")
            self.update_db_status_led(False, f"DB: Init Error ({e})")
            messagebox.showerror("Connection Error", f"Configuration saved, but an error occurred connecting to the database:\n{e}", parent=window)
            # Keep window open


    def add_security_alert(self, alert):
        """Add a security alert to the GUI treeview."""
        if not alert:
            return

        timestamp_str = alert.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S')
        severity = alert.get('severity', 'LOW').upper()
        prefix = alert.get('prefix', 'N/A')
        as_path = alert.get('as_path', 'N/A')
        peer_asn = alert.get('peer_asn', 'N/A')
        reasons = "; ".join(alert.get('reasons', []))
        is_critical = alert.get('is_critical_prefix', False)
        # is_telecom = alert.get('is_uk_telecom', False) # Removed

        # Determine alert type based on reasons (simplified)
        alert_type = "Suspicious"
        if "hijack" in reasons.lower() or "origin change" in reasons.lower():
            alert_type = "Hijack?"
        elif "leak" in reasons.lower():
            alert_type = "Leak?"
        elif "rpki invalid" in reasons.lower():
            alert_type = "RPKI Invalid"
        elif "critical" in reasons.lower():
             alert_type = "Critical Prefix"

        # Add details to the reason string for display
        details_display = f"Prefix: {prefix}, Path: {as_path}, Peer: {peer_asn}, Reasons: {reasons}"
        if is_critical:
             details_display += " (CRITICAL PREFIX)"
        # if is_telecom: # Removed
        #     details_display += " (UK TELECOM ASN)" # Removed

        # Insert into treeview with severity tag
        try:
            self.alerts_tree.insert(
                "", tk.END,
                values=(timestamp_str, severity, alert_type, details_display),
                tags=(severity,) # Use severity as tag for coloring
            )
            # Optional: Limit number of items in treeview for performance
            # max_items = 1000
            # if len(self.alerts_tree.get_children()) > max_items:
            #     self.alerts_tree.delete(self.alerts_tree.get_children()[0])
        except Exception as e:
            logging.error(f"Failed to add alert to GUI: {e}")


    def load_recent_alerts(self):
        """Load recent alerts from DB or CSV on startup."""
        alerts = []
        # Try loading from DB first
        if self.bgp_monitor and self.bgp_monitor.db_manager:
            try:
                alerts = self.bgp_monitor.db_manager.get_recent_alerts(limit=200) # Load more initially
                if alerts:
                    logging.info(f"Loaded {len(alerts)} recent alerts from database.")
            except Exception as e:
                logging.warning(f"Could not load recent alerts from DB: {e}")

        # If DB fails or no alerts, try loading from today's CSV as fallback (optional)
        # This part can be complex due to CSV parsing, skipping for now.

        # Add loaded alerts to GUI
        for alert in reversed(alerts): # Show newest first if desired, or sort later
            self.add_security_alert(alert)


    def export_alerts(self):
        """Export alerts currently shown in the treeview to a CSV file."""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Security Alerts"
        )
        if not filepath:
            return # User cancelled

        try:
            with open(filepath, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Write header matching treeview columns
                writer.writerow(["Timestamp", "Severity", "Type", "Details"])

                # Write data from treeview items
                for item_id in self.alerts_tree.get_children():
                    values = self.alerts_tree.item(item_id)['values']
                    writer.writerow(values)

            messagebox.showinfo("Export Successful", f"Alerts exported successfully to:\n{filepath}")
            logging.info(f"Exported {len(self.alerts_tree.get_children())} alerts to {filepath}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export alerts: {e}")
            logging.error(f"Failed to export alerts: {e}")


    # --- Sorting Logic for Alerts Treeview ---
    def _on_alerts_header_click(self, col):
        """Handle clicking on an alerts treeview column header."""
        reverse = False
        if col == self._alerts_sort_col:
            reverse = not self._alerts_sort_reverse # Toggle sort direction
        else:
            self._alerts_sort_col = col # Set new sort column
            reverse = False # Default to ascending

        self._alerts_sort_reverse = reverse
        self._sort_alerts_column(col, reverse)

    def _sort_alerts_column(self, col, reverse):
        """Sort the alerts treeview by the specified column."""
        # Get column index
        try:
            col_index = ["Timestamp", "Severity", "Type", "Details"].index(col)
        except ValueError:
            logging.error(f"Invalid column name for sorting: {col}")
            return

        # Extract data for sorting
        data = []
        for item in self.alerts_tree.get_children(''):
            try:
                value = self.alerts_tree.item(item)['values'][col_index]
                data.append((value, item))
            except IndexError:
                 logging.warning(f"Could not get value for column index {col_index} in item {item}")
                 continue # Skip items with missing data

        # Define severity order for sorting
        severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

        # Sort data based on column type
        log_func = getattr(self, 'logger', None) # Get logger if available
        try:
            if col == "Timestamp":
                # Sort by datetime objects
                data.sort(key=lambda x: datetime.strptime(x[0], '%Y-%m-%d %H:%M:%S'), reverse=reverse)
            elif col == "Severity":
                 # Sort by severity level
                 data.sort(key=lambda x: severity_map.get(x[0].upper(), -1), reverse=reverse)
            else: # Default string sort for Type, Details
                data.sort(key=lambda x: str(x[0]), reverse=reverse)
        except Exception as e:
            # Log error and attempt fallback string sort
            if log_func:
                 log_func.error(f"Error sorting column '{col}': {e}. Data might have mixed types.")
            else:
                 print(f"Error sorting column '{col}': {e}. Data might have mixed types.")
            # Attempt a simple string sort as fallback
            try:
                 data.sort(key=lambda x: str(x[0]), reverse=reverse)
            except Exception as fallback_e:
                 if log_func:
                      log_func.error(f"Fallback string sort also failed for column '{col}': {fallback_e}")
                 else:
                      print(f"Fallback string sort also failed for column '{col}': {fallback_e}")
                 return # Abort sort if fallback fails

        # Reorder items in the treeview
        for index, (val, item) in enumerate(data):
            self.alerts_tree.move(item, '', index)

        # Update column heading indicator (optional, but good UX)
        # This requires a bit more setup to show arrows, skipping for now for simplicity
        # For example: self.alerts_tree.heading(col, text=f"{col} {'▲' if not reverse else '▼'}")
        # Need to reset other headings too.

        log_func = getattr(self, 'logger', None)
        if log_func:
             log_func.info(f"Sorted alerts by '{col}' {'descending' if reverse else 'ascending'}")
        else:
             print(f"Sorted alerts by '{col}' {'descending' if reverse else 'ascending'}")

    # --- Syslog Configuration ---
    def open_syslog_config_window(self):
        """Open the Syslog configuration dialog."""
        syslog_win = tk.Toplevel(self.root)
        syslog_win.title("Syslog Settings")
        syslog_win.geometry("350x200")
        syslog_win.transient(self.root) # Keep on top of main window
        syslog_win.grab_set() # Modal behavior

        # Load current settings
        # Ensure app_settings is refreshed in case it was modified elsewhere or needs defaults
        self.app_settings = self.config_manager.load_app_settings()
        current_log_settings = self.app_settings.get("logging", {})
        current_syslog = current_log_settings.get("syslog", {})

        # Variables
        enabled_var = tk.BooleanVar(value=current_syslog.get("enabled", False))
        host_var = tk.StringVar(value=current_syslog.get("host", "localhost"))
        # Use get() with default for port to avoid KeyError if port isn't set
        port_val = current_syslog.get("port", 514)
        port_var = tk.IntVar(value=port_val if isinstance(port_val, int) else 514) # Ensure it's an int
        protocol_var = tk.StringVar(value=current_syslog.get("protocol", "UDP").upper())

        # --- Widgets ---
        main_frame = ttk.Frame(syslog_win, padding="10")
        main_frame.pack(fill="both", expand=True)

        # Enable Checkbox
        ttk.Checkbutton(main_frame, text="Enable Syslog Forwarding", variable=enabled_var).grid(row=0, column=0, columnspan=2, sticky="w", pady=5)

        # Host
        ttk.Label(main_frame, text="Host:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(main_frame, textvariable=host_var, width=30).grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        # Port
        ttk.Label(main_frame, text="Port:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(main_frame, textvariable=port_var, width=10).grid(row=2, column=1, sticky="w", padx=5, pady=2)

        # Protocol
        ttk.Label(main_frame, text="Protocol:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        protocol_frame = ttk.Frame(main_frame)
        protocol_frame.grid(row=3, column=1, sticky="w", padx=5, pady=2)
        ttk.Radiobutton(protocol_frame, text="UDP", variable=protocol_var, value="UDP").pack(side="left")
        ttk.Radiobutton(protocol_frame, text="TCP", variable=protocol_var, value="TCP").pack(side="left", padx=10)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=15)

        save_button = ttk.Button(
            button_frame,
            text="Save",
            command=lambda: self.save_syslog_config(
                syslog_win, enabled_var.get(), host_var.get(), port_var.get(), protocol_var.get()
            )
        )
        save_button.pack(side="left", padx=10)

        cancel_button = ttk.Button(button_frame, text="Cancel", command=syslog_win.destroy)
        cancel_button.pack(side="left", padx=10)

        main_frame.columnconfigure(1, weight=1) # Allow entry fields to expand

    def save_syslog_config(self, window, enabled, host, port, protocol):
        """Save Syslog configuration and close the dialog."""
        try:
            # Ensure app_settings is up-to-date before modifying
            self.app_settings = self.config_manager.load_app_settings()

            # Update the application settings dictionary safely
            log_settings = self.app_settings.setdefault("logging", {})
            syslog_settings = log_settings.setdefault("syslog", {})

            syslog_settings["enabled"] = enabled
            syslog_settings["host"] = host
            # Validate port is an integer before saving
            try:
                 syslog_settings["port"] = int(port)
            except ValueError:
                 messagebox.showerror("Syslog Settings", "Invalid port number. Please enter an integer.", parent=window)
                 return # Don't save if port is invalid

            syslog_settings["protocol"] = protocol.upper()

            # Save the updated settings
            if self.config_manager.save_app_settings(self.app_settings):
                messagebox.showinfo("Syslog Settings", "Syslog settings saved successfully.\nA restart is required for changes to take effect.", parent=window)
                window.destroy()
            else:
                messagebox.showerror("Syslog Settings", "Failed to save Syslog settings.", parent=window)

        except Exception as e:
            messagebox.showerror("Syslog Settings", f"An error occurred: {e}", parent=window)
            logging.error(f"Error saving syslog config: {e}")
    # ---------------------------

    # --- RPKI Configuration ---
    def open_rpki_config_window(self):
        """Open the RPKI configuration dialog."""
        config_window = tk.Toplevel(self.root)
        config_window.title("RPKI Validator Settings")
        config_window.geometry("400x150")
        config_window.transient(self.root) # Keep on top of main window
        config_window.grab_set() # Modal behavior

        main_frame = ttk.Frame(config_window, padding="10")
        main_frame.pack(fill="both", expand=True)

        # Load current setting
        # Ensure app_settings is refreshed
        self.app_settings = self.config_manager.load_app_settings()
        current_rpki_settings = self.app_settings.get("rpki", {})
        current_url = current_rpki_settings.get("local_validator_url", "") or "" # Handle null/None

        # URL Entry
        ttk.Label(main_frame, text="Local Validator URL (e.g., http://localhost:8323):").pack(pady=(0, 5))
        url_var = tk.StringVar(value=current_url)
        url_entry = ttk.Entry(main_frame, textvariable=url_var, width=50)
        url_entry.pack(fill="x", expand=True)

        # Button Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=(10, 0))

        # Save Button
        save_button = ttk.Button(
            button_frame,
            text="Save",
            command=lambda: self.save_rpki_config(config_window, url_var.get())
        )
        save_button.pack(side=tk.LEFT, padx=5)

        # Close Button
        close_button = ttk.Button(button_frame, text="Close", command=config_window.destroy)
        close_button.pack(side=tk.LEFT, padx=5)

        config_window.wait_window() # Wait for dialog to close

    def save_rpki_config(self, window, url):
        """Save RPKI configuration."""
        try:
            # Basic validation: allow empty string or something that looks like a URL
            url = url.strip()
            if url and not (url.startswith("http://") or url.startswith("https://")):
                 messagebox.showerror("Invalid URL", "URL must start with http:// or https://, or be empty.", parent=window)
                 return

            # Ensure app_settings is up-to-date before modifying
            self.app_settings = self.config_manager.load_app_settings()

            # Update settings dictionary
            rpki_settings = self.app_settings.setdefault("rpki", {})
            # Store empty string as null in JSON for consistency
            rpki_settings["local_validator_url"] = url if url else None

            # Save to file
            if self.config_manager.save_app_settings(self.app_settings):
                # Update the running RPKIValidator instance
                if self.rpki_validator:
                    self.rpki_validator.local_validator_url = url if url else None
                    logging.info(f"Updated running RPKIValidator instance. New URL: {self.rpki_validator.local_validator_url}") # Use logging
                else:
                     logging.warning("RPKIValidator instance not found in GUI, cannot update running instance.") # Use logging

                messagebox.showinfo("Success", "RPKI settings saved.", parent=window)
                window.destroy()
            else:
                 messagebox.showerror("Error", "Failed to save RPKI settings.", parent=window)


        except Exception as e:
            messagebox.showerror("Error", f"Failed to save RPKI settings: {e}", parent=window)
            logging.error(f"Error saving RPKI config: {e}", exc_info=True) # Add traceback info
    # ---------------------------

    # --- Application Log Method ---
    def log_app_message(self, message):
        """Appends a message to the Application Log tab."""
        if hasattr(self, 'app_log_text'):
            try:
                # Ensure widget is enabled for writing
                self.app_log_text.config(state=tk.NORMAL)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.app_log_text.insert(tk.END, f"{timestamp} - {message}\n")
                self.app_log_text.see(tk.END) # Scroll to the end
                # Disable writing again
                self.app_log_text.config(state=tk.DISABLED)
            except Exception as e:
                # Fallback to console if GUI logging fails
                print(f"APP LOG FALLBACK: {timestamp} - {message}")
                print(f"GUI Log Error: {e}")
        else:
             # Fallback if called before widget exists
             print(f"APP LOG (Pre-Init): {message}")
    # ---------------------------

# End of BGPMonitorGUI class definition

def main():
    root = tk.Tk()
    app = BGPMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()

# Removed the sorting methods from outside the class

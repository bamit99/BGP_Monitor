# BGP Monitor

## Overview

BGP Monitor is a tool for collecting, analyzing, and monitoring BGP routing updates in real-time. It connects to RIPE RIS (Routing Information Service) to receive live BGP updates, processes them, and stores them in both CSV files and a Neo4j graph database.

![image](https://github.com/user-attachments/assets/1fbdb0ef-c844-457e-a0ac-6e878dba19ae)



## Key Features

- Real-time BGP update monitoring from RIPE RIS
- AS path and prefix tracking
- Real-time BGP update collection via WebSockets from RIPE RIS.
- Data storage in Neo4j graph database and/or CSV files.
- User-friendly GUI built with Tkinter and ttkwidgets.
- Configurable filtering by AS numbers.
- Geographic region-based collector selection with location display.
- AS Information lookup using external APIs.
- Advanced security analysis:
  - **BGP Hijacking Detection:** Monitors origin AS changes using a prefix origin cache. Detects suspicious more-specific announcements of critical prefixes. Flags announcements from known bad actors.
  - **Route Leak Detection:** Implements valley-free path validation using AS relationship data (`data/as_relationships.txt.bz2`). Detects suspiciously long AS paths and paths containing private ASNs.
  - **RPKI Validation:** Validates announcements against RPKI data using the RIPEstat Validator API.
  - **Path Prepending Detection:** Identifies excessive AS path prepending based on configurable thresholds.
  - **Critical Infrastructure Monitoring:** Allows defining critical prefixes for heightened alert severity.
  - **Known Bad Actor Monitoring:** Flags updates involving ASNs listed as known bad actors.
  - **Advanced Event/Episode Aggregation:** Groups related security alerts into "episodes" based on prefix, origin AS, and time window. Each episode is scored, enriched with metadata (hijack scope, subtype, AS path edit distance), and stored in Neo4j for high-level incident analysis.
- Configurable security heuristics (thresholds, severity) via `config/app_settings.json`.
- Detailed security alert logging to standard logging, daily CSV files (`data/security_alerts/`), and Neo4j.
- **Episode Storage, Persistence & Analytics:** Episodes are stored in Neo4j, loaded on startup for persistence, and can be queried for incident analysis. (See "Episode Aggregation" below.)
- Configurable Syslog forwarding with JSON formatting for SIEM integration.
- GUI panels for viewing BGP updates, security alerts, and aggregated episodes.
- Database connection status indicator and entry count display.
- Automatic reconnection logic for WebSocket connections.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/bgp-monitor.git
cd bgp-monitor
```

2. Install required dependencies:
```bash
conda create -n bgpmon python=3.11
conda activate bgpmon
pip install -r requirements.txt
```

3. Configure Neo4j database connection (optional):
   - Copy the configuration template:
   ```bash
   cp config/database_config_template.ini config/database_config.ini
   ```
   - Edit the configuration file with your Neo4j credentials:
   ```bash
   # Edit config/db_config.json (Recommended)
   {
     "uri": "bolt://localhost:7687",
     "username": "neo4j",
     "password": "your_password"
   }

   # Or, edit config/database_config.ini (Less preferred)
   [neo4j]
   uri = bolt://localhost:7687
   username = neo4j
   password = your_password
   ```
   *Note: Configuration is primarily managed via `utils/config_manager.py` which favors `db_config.json`.*

## Running the Application

Ensure your Neo4j instance (if used) is running.

To start the BGP Monitor:

```bash
python main.py
```

This will launch the GUI interface.

## Configuration

### Central Configuration (`utils/config_manager.py`)

Configuration is managed centrally via `utils/config_manager.py`, loading settings primarily from JSON files in the `config/` directory.

### Database Configuration (`config/db_config.json`)

Neo4j integration is optional but recommended for advanced analysis and historical data storage.

- **Using the GUI**: Click the "Connect DB" button. This opens a dialog to enter and test connection details (URI, Username, Password). Saving updates `config/db_config.json`.
- **Manual Edit**: Directly edit `config/db_config.json` before starting the application.

### Security Configuration (`config/security_config.json`)

This file defines parameters for the security analysis module (`utils/security_analyzer.py`):

- **`critical_prefixes`**: A list of IP prefixes considered critical. Announcements affecting these prefixes may trigger higher severity alerts or specific checks (e.g., more-specific announcements).
- **`known_bad_actors`**: A list of ASNs identified as sources of malicious BGP activity. Updates involving these ASNs trigger alerts. Populate this based on your threat intelligence.
- **`trusted_transit_asns`**: A list of ASNs generally considered reliable transit providers. (Currently used for context, potential future checks).

*If `security_config.json` is missing, it will be created with example default values.*

### Application Settings (`config/app_settings.json`)

This file controls general application behavior, logging, and security heuristic tuning:

### GUI Settings (`config/gui_settings.json`)

The application saves GUI state (selected region, collectors, AS filters) to this file on exit and loads them on startup.

```json
{
```json
{
  "logging": {
    "level": "INFO",
    "syslog": {
      "enabled": false,
      "host": "localhost",
      "port": 514,
      "protocol": "UDP"
    }
  },
  "security_analysis": {
    "heuristics": {
      "long_path": {
        "enabled": true,
        "threshold": 30,
        "severity": "LOW"
      },
      "prepending": {
        "enabled": true,
        "threshold": 5,
        "severity": "LOW"
      },
      "more_specific": {
        "enabled": true,
        "prefix_length_diff": 4,
        "severity": "MEDIUM"
      }
      // Add other potential heuristics here if needed
    }
  }
  // Other application settings can be added here
}
```

- **`logging.level`**: Minimum logging level for standard output/file logging (e.g., "DEBUG", "INFO", "WARNING", "ERROR").
- **`logging.syslog.enabled`**: Set to `true` to enable Syslog forwarding.
- **`logging.syslog.host`**: IP address or hostname of the Syslog server.
- **`logging.syslog.port`**: Port number for the Syslog server.
- **`logging.syslog.protocol`**: Protocol ("UDP" or "TCP"). Logs are sent in JSON format using a custom formatter (`main.py:JsonSyslogFormatter`).
- **`security_analysis.heuristics.*.enabled`**: Enable or disable specific heuristic checks (e.g., `long_path`, `prepending`, `more_specific`).
- **`security_analysis.heuristics.*.threshold`**: Adjust detection thresholds (e.g., max path length for `long_path`, repetition count for `prepending`, prefix length difference for `more_specific`).
- **`security_analysis.heuristics.*.severity`**: Set the default alert severity ("LOW", "MEDIUM", "HIGH") if an alert is triggered *solely* by that specific heuristic. The final alert severity is the highest severity among all triggered reasons.

*If `app_settings.json` is missing, it will be created with default values upon first run.*

## Episode Aggregation

### What is an Episode?

An **episode** is a group of related BGP security alerts (e.g., hijacks, leaks, RPKI invalids) that affect the same prefix and origin AS within a configurable time window. Instead of treating every alert as an isolated event, the system aggregates them into episodes, providing a higher-level view of ongoing or recent security incidents.

- **Scoring:** Each episode is assigned a score based on the severity and type of its constituent alerts, with configurable multipliers for critical prefixes, origin changes, and RPKI invalids.
- **Metadata:** Episodes are enriched with metadata such as hijack scope, subtype (e.g., origin change, more-specific), AS path edit distance, and affected ASNs.
- **Storage & Persistence:** Episodes are stored in the Neo4j database and active episodes are loaded on application startup for persistence across restarts. They can be queried for analytics, reporting, or incident review.
- **Viewing Episodes:** A dedicated "Episodes" tab in the GUI displays a summary of active episodes. The CLI command below can still be used for direct database queries.

#### Example: Listing Active Episodes

To view active episodes in the database, run:
```bash
python -c "from utils.db_manager import BGPDatabaseManager; import config.database_config as db_config; db = BGPDatabaseManager(db_config.NEO4J_CONFIG['uri'], db_config.NEO4J_CONFIG['username'], db_config.NEO4J_CONFIG['password']); print(db.get_active_episodes())"
```
This will print a list of episode summaries, each with fields like prefix, origin AS, time window, max severity, score, event count, and metadata.

## Usage

1.  **Configure**: Set up database connection (`Connect DB` button or `config/db_config.json`) and Syslog (`Syslog Settings` button or `config/app_settings.json`) if needed. Review `config/security_config.json` and `config/app_settings.json` for security parameters and heuristics.
2.  **Select Region & Collectors**: Choose a geographic region and one or more RIPE RIS collectors from the GUI lists. Collector locations are displayed.
3.  **Set AS Filters (Optional)**: Enter AS numbers (e.g., "AS64512" or "64512") in the "AS Number Filtering" section and click "Add Filter". Only updates whose AS path contains at least one of the filtered ASNs will be processed. Use "Remove Filter" or "Clear All" to manage filters.
4.  **AS Info (Optional)**: Select an AS number in the filter list and click "AS Info" to look up details about that AS using multiple sources, including PeeringDB for richer context (e.g., network type, IX/facility counts).
5.  **Start Monitoring**: Click "Start Monitoring". The button changes to "Stop Monitoring".
6.  **View Updates**: Real-time BGP updates (announcements and withdrawals) matching filters appear in the "BGP Updates" log panel.
7.  **Monitor Security Alerts & Episodes**:
    - The "Security Alerts" tab displays individual detected potential issues (hijacks, leaks, RPKI invalid, etc.). Click column headers to sort or "Export Alerts" to save.
    - The "Episodes" tab displays aggregated incidents based on related alerts. Click "Refresh Episodes" to update the view.
8.  **Manage Data**:
    - Click "Clear Log" to clear the "BGP Updates" panel.
    - Click "Open Data" to open the `data/` directory (containing CSV backups, AS relationship files) in your file explorer.
    - **Color Coding**: The "BGP Updates" panel uses color coding for better readability:
        - Default Announcements: Black text
        - Withdrawals: Blue text
        - Updates Triggering Security Alerts: Orange text (entire line)
        - Filtered AS Numbers: Bold Green text (applied to the specific AS number within the line, unless the line is an alert)
9.  **Stop Monitoring**: Click "Stop Monitoring".
10. **Check Status**: Monitor the DB connection LED and entry count at the bottom of the window.

## Project Structure

- **`main.py`**: Main application entry point, sets up logging (including JSON Syslog formatter), initializes and runs the GUI.
- **`gui/`**: Contains the Tkinter GUI code.
  - `main_window.py`: Defines the main application window, layout, widgets, event handling, and interaction with backend modules.
- **`src/`**: Core BGP monitoring logic.
  - `bgp_monitor.py`: Handles connecting to RIPE RIS via WebSockets, receiving messages, and dispatching them for processing.
  - `connection_manager.py`: (Potentially used for managing WebSocket connections - verify usage).
- **`utils/`**: Utility modules providing various functionalities.
  - `security_analyzer.py`: Core logic for analyzing BGP updates for security threats (hijacks, leaks, RPKI, etc.). Includes `SecurityAlertLogger`.
  - `episode_manager.py`: Aggregates security alerts into episodes, scores them, and manages episode metadata and storage.
  - `db_manager.py`: Handles all interactions with the Neo4j database (storing updates, alerts, episodes, querying data).
  - `config_manager.py`: Centralized loading and saving of configuration files (`app_settings.json`, `gui_settings.json`, `db_config.json`, `security_config.json`).
  - `bgp_utils.py`: Helper functions for BGP data, including loading and querying AS relationship data.
  - `as_lookup.py`: Fetches AS information (name, country, etc.) from external APIs.
  - `data_manager.py`: Manages file paths and operations within the `data/` directory.
  - `analysis.py`: (Potentially contains data analysis functions - verify usage).
- **`config/`**: Configuration files.
  - `app_settings.json`: General settings, logging config, security heuristics.
  - `gui_settings.json`: Saved state of the GUI (region, collectors, filters).
  - `db_config.json`: Neo4j connection details.
  - `security_config.json`: Lists of critical prefixes, bad actors, trusted ASNs.
  - `collectors.py`: Defines available RIPE RIS collectors by region.
  - `database_config.py`: Contains `BGPDatabaseManager` class definition (though instance is often created via `db_manager.py`).
  - `database_config.ini`, `db_config.json.template`: Alternative/template config files.
- **`data/`**: Directory for storing runtime data.
  - `security_alerts/`: Contains daily CSV backups of security alerts.
  - `as_relationships.txt.bz2`: (Required) File containing AS relationship data (downloaded separately, e.g., from CAIDA).
- **`tests/`**: Unit and integration tests.
- **`requirements.txt`**: Python package dependencies.
- **`README.md`**: This file.
- **`LICENSE`**: Project license information.
- **`.gitignore`**, **`.gitattributes`**: Git configuration files.

## Dependencies

Key dependencies (see `requirements.txt` for the full list and specific versions):

- `websockets`: For connecting to RIPE RIS live stream.
- `neo4j`: Python driver for Neo4j database interaction.
- `requests`: For making HTTP requests (e.g., to RPKI validator API, AS lookup).
- `pandas`: Used for data manipulation (e.g., potentially in `utils/analysis.py`).
- `ttkwidgets`: Provides additional themed widgets for the Tkinter GUI.
- `python-dateutil`: For flexible datetime parsing.
- `aiohttp`, `asyncio`: Core libraries for asynchronous operations (used by `websockets`).
- `pathlib`: Modern path manipulation (standard library).
- `ipaddress`: For IP address and network manipulation (standard library).
- `peeringdb`: For querying PeeringDB for ASN details.
- `Django`: Required dependency for the `peeringdb` library.
- `tkinter`: GUI framework (standard library).

*Note: `tkinter` is part of the standard Python library but might require separate installation on some Linux distributions (e.g., `sudo apt-get install python3-tk`).*

## Error Handling & Resilience

- **WebSocket Reconnection**: Automatically attempts to reconnect to RIPE RIS using exponential backoff if the connection drops.
- **Database Robustness**: Logs errors during database operations but attempts to continue running. Security alerts are logged to CSV as a backup if DB logging fails. Schema initialization includes checks for existing constraints/indexes.
- **Configuration Loading**: Handles missing configuration files by creating defaults.
- **API Failures**: Logs errors during RPKI validation or AS lookup API calls. RPKI validation falls back to "UNKNOWN" state on error.
- **Logging**: Comprehensive logging captures errors and warnings during operation. Syslog forwarding provides external monitoring capabilities.
- **Prefix Origin Cache**: Implements a simple size limit (`MAX_PREFIX_CACHE_SIZE`) to prevent unbounded memory growth.

## Contributing

Contributions are welcome! Please refer to the project's contribution guidelines (if available) or open an issue to discuss potential changes.

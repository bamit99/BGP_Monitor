# BGP Monitor

## Overview

BGP Monitor is a tool for collecting, analyzing, and monitoring BGP routing updates in real-time. It connects to RIPE RIS (Routing Information Service) to receive live BGP updates, processes them, and stores them in both CSV files and a Neo4j graph database.

## Key Features

- Real-time BGP update monitoring from RIPE RIS
- AS path and prefix tracking
- Neo4j graph database integration
- Advanced security analysis:
  - BGP hijacking detection
  - Route leak detection
  - Path manipulation monitoring
  - RPKI validation
  - Critical infrastructure monitoring
- Automatic failover to CSV storage
- Customizable filtering by AS numbers
- Geographic region-based collector selection
- User-friendly GUI interface with security alerts panel

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/bgp-monitor.git
cd bgp-monitor
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Configure Neo4j database connection (optional):
   - Copy the configuration template:
   ```bash
   cp config/database_config_template.ini config/database_config.ini
   ```
   - Edit the configuration file with your Neo4j credentials:
   ```bash
   # In config/database_config.ini
   [neo4j]
   uri = bolt://localhost:7687
   username = neo4j
   password = your_password
   ```

## Running the Application

To start the BGP Monitor:

```bash
python main.py
```

This will launch the GUI interface.

## Configuration

### Database Configuration

The application supports Neo4j database integration for storing and analyzing BGP updates. You can configure the database connection in three ways:

1. **Using the GUI**: Click the "Connect DB" button in the main interface to set up your Neo4j connection.

2. **Configuration Files**:
   - INI format: Edit `config/database_config.ini`
   - JSON format: Edit `config/db_config.json`

3. **Via Code**: Use the `update_neo4j_config()` function in the database_config module:
   ```python
   from config.database_config import update_neo4j_config
   
   update_neo4j_config(
       uri="bolt://localhost:7687",
       username="neo4j",
       password="your_password"
   )
   ```

### Security Configuration

The application includes advanced security monitoring features:

1. **Critical Infrastructure**: Define critical UK prefixes and ASNs in `config/security_config.json`
2. **RPKI Validation**: Uses RIPE RPKI Validator API for route validation
3. **Alert Levels**: Configurable severity levels (LOW, MEDIUM, HIGH)
4. **Data Persistence**: 
   - Stores alerts in Neo4j for analysis
   - Automatic CSV backup in `data/security_alerts/`

### GUI Settings

The application saves GUI settings such as selected region, collectors, and AS filters. These settings are stored in `config/gui_settings.json` and are loaded automatically when the application starts.

## Usage

1. **Select a Region**: Choose a geographic region from the dropdown menu.

2. **Select Collectors**: Choose one or more BGP collectors from the list.

3. **Add AS Filters**: Enter AS numbers to filter updates by specific autonomous systems.

4. **Start Monitoring**: Click the "Start Monitoring" button to begin collecting BGP updates.

5. **View Updates**: BGP updates matching your criteria will appear in the log area.

6. **Monitor Security**: The security panel shows real-time alerts for:
   - BGP hijacking attempts
   - Route leaks
   - Path manipulation
   - RPKI invalidity
   - Critical infrastructure impacts

7. **Export Data**: 
   - Use the "Export Alerts" button to save security alerts to CSV
   - Daily CSV backups are automatically maintained
   - Neo4j database stores full alert history

## Project Structure

- `main.py`: Main entry point
- `gui/`: GUI components and security panel
- `config/`: Configuration files
- `utils/`: 
  - `security_analyzer.py`: Security monitoring and analysis
  - `db_manager.py`: Neo4j database operations
  - `config_manager.py`: Configuration management
- `src/`: Core application code
- `data/`: CSV storage for updates and alerts

## Dependencies

Key dependencies (see requirements.txt for full list):
- websockets>=10.0: WebSocket client for RIPE RIS
- neo4j>=5.14.0: Neo4j database driver
- tkinter>=8.6: GUI framework
- requests>=2.25.1: HTTP client for RPKI validation
- pandas>=1.2.0: Data analysis
- python-dotenv>=1.0.0: Environment configuration

## Error Handling

The application includes robust error handling:
1. Automatic reconnection for WebSocket drops
2. Exponential backoff for connection retries
3. Failover to CSV storage if database is unavailable
4. Daily log rotation for alerts and updates

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

# BGP Monitor

A real-time BGP monitoring tool that connects to RIPE RIS collectors and stores BGP updates in both Neo4j graph database and CSV files for comprehensive analysis.

## Features

- Real-time BGP update monitoring from RIPE RIS collectors
- Region-based collector selection (Asia Pacific, Europe, etc.)
- Dual storage system:
  - Neo4j graph database for relationship analysis
  - CSV files for traditional data analysis
- AS path tracking and change detection
- Suspicious update detection
- AS information lookup from multiple sources:
  - PeeringDB
  - ARIN
  - APNIC
  - RADB
  - RIPE

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```
3. Set up Neo4j:
   - Install Neo4j Database
   - Create a new database
   - Update connection details in `config/database_config.py`

## Usage

Run the application:
```bash
python main.py
```

### Main Features

1. **Collector Selection**
   - Select region from dropdown (Asia Pacific, Europe, etc.)
   - Choose one or multiple collectors from the selected region
   - Each collector shows its location (e.g., Tokyo, Japan)

2. **BGP Update Storage**
   - Neo4j Graph Database:
     - Stores updates with relationships
     - Tracks AS path changes
     - Monitors suspicious patterns
     - Enables complex graph queries
   - CSV Storage:
     - Timestamp-based files
     - Traditional data analysis
     - Historical record keeping

3. **AS Path Analysis**
   - Real-time AS path change detection
   - Suspicious pattern monitoring:
     - Multiple rapid changes
     - Unusual path lengths
     - Unexpected AS appearances
   - Graph-based relationship analysis

4. **BGP Update Monitoring**
   - Start/Stop monitoring from selected collectors
   - View real-time updates in log window
   - Updates show:
     - Timestamp
     - Prefix
     - Next Hop
     - Peer AS
     - AS Path
     - Origin
     - Withdrawals (if any)

5. **Data Analysis**
   - Neo4j Browser for graph queries
   - CSV files for traditional analysis
   - Built-in validation tools
   - Suspicious update tracking

## File Structure

### Core Components
- `main.py` - Application entry point, initializes GUI and signal handlers
- `bgp_collector.py` - Main BGP update collector implementation
- `src/`
  - `bgp_monitor.py` - Core BGP monitoring and update processing
  - `connection_manager.py` - Manages WebSocket connections to RIPE RIS collectors

### Configuration
- `config/`
  - `database_config.py` - Neo4j database connection configuration
  - `collectors.py` - RIPE RIS collector definitions and region mapping

### GUI Components
- `gui/`
  - `main_window.py` - Main GUI implementation with monitoring controls and visualization

### Utility Modules
- `utils/`
  - `analysis.py` - BGP update analysis and pattern detection
  - `as_lookup.py` - AS information lookup from various sources
  - `bgp_utils.py` - BGP-specific utility functions
  - `config_manager.py` - Configuration file management
  - `data_manager.py` - CSV file storage management
  - `db_manager.py` - Neo4j database operations

### Testing and Validation
- `tests/`
  - `validate_neo4j_data.py` - Validates data integrity in Neo4j
  - `test_neo4j_connection.py` - Tests Neo4j connection and basic operations
  - `test_websocket.py` - Tests WebSocket connectivity to collectors
  - `query_suspicious.py` - Tests suspicious update detection
  - `verify_live_updates.py` - Validates live update processing

### Data Storage
- `data/` - BGP update CSV files
- `logs/` - Application logs

## Neo4j Graph Structure

### Nodes
- Update: BGP update information
- Prefix: Network prefixes
- AS: Autonomous System nodes
- Collector: RIPE RIS collectors

### Relationships
- ANNOUNCES: Update to Prefix
- PEERS_WITH: AS to AS connections
- RECEIVED: Collector to Update
- AFFECTS: Update to affected entities

## Dependencies

- `neo4j`: Graph database driver
- `websockets`: BGP collector connection
- `pandas`: Data management
- `networkx`: Network graph analysis
- `plotly`: Interactive visualizations
- `tkinter`: GUI framework

## Testing

The project includes several test scripts for different components:

```bash
# Test Neo4j database integration
python tests/test_neo4j_connection.py

# Validate stored data integrity
python tests/validate_neo4j_data.py

# Test WebSocket connectivity
python tests/test_websocket.py

# Verify live update processing
python tests/verify_live_updates.py

# Test suspicious update detection
python tests/query_suspicious.py
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

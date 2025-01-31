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

- `collected_data/` - BGP update CSV files
- `config/` - Configuration files
- `gui/` - GUI components
- `utils/` - Utility functions
- `tests/` - Test and validation scripts
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

Run the validation script to check Neo4j integration:
```bash
python tests/validate_neo4j_data.py
```

For more detailed documentation of each component, please see `HELP.md`.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

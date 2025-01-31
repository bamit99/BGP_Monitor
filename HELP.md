# BGP Monitor - Code Documentation

This document provides an overview of each Python file in the BGP Monitor repository and its function.

## Core Files

### bgp_collector.py
The main BGP data collection script that:
- Connects to RIPE RIS WebSocket API
- Collects live BGP updates
- Processes and stores updates in both CSV and Neo4j
- Analyzes updates for suspicious patterns
- Tracks AS path changes

### main.py
Entry point for the application that:
- Initializes the BGP collector
- Sets up logging
- Handles application startup

## Configuration Files

### config/database_config.py
Contains Neo4j database configuration including:
- URI
- Username
- Password
- Connection settings

### config/collectors.py
Defines available RIPE RIS collectors and their locations:
- List of RRC (Route Collectors)
- Geographic locations
- Default collector settings

## Utilities

### utils/db_manager.py
Neo4j database management class that:
- Handles database connections
- Stores BGP updates
- Creates graph relationships
- Manages suspicious updates

## Tests

### tests/test_neo4j_connection.py
Test script to verify Neo4j connectivity and operations:
- Tests database connection
- Validates data storage
- Checks relationship creation

### tests/validate_neo4j_data.py
Validation script that:
- Checks stored BGP data
- Validates graph relationships
- Provides data statistics

## GUI Components

### gui/main_window.py
Main GUI window implementation for:
- Displaying live BGP updates
- Visualizing AS path changes
- Showing suspicious updates
- Managing collector settings

## Directory Structure

- `collected_data/`: Stores CSV files with BGP updates
- `config/`: Configuration files
- `gui/`: GUI-related code
- `logs/`: Application log files
- `tests/`: Test scripts
- `utils/`: Utility functions and classes

## Common Operations

### Starting the BGP Monitor
```bash
python main.py
```

### Running Tests
```bash
python tests/test_neo4j_connection.py
python tests/validate_neo4j_data.py
```

### Checking Data
1. CSV data is stored in `collected_data/`
2. Neo4j data can be queried using Neo4j Browser
3. Application logs are in `bgp_collector.log`

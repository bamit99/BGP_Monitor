# BGP Monitor

A real-time BGP monitoring tool that connects to RIPE RIS collectors and allows filtering of BGP updates by AS numbers.

## Features

- Real-time BGP update monitoring from RIPE RIS collectors
- Region-based collector selection (Asia Pacific, Europe, etc.)
- AS path filtering with real-time feedback
- AS information lookup from multiple sources:
  - PeeringDB
  - ARIN
  - APNIC
  - RADB
  - RIPE
- Automatic data storage in CSV format with timestamps

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

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

2. **AS Filtering**
   - Add AS numbers via entry field
   - View added AS numbers in listbox
   - Remove selected AS numbers
   - Clear all AS filters
   - Only see BGP updates containing filtered AS numbers in paths

3. **AS Information Lookup**
   - Look up AS details by selecting from list or entering AS number
   - View comprehensive AS information:
     - Basic details (Name, Description)
     - Network information (Type, Scope, Traffic levels)
     - Location information
     - Peering policies
     - Website
   - Information is cached locally for 24 hours

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
   - Automatic CSV storage with all update details

5. **Data Management**
   - CSV files created automatically with timestamps
   - Direct "Open Data" button to access stored files
   - AS information cached in cache directory
   - Clear log functionality

## File Structure

- `data/` - BGP update CSV files (automatically created)
- `cache/` - AS information cache
- `gui/` - GUI components
- `utils/` - Utility functions
- `config/` - Configuration files

## Notes

- The application creates necessary directories automatically
- AS information is cached for 24 hours for faster lookups
- Data files are stored with timestamps for easy tracking
- All generated files (cache, data) are git-ignored

## Dependencies

- `websockets`: BGP collector connection
- `pandas`: Data management
- `matplotlib`: Static plotting
- `seaborn`: Statistical visualizations
- `networkx`: Network graph analysis
- `plotly`: Interactive visualizations
- `tkinter`: GUI framework

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0) - see the [LICENSE](LICENSE) file for details.

Key points:
- Free for non-commercial use with proper attribution
- Commercial use requires explicit permission from the copyright holder
- Modifications allowed for non-commercial use
- Must maintain copyright and license notices

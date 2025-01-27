"""Data management utilities for BGP Monitor."""
import os
import csv
import shutil
import tempfile
import pandas as pd
import json
from datetime import datetime
from pathlib import Path
import logging

class DataManager:
    def __init__(self, base_dir="data"):
        """Initialize data manager with base directory."""
        self.base_dir = Path(base_dir)
        self.current_file = None
        self.current_writer = None
        self.csv_file = None
        self.headers = [
            'timestamp',
            'prefix',
            'peer',
            'peer_asn',
            'path',
            'next_hop',
            'type',
            'origin',
            'aggregator',
            'community',
            'withdrawals',
            'host',
            'id',
            'raw'
        ]
        self.ensure_data_directory()
        
    def ensure_data_directory(self):
        """Create data directory if it doesn't exist."""
        os.makedirs(self.base_dir, exist_ok=True)
        
    def get_current_file_path(self):
        """Get the current file path based on timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        return self.base_dir / f"bgp_updates_{timestamp}.csv"
        
    def start_or_continue_file(self):
        """Start a new CSV file or continue with existing one."""
        new_file_path = self.get_current_file_path()
        
        # If we already have this file open, keep using it
        if self.current_file == new_file_path and self.csv_file and not self.csv_file.closed:
            return self.current_file
            
        # Close any existing file
        self.close_current_file()
        
        self.current_file = new_file_path
        file_exists = self.current_file.exists()
        
        # Open file in append mode if it exists, write mode if new
        mode = 'a' if file_exists else 'w'
        self.csv_file = open(self.current_file, mode, newline='', encoding='utf-8')
        self.current_writer = csv.DictWriter(self.csv_file, fieldnames=self.headers, extrasaction='ignore')
        
        # Write header only for new files
        if not file_exists:
            self.current_writer.writeheader()
        
        return self.current_file
        
    def save_update(self, update):
        """Save BGP update to CSV file."""
        try:
            # Create a new file if needed
            if not self.current_file or not self.current_writer:
                self.start_or_continue_file()
            
            # Extract prefixes and next_hop from announcements
            prefix = 'N/A'
            next_hop = 'N/A'
            if update.get('announcements'):
                announcement = update['announcements'][0]  # Take first announcement
                prefix = ', '.join(announcement.get('prefixes', []))
                next_hop = announcement.get('next_hop', 'N/A')
            
            # Format withdrawals
            withdrawals = ', '.join(update.get('withdrawals', []))
            
            # Format the data for CSV
            row = {
                'timestamp': datetime.fromtimestamp(update['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                'prefix': prefix,
                'peer': update.get('peer', 'N/A'),
                'peer_asn': update.get('peer_asn', 'N/A'),
                'path': ' > '.join(str(asn) for asn in update.get('path', [])),
                'next_hop': next_hop,
                'type': update.get('type', 'N/A'),
                'origin': update.get('origin', 'N/A'),
                'aggregator': update.get('aggregator', 'N/A'),
                'community': str(update.get('community', [])),
                'withdrawals': withdrawals,
                'host': update.get('host', 'N/A'),
                'id': update.get('id', 'N/A'),
                'raw': json.dumps(update)
            }
            
            # Write to CSV
            self.current_writer.writerow(row)
            self.csv_file.flush()  # Ensure data is written to disk
            return True
            
        except Exception as e:
            logging.error(f"Error saving update: {str(e)}")
            return False
            
    def close_current_file(self):
        """Close the current CSV file."""
        if self.csv_file and not self.csv_file.closed:
            self.csv_file.flush()
            os.fsync(self.csv_file.fileno())  # Ensure all data is written to disk
            self.csv_file.close()
            self.csv_file = None
            self.current_writer = None
            
    def get_saved_files(self):
        """Get list of all saved data files."""
        return sorted(self.base_dir.glob("bgp_updates_*.csv"))
        
    def read_updates(self, file_path):
        """Read updates from a saved file."""
        return pd.read_csv(file_path)
        
    def check_filtered_updates(self, file_path, as_numbers):
        """Check updates in a file that match AS number filters."""
        df = self.read_updates(file_path)
        if 'path' not in df.columns:
            return pd.DataFrame()
            
        # Convert path to string and filter rows where path contains any of the AS numbers
        df['path'] = df['path'].astype(str)
        mask = df['path'].apply(lambda x: any(str(asn) in x.split(' > ') for asn in as_numbers))
        return df[mask]
        
    def __del__(self):
        """Cleanup on deletion."""
        self.close_current_file()

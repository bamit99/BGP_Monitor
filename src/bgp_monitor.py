"""Main BGP monitoring application."""
import asyncio
import logging
from datetime import datetime
from typing import Set, Dict, Any

from utils.bgp_utils import validate_as_number, parse_as_path
from config.collectors import get_collectors_by_region, get_collector_location
from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG

class BGPMonitor:
    def __init__(self):
        self.collectors: Dict[str, str] = {}
        self.active_collectors: Set[str] = set()
        self.filtered_as_numbers: Set[int] = set()
        self.running: bool = True
        
        # Initialize Neo4j database manager
        self.db_manager = BGPDatabaseManager(
            uri=NEO4J_CONFIG['uri'],
            username=NEO4J_CONFIG['username'],
            password=NEO4J_CONFIG['password']
        )
        
        # Configure logging
        logging.basicConfig(
            filename='bgp_monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def add_collector(self, collector_id: str) -> bool:
        """Add a collector to the active set."""
        location = get_collector_location(collector_id)
        if location:
            self.collectors[collector_id] = location
            self.active_collectors.add(collector_id)
            logging.info(f"Added collector: {collector_id} ({location})")
            return True
        return False
        
    def remove_collector(self, collector_id: str) -> bool:
        """Remove a collector from the active set."""
        if collector_id in self.active_collectors:
            self.active_collectors.remove(collector_id)
            logging.info(f"Removed collector: {collector_id}")
            return True
        return False
        
    def add_as_filter(self, as_number: int) -> bool:
        """Add AS number to filter set."""
        if validate_as_number(as_number):
            self.filtered_as_numbers.add(as_number)
            logging.info(f"Added AS filter: {as_number}")
            return True
        return False
        
    def remove_as_filter(self, as_number: int) -> bool:
        """Remove AS number from filter set."""
        if as_number in self.filtered_as_numbers:
            self.filtered_as_numbers.remove(as_number)
            logging.info(f"Removed AS filter: {as_number}")
            return True
        return False
        
    def should_process_update(self, update: Dict[str, Any]) -> bool:
        """Check if update should be processed based on filters."""
        if not self.filtered_as_numbers:
            return True
            
        as_path = update.get('as_path', '')
        if not as_path:
            return False
            
        path_asns = set(parse_as_path(as_path))
        return bool(path_asns & self.filtered_as_numbers)
        
    async def process_bgp_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Process BGP update message."""
        try:
            data = message.get("data", {})
            
            # Basic message info
            update_info = {
                "timestamp": datetime.fromtimestamp(data.get("timestamp", 0)),
                "collector": data.get("host", "unknown"),
                "peer_ip": data.get("peer", ""),
                "peer_asn": data.get("peer_asn", ""),
            }
            
            # Process announcements
            announcements = data.get("announcements", [])
            if announcements:
                update_info["type"] = "announcement"
                update_info.update({
                    "prefix": announcements[0].get("prefix", ""),
                    "as_path": ",".join(map(str, data.get("path", []))),
                    "communities": str(data.get("community", [])),
                    "next_hop": announcements[0].get("next_hop", "")
                })
                
            # Process withdrawals
            withdrawals = data.get("withdrawals", [])
            if withdrawals:
                update_info["type"] = "withdrawal"
                update_info["prefix"] = withdrawals[0]
                
            return update_info if self.should_process_update(update_info) else None
            
        except Exception as e:
            logging.error(f"Error processing BGP message: {e}")
            return None
            
    async def process_message(self, message: Dict[str, Any]) -> None:
        """Process BGP update message."""
        try:
            data = message.get("data", {})
            
            # Format timestamp
            timestamp = datetime.fromtimestamp(data.get("timestamp", 0))
            collector = data.get("host", "unknown")
            peer = data.get("peer", "")
            peer_asn = data.get("peer_asn", "")
            
            # Process announcements
            announcements = data.get("announcements", [])
            if announcements:
                # Get AS path once since it's the same for all prefixes in this update
                as_path = ",".join(map(str, data.get("path", [])))
                next_hop = announcements[0].get("next_hop", "") if announcements else ""
                communities = data.get("community", [])
                
                # Process each prefix in the announcement
                for announcement in announcements:
                    prefixes = announcement.get("prefixes", [])
                    if not prefixes:
                        # Try single prefix format
                        prefix = announcement.get("prefix")
                        if prefix:
                            prefixes = [prefix]
                    
                    for prefix in prefixes:
                        if not prefix:
                            continue
                            
                        # Store in Neo4j
                        self.db_manager.store_bgp_update(
                            timestamp=timestamp,
                            collector=collector,
                            peer_asn=peer_asn,
                            prefix=prefix,
                            as_path=as_path,
                            next_hop=next_hop,
                            communities=communities,
                            update_type="announcement"
                        )
                        
                        # Log the update
                        logging.info(f"Announcement - Prefix: {prefix}, AS Path: {as_path}")
            
            # Process withdrawals
            withdrawals = data.get("withdrawals", [])
            if withdrawals:
                for prefix in withdrawals:
                    # Store withdrawal in Neo4j
                    self.db_manager.store_bgp_update(
                        timestamp=timestamp,
                        collector=collector,
                        peer_asn=peer_asn,
                        prefix=prefix,
                        update_type="withdrawal"
                    )
                    
                    # Log the withdrawal
                    logging.info(f"Withdrawal - Prefix: {prefix}")
            
        except Exception as e:
            logging.error(f"Error processing BGP message: {e}")
            
    async def connect_ris(self):
        """Connect to RIPE RIS service."""
        # Implementation moved to separate connection manager
        pass
        
    def stop(self):
        """Stop the monitor."""
        self.running = False
        logging.info("BGP Monitor stopped")

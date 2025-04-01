"""Main BGP monitoring application."""
import asyncio
import logging
import json
import time
from datetime import datetime
from typing import Set, Dict, Any

from utils.bgp_utils import validate_as_number, parse_as_path
from config.collectors import get_collectors_by_region, get_collector_location
from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG
import websockets

class BGPMonitor:
    """BGP Monitor class for handling BGP update streams."""
    
    def __init__(self, use_db=False):
        """Initialize BGP Monitor."""
        self.websocket = None
        self.is_monitoring = False
        self.db_manager = None
        self._last_keepalive = None
        self._keepalive_interval = None
        self._keepalive_timeout = None
        
        if use_db:
            try:
                uri = NEO4J_CONFIG['uri']
                username = NEO4J_CONFIG['username']
                password = NEO4J_CONFIG['password']
                self.db_manager = BGPDatabaseManager(uri, username, password)
            except Exception as e:
                logging.error(f"Failed to initialize database: {e}")
                
    async def monitor_updates(self, collectors, callback, keepalive_interval=30, keepalive_timeout=35):
        """
        Monitor BGP updates from specified collectors.
        
        Args:
            collectors: List of collector IDs
            callback: Function to call with updates
            keepalive_interval: Seconds between keepalive pings
            keepalive_timeout: Seconds to wait for keepalive response
        """
        self.is_monitoring = True
        self._keepalive_interval = keepalive_interval
        self._keepalive_timeout = keepalive_timeout
        
        try:
            # Connect to WebSocket
            uri = "wss://ris-live.ripe.net/v1/ws/"
            async with websockets.connect(uri) as websocket:
                self.websocket = websocket
                
                # Subscribe to collectors
                for collector in collectors:
                    await self._subscribe(collector)
                
                # Start keepalive task
                keepalive_task = asyncio.create_task(self._keepalive_loop())
                
                # Main message loop
                while self.is_monitoring:
                    try:
                        message = await asyncio.wait_for(
                            websocket.recv(),
                            timeout=self._keepalive_timeout
                        )
                        self._last_keepalive = time.time()
                        
                        # Process message
                        data = json.loads(message)
                        if callback:
                            callback(data)
                            
                    except asyncio.TimeoutError:
                        if time.time() - self._last_keepalive > self._keepalive_timeout:
                            raise ConnectionError("Keepalive timeout")
                            
                # Clean up
                keepalive_task.cancel()
                try:
                    await keepalive_task
                except asyncio.CancelledError:
                    pass
                    
        except Exception as e:
            logging.error(f"WebSocket error: {e}")
            raise
        finally:
            self.websocket = None
            
    async def _keepalive_loop(self):
        """Send periodic keepalive pings."""
        try:
            while self.is_monitoring and self.websocket:
                await asyncio.sleep(self._keepalive_interval)
                if self.websocket and self.websocket.open:
                    await self.websocket.ping()
                    self._last_keepalive = time.time()
        except Exception as e:
            logging.error(f"Keepalive error: {e}")
            
    async def _subscribe(self, collector):
        """Subscribe to a collector."""
        if not self.websocket:
            return False
            
        try:
            subscribe_message = {
                "type": "ris_subscribe",
                "data": {
                    "host": collector
                }
            }
            await self.websocket.send(json.dumps(subscribe_message))
            return True
        except Exception as e:
            logging.error(f"Subscribe error for {collector}: {e}")
            return False
            
    def stop_monitoring(self):
        """Stop monitoring BGP updates."""
        self.is_monitoring = False
        
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
                
            return update_info
            
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
                            
                        # Store in Neo4j if available
                        if self.db_manager:
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
                    # Store withdrawal in Neo4j if available
                    if self.db_manager:
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
        self.stop_monitoring()
        logging.info("BGP Monitor stopped")

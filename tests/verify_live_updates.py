import asyncio
import json
import logging
from datetime import datetime
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.connection_manager import ConnectionManager
from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - %(message)s')

async def process_message(message):
    """Process and store BGP update message."""
    try:
        if isinstance(message, str):
            data = json.loads(message)
        else:
            data = message

        logging.debug(f"Raw message received: {message}")
        logging.debug(f"Parsed message structure:\n{json.dumps(data, indent=2)}")

        if data.get('type') == 'ris_message':
            update = data.get('data', {})
            
            # Format timestamp (convert from Unix milliseconds to datetime)
            unix_ms = update.get('timestamp', 0)
            timestamp = datetime.fromtimestamp(unix_ms / 1000.0)
            logging.debug(f"Parsed timestamp: {timestamp} (from Unix ms: {unix_ms})")
            
            collector = update.get('host', 'unknown')
            peer_asn = str(update.get('peer_asn', ''))
            
            logging.info(f"Received update from {collector} at {timestamp}")
            logging.debug(f"Update data: {json.dumps(update, indent=2)}")
            
            # Store in Neo4j
            db_manager = BGPDatabaseManager(**NEO4J_CONFIG)
            
            # Process announcements
            if 'announcements' in update:
                path = update.get('path', [])
                as_path = ','.join(map(str, path)) if path else ''
                for announcement in update['announcements']:
                    next_hop = announcement.get('next_hop', '')
                    prefixes = announcement.get('prefixes', [])
                    if not prefixes:
                        prefix = announcement.get('prefix')
                        if prefix:
                            prefixes = [prefix]
                    
                    for prefix in prefixes:
                        if prefix:
                            logging.info(f"Storing announcement for prefix {prefix}")
                            logging.debug(f"Announcement details: collector={collector}, peer_asn={peer_asn}, as_path={as_path}, next_hop={next_hop}")
                            try:
                                success = db_manager.store_bgp_update(
                                    timestamp=timestamp,
                                    collector=collector,
                                    peer_asn=peer_asn,
                                    prefix=prefix,
                                    as_path=as_path,
                                    next_hop=next_hop,
                                    update_type="announcement"
                                )
                                if success:
                                    logging.info(f"Successfully stored announcement for prefix {prefix}")
                                else:
                                    logging.error(f"Failed to store announcement for prefix {prefix}")
                            except Exception as e:
                                logging.error(f"Error storing announcement: {e}", exc_info=True)
            
            # Process withdrawals
            if 'withdrawals' in update:
                for prefix in update['withdrawals']:
                    logging.info(f"Storing withdrawal for prefix {prefix}")
                    logging.debug(f"Withdrawal details: collector={collector}, peer_asn={peer_asn}")
                    try:
                        success = db_manager.store_bgp_update(
                            timestamp=timestamp,
                            collector=collector,
                            peer_asn=peer_asn,
                            prefix=prefix,
                            update_type="withdrawal"
                        )
                        if success:
                            logging.info(f"Successfully stored withdrawal for prefix {prefix}")
                        else:
                            logging.error(f"Failed to store withdrawal for prefix {prefix}")
                    except Exception as e:
                        logging.error(f"Error storing withdrawal: {e}", exc_info=True)
            
    except Exception as e:
        logging.error(f"Error processing message: {e}", exc_info=True)

async def main():
    # Initialize connection manager with our callback
    connection_manager = ConnectionManager(process_message)
    
    try:
        # Connect to RIPE RIS
        if not await connection_manager.connect():
            logging.error("Failed to connect to RIPE RIS")
            return
        
        # Subscribe to updates
        if await connection_manager.subscribe():
            logging.info("Successfully subscribed to BGP updates")
        else:
            logging.error("Failed to subscribe to BGP updates")
            return
        
        # Listen for 30 seconds
        logging.info("Listening for updates (30 seconds)...")
        try:
            await asyncio.sleep(30)
        finally:
            connection_manager.stop()
            
    except Exception as e:
        logging.error(f"Error in main: {e}")

if __name__ == "__main__":
    asyncio.run(main())

import asyncio
import websockets
import json
import datetime
import pandas as pd
from pathlib import Path
import logging
import sys
from websockets.exceptions import ConnectionClosed, WebSocketException
import ssl
import signal
from utils.db_manager import BGPDatabaseManager
from config.database_config import NEO4J_CONFIG
from utils.security_analyzer import check_suspicious_patterns as security_check

# Set up logging with more detailed format
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

# Create file handler with immediate flush
file_handler = logging.FileHandler(log_dir / 'bgp_collector.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'))

# Create console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'))

# Configure root logger
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

class RIPECollector:
    def __init__(self):
        self.websocket_url = "wss://ris-live.ripe.net/v1/ws/"
        self.data_dir = Path("collected_data")
        self.data_dir.mkdir(exist_ok=True)
        self.retry_attempts = 3
        self.retry_delay = 5  # seconds
        self.running = True
        
        # Initialize database manager with config
        self.db_manager = BGPDatabaseManager(
            uri=NEO4J_CONFIG['uri'],
            username=NEO4J_CONFIG['username'],
            password=NEO4J_CONFIG['password']
        )
        
        # Define available RRC collectors
        self.collectors = {
            "rrc01": "London, United Kingdom (LINX)",
            "rrc12": "Frankfurt, Germany (DE-CIX)",
            "rrc21": "Paris, France (France-IX)",
            "rrc03": "Amsterdam, Netherlands (NL-IX)",
            "rrc04": "Geneva, Switzerland (CIXP)",
            "rrc05": "Vienna, Austria (VIX)"
        }
        
        # Default collectors for UK-based monitoring
        self.active_collectors = ["rrc01", "rrc12"]  # London and Frankfurt by default
        
        # Print collector information
        print("\nBGP Route Collector Information:")
        print("=" * 50)
        print("Active collectors:")
        for collector in self.active_collectors:
            print(f"- {collector}: {self.collectors[collector]}")
        print("=" * 50 + "\n")

        # Track important routing changes
        self.prefix_history = {}  # Track prefix changes
        self.as_path_changes = {}  # Track AS path changes
        self.suspicious_updates = []  # Track potentially suspicious updates

    def handle_signal(self, signum, frame):
        """Handle interrupt signals"""
        print("\nReceived interrupt signal. Cleaning up...")
        self.running = False

    async def connect_ris(self):
        """Establish connection to RIPE RIS WebSocket with retry logic."""
        for attempt in range(self.retry_attempts):
            try:
                print(f"\nAttempting to connect to RIPE RIS (Attempt {attempt + 1}/{self.retry_attempts})")
                
                # Create SSL context with modern security settings
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = True
                ssl_context.verify_mode = ssl.CERT_REQUIRED

                connection = await websockets.connect(
                    self.websocket_url,
                    ssl=ssl_context,
                    ping_interval=20,
                    ping_timeout=20,
                    close_timeout=10
                )
                print(f"✓ Successfully connected to RIPE RIS WebSocket")
                return connection
            except Exception as e:
                print(f"✗ Connection attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.retry_attempts - 1:
                    print(f"  Retrying in {self.retry_delay} seconds...")
                    await asyncio.sleep(self.retry_delay)
                else:
                    print("✗ Max retry attempts reached")
                    return None

    async def maintain_connection(self, websocket):
        """Keep the connection alive by sending periodic ping messages."""
        try:
            while self.running:
                try:
                    await websocket.ping()
                    await asyncio.sleep(15)
                except Exception:
                    break
        except asyncio.CancelledError:
            pass

    def analyze_update(self, timestamp, prefix, as_path, peer_asn, collector, next_hop=None, communities=None, update_type="announcement"):
        """Analyze BGP updates for significant changes and potential issues."""
        try:
            # Store update in Neo4j
            self.db_manager.store_bgp_update(
                timestamp=timestamp,
                collector=collector,
                peer_asn=peer_asn,
                prefix=prefix,
                as_path=as_path,
                next_hop=next_hop,
                communities=communities,
                update_type=update_type
            )
            
            # 1. Track prefix history
            if prefix not in self.prefix_history:
                self.prefix_history[prefix] = []
            self.prefix_history[prefix].append({
                'timestamp': timestamp,
                'as_path': as_path,
                'peer_asn': peer_asn
            })
            
            # 2. Check for AS path changes
            if prefix in self.prefix_history and len(self.prefix_history[prefix]) > 1:
                prev_path = self.prefix_history[prefix][-2]['as_path']
                if prev_path != as_path:
                    change = {
                        'timestamp': timestamp,
                        'prefix': prefix,
                        'old_path': prev_path,
                        'new_path': as_path
                    }
                    self.as_path_changes[prefix] = change
                    logging.warning(f"AS Path Change: {prefix} changed from {prev_path} to {as_path}")
                    print(f"\n⚠️ Route Change Detected:")
                    print(f"Prefix: {prefix}")
                    print(f"Old Path: {prev_path}")
                    print(f"New Path: {as_path}")
            
            # 3. Check for suspicious patterns
            alert = security_check(timestamp, prefix, as_path, peer_asn, self.prefix_history, self.db_manager)
            if alert:
                self.suspicious_updates.append(alert)
            
        except Exception as e:
            logging.error(f"Error in analyze_update: {e}")

    async def process_bgp_message(self, message):
        """Process and format BGP update message."""
        try:
            data = message.get("data", {})
            
            # Format timestamp
            timestamp = datetime.datetime.fromtimestamp(data.get("timestamp", 0))
            collector = data.get("host", "unknown")
            peer = data.get("peer", "")
            peer_asn = data.get("peer_asn", "")
            
            # Process announcements
            announcements = data.get("announcements", [])
            if announcements:
                print(f"\n{'='*80}")
                print(f"Time: {timestamp}")
                print(f"Collector: {collector} (Peer AS{peer_asn})")
                print(f"Type: BGP Announcement")
                
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
                            
                        print(f"\nPrefix: {prefix}")
                        print(f"AS Path: {as_path}")
                        print(f"Next Hop: {next_hop}")
                        if communities:
                            print(f"Communities: {communities}")
                        
                        # Store in Neo4j and analyze this update
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
                        self.analyze_update(timestamp, prefix, as_path, peer_asn, collector)
                    
                print(f"{'='*80}")
            
            # Process withdrawals
            withdrawals = data.get("withdrawals", [])
            if withdrawals:
                print(f"\n{'='*80}")
                print(f"Time: {timestamp}")
                print(f"Collector: {collector} (Peer AS{peer_asn})")
                print(f"Type: BGP Withdrawal")
                
                for prefix in withdrawals:
                    print(f"\nPrefix: {prefix}")
                    
                    # Store withdrawal in Neo4j
                    self.db_manager.store_bgp_update(
                        timestamp=timestamp,
                        collector=collector,
                        peer_asn=peer_asn,
                        prefix=prefix,
                        update_type="withdrawal"
                    )
                    self.analyze_update(timestamp, prefix, None, peer_asn, collector, update_type="withdrawal")
                
                print(f"{'='*80}")
            
            return None
            
        except Exception as e:
            print(f"\n✗ Error processing BGP message: {e}")
            return None

    def generate_report(self):
        """Generate a summary report of routing changes and potential issues."""
        print("\n📊 BGP Monitoring Report")
        print("=" * 80)
        
        # 1. Route Changes Summary
        print("\n🔄 Recent Route Changes:")
        for prefix, change in self.as_path_changes.items():
            print(f"\nPrefix: {prefix}")
            print(f"Time: {change['timestamp']}")
            print(f"Old Path: {change['old_path']}")
            print(f"New Path: {change['new_path']}")
        
        # 2. Suspicious Activities
        print("\n⚠️ Suspicious Activities Detected:")
        for alert in self.suspicious_updates[-5:]:  # Show last 5 alerts
            print(f"\nPrefix: {alert['prefix']}")
            print(f"Time: {alert['timestamp']}")
            print(f"AS Path: {alert['as_path']}")
            for reason in alert['reasons']:
                print(f"- {reason}")
        
        # 3. Most Active Prefixes
        print("\n📈 Most Active Prefixes:")
        prefix_activity = {p: len(h) for p, h in self.prefix_history.items()}
        most_active = sorted(prefix_activity.items(), key=lambda x: x[1], reverse=True)[:5]
        for prefix, changes in most_active:
            print(f"{prefix}: {changes} updates")

    async def collect_bgp_data(self, collection_time=300):
        """Main method to collect BGP data."""
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)

        websocket = None
        try:
            websocket = await self.connect_ris()
            if not websocket:
                print("✗ Failed to establish connection")
                return

            # Subscribe to BGP updates
            print("\nSubscribing to collectors:")
            for collector in self.active_collectors:
                try:
                    subscription = {
                        "type": "ris_subscribe",
                        "data": {
                            "host": collector,
                            "type": "ALL",
                            "socketOptions": {
                                "acknowledge": True
                            }
                        }
                    }
                    
                    print(f"\nSending subscription to {collector}:")
                    print(json.dumps(subscription, indent=2))
                    
                    await websocket.send(json.dumps(subscription))
                    print(f"✓ Subscription sent to {collector}: {self.collectors[collector]}")
                    await asyncio.sleep(1)  # Small delay between subscriptions
                    
                except Exception as e:
                    print(f"✗ Failed to subscribe to {collector}: {e}")

            print("\nMonitoring BGP updates...")
            print("=" * 50)
            
            start_time = datetime.datetime.now()
            updates = []
            update_counts = {collector: 0 for collector in self.active_collectors}
            last_save_time = datetime.datetime.now()
            message_count = 0

            while self.running and (datetime.datetime.now() - start_time).seconds < collection_time:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=30)
                    message_count += 1
                    
                    # Print every 10th raw message for debugging
                    if message_count % 10 == 0:
                        print(f"\nRaw message #{message_count}:")
                        print(message[:200] + "..." if len(message) > 200 else message)
                    
                    message = json.loads(message)
                    
                    if message.get("type") == "ris_message":
                        collector = message.get("data", {}).get("host", "unknown")
                        await self.process_bgp_message(message)
                        
                        # Print update statistics
                        print("\rMessages received: {}".format(
                            message_count
                        ), end="")

                    elif message.get("type") == "ris_error":
                        error_data = message.get("data", {})
                        print(f"\n✗ Error from collector: {error_data}")
                        print(f"Full error message: {message}")
                    
                    elif message.get("type") == "ris_response":
                        response_data = message.get("data", {})
                        print(f"\nReceived response:")
                        print(json.dumps(response_data, indent=2))
                    
                except asyncio.TimeoutError:
                    if self.running:
                        print("\nChecking connection status...")
                        try:
                            pong = await websocket.ping()
                            await asyncio.wait_for(pong, timeout=10)
                            print("✓ Connection alive")
                        except:
                            print("✗ Connection lost, attempting to reconnect...")
                            websocket = await self.connect_ris()
                            if websocket:
                                print("✓ Reconnected successfully")
                            else:
                                print("✗ Reconnection failed")
                                break
                
                except (WebSocketException, ConnectionClosed) as e:
                    print(f"\n✗ WebSocket error: {e}")
                    print("Attempting to reconnect...")
                    websocket = await self.connect_ris()
                    if not websocket:
                        print("✗ Reconnection failed")
                        break
                    continue
                
                except json.JSONDecodeError as e:
                    print(f"\n✗ Invalid message format: {e}")
                    continue
                
                except Exception as e:
                    print(f"\n✗ Unexpected error: {e}")
                    if not self.running:
                        break
                    continue

        except Exception as e:
            print(f"\n✗ Critical error: {e}")
        finally:
            if websocket:
                try:
                    await websocket.close()
                except:
                    pass
            # Close Neo4j connection
            self.db_manager.close()
            
            print("\n\nFinal Update Statistics:")
            print("=" * 50)
            for collector, count in update_counts.items():
                print(f"{collector} ({self.collectors[collector]}): {count} updates")
            print("=" * 50)
            self.generate_report()

async def main():
    collector = RIPECollector()
    try:
        print("Starting BGP data collection...")
        await collector.collect_bgp_data()
    except KeyboardInterrupt:
        print("\nReceived keyboard interrupt. Shutting down...")
    except Exception as e:
        print(f"Error in main: {e}")
    finally:
        print("BGP data collection completed")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete")
    except Exception as e:
        print(f"Fatal error: {e}")

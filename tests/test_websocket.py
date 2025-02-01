"""Test WebSocket connection to RIPE RIS Live service."""
import sys
import json
import asyncio
import websockets
from pathlib import Path
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

def print_header(text):
    """Print a section header."""
    print(f"\n{text}")
    print("=" * 50)

async def test_websocket():
    """Test WebSocket connection and message reception."""
    uri = "wss://ris-live.ripe.net/v1/ws/"
    messages_received = 0
    valid_messages = 0
    test_passed = False
    
    try:
        print_header("Testing WebSocket Connection")
        
        # Set connection timeout
        async with websockets.connect(uri, ping_interval=None, close_timeout=20) as websocket:
            # 1. Test Connection
            print("\n1. Testing Connection...")
            try:
                await websocket.ping()
                print("✓ Connection established")
            except Exception as e:
                print(f"✗ Connection failed: {str(e)}")
                return False
            
            # 2. Send Subscription
            print("\n2. Sending Subscription...")
            subscription = {
                "type": "ris_subscribe",
                "data": {
                    "host": "rrc01.ripe.net",
                    "type": "UPDATE",
                    "require": "announcements"
                }
            }
            
            try:
                await websocket.send(json.dumps(subscription))
                print("✓ Subscription sent")
            except Exception as e:
                print(f"✗ Subscription failed: {str(e)}")
                return False
            
            # 3. Receive Messages
            print("\n3. Receiving Messages...")
            start_time = datetime.now()
            
            try:
                for i in range(20):
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                        messages_received += 1
                        
                        data = json.loads(message)
                        msg_data = data.get('data', {})
                        
                        if (data.get('type') == 'ris_message' and
                            msg_data.get('host') == 'rrc01.ripe.net'):
                            
                            announcements = msg_data.get('announcements', [])
                            peer_asn = msg_data.get('peer_asn')
                            
                            if announcements and peer_asn:
                                valid_messages += 1
                                status = "✓"
                                
                                # Get the first announcement's path
                                first_announcement = announcements[0] if announcements else {}
                                prefix = first_announcement.get('prefix', 'Unknown')
                                as_path = msg_data.get('path', [])  # Path is at the message level
                                
                                print(f"\n{status} Message {messages_received}:")
                                print(f"  Peer ASN: {peer_asn}")
                                print(f"  Prefix: {prefix}")
                                print(f"  AS Path: {','.join(map(str, as_path)) if as_path else 'No path'}")
                                if len(announcements) > 1:
                                    print(f"  Additional Announcements: {len(announcements)-1}")
                            else:
                                status = "!"
                                print(f"\n{status} Message {messages_received}: No announcements")
                        else:
                            print(f"\n✗ Message {messages_received}: Invalid format")
                            
                    except asyncio.TimeoutError:
                        print(f"\n! Timeout waiting for message {i+1}")
                        break
                    except json.JSONDecodeError:
                        print(f"\n✗ Message {messages_received}: Invalid JSON")
                    except Exception as e:
                        print(f"\n✗ Error processing message {messages_received}: {str(e)}")
                
            except Exception as e:
                print(f"\n✗ Error receiving messages: {str(e)}")
            
            # Calculate test results
            duration = (datetime.now() - start_time).total_seconds()
            test_passed = messages_received >= 15 and valid_messages >= 10
            
            # Print Results
            print_header("Test Results")
            if test_passed:
                print("✓ Test PASSED")
            else:
                print("✗ Test FAILED")
                
            print(f"\nStatistics:")
            print(f"  Duration: {duration:.1f} seconds")
            print(f"  Messages Received: {messages_received}/20")
            print(f"  Valid Messages: {valid_messages}/{messages_received}")
            print(f"  Messages/Second: {messages_received/duration:.1f}")
            
    except websockets.exceptions.WebSocketException as e:
        print("\n✗ WebSocket Error:")
        print(f"  {str(e)}")
    except Exception as e:
        print("\n✗ Unexpected Error:")
        print(f"  {str(e)}")
        import traceback
        traceback.print_exc()
    
    return test_passed

if __name__ == "__main__":
    asyncio.run(test_websocket())

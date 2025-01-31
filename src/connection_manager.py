"""Manage WebSocket connections to RIPE RIS."""
import asyncio
import websockets
import json
import logging
from typing import Dict, Set, Optional, Callable, Any
from websockets.exceptions import WebSocketException, ConnectionClosed

class ConnectionManager:
    def __init__(self, message_callback: Callable[[Dict[str, Any]], None]):
        self.websocket = None
        self.message_callback = message_callback
        self.running = True
        self._listen_task = None
        self._event_loop = None
        self.RIPE_RIS_URL = 'wss://ris-live.ripe.net/v1/ws/'
        
    async def connect(self) -> bool:
        """Connect to RIPE RIS WebSocket."""
        try:
            self.websocket = await websockets.connect(self.RIPE_RIS_URL)
            logging.info("Connected to RIPE RIS WebSocket")
            return True
        except Exception as e:
            logging.error(f"Failed to connect to RIPE RIS: {e}")
            return False
            
    async def subscribe(self, collector=None) -> bool:
        """Subscribe to BGP updates."""
        if not self.websocket:
            return False
            
        try:
            subscription = {
                "type": "ris_subscribe",
                "data": {
                    "type": "UPDATE"  # Subscribe to all update messages
                }
            }
            
            # Add collector if specified
            if collector:
                subscription["data"]["host"] = collector
            
            await self.websocket.send(json.dumps(subscription))
            logging.info(f" Subscribed to BGP updates{' for ' + collector if collector else ''}")
            return True
            
        except Exception as e:
            logging.error(f" Failed to subscribe{' to ' + collector if collector else ''}: {e}")
            return False
            
    async def listen(self):
        """Listen for incoming messages."""
        self.running = True
        
        while self.running:
            try:
                # Check if websocket is closed or None
                if not self.websocket:
                    logging.info("WebSocket connection closed, stopping listen loop")
                    break
                
                # Receive message with timeout
                try:
                    message = await asyncio.wait_for(self.websocket.recv(), timeout=1.0)
                    if message:
                        # Debug log raw message
                        logging.debug(f"Raw message received: {message}")
                        
                        # Parse message once here
                        try:
                            data = json.loads(message)
                            logging.debug(f"Parsed message structure:\n{json.dumps(data, indent=2)}")
                            if data.get("type") == "ris_message":
                                if self.message_callback:
                                    try:
                                        if asyncio.iscoroutinefunction(self.message_callback):
                                            await self.message_callback(data)
                                        else:
                                            self.message_callback(data)
                                    except Exception as e:
                                        logging.error(f"Error in message callback: {e}", exc_info=True)
                            elif data.get("type") == "ris_error":
                                logging.error(f"Received error: {data}")
                        except json.JSONDecodeError as e:
                            logging.error(f"Failed to parse message: {e}")
                            logging.debug(f"Raw message: {message}")
                except asyncio.TimeoutError:
                    # Timeout is normal, just continue
                    continue
                except Exception as e:
                    if not self.running:
                        # If we're stopping, this is expected
                        break
                    logging.error(f"Error in listen loop: {e}")
                    if "ConnectionClosed" in str(e):
                        break
                    
            except Exception as e:
                if not self.running:
                    # If we're stopping, this is expected
                    break
                logging.error(f"Error in listen loop: {e}")
                # Break on connection errors
                if "ConnectionClosed" in str(e) or isinstance(e, AttributeError):
                    break
                # For other errors, wait a bit before retrying
                await asyncio.sleep(1)
        
        # Ensure we close the connection when the listen loop ends
        if self.websocket:
            await self.close()
        
        self.running = False
        logging.info("Listen loop stopped")

    async def close(self):
        """Close the WebSocket connection asynchronously."""
        if self.websocket:
            try:
                # Get all tasks in the current loop
                loop = asyncio.get_running_loop()
                tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task()]
                
                # Cancel all other tasks (including keepalive)
                for task in tasks:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                
                # Now close the websocket
                await self.websocket.close()
                self.websocket = None
                logging.info("✓ WebSocket connection closed")
            except Exception as e:
                logging.error(f"Error during WebSocket close: {e}")
                self.websocket = None

    def stop(self):
        """Stop the WebSocket connection."""
        self.running = False
        
        # Cancel listen task if running
        if self._listen_task and not self._listen_task.done():
            self._listen_task.cancel()
        
        # Close WebSocket connection
        if self.websocket:
            try:
                # Try to get the current event loop
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    # If no loop exists, create a new one
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                # Create a future for the close operation
                close_future = asyncio.run_coroutine_threadsafe(
                    self.close(),
                    loop
                )
                
                # Wait for the close operation to complete with timeout
                try:
                    close_future.result(timeout=5.0)
                except Exception as e:
                    logging.error(f"Error waiting for WebSocket close: {e}")
                    # Force close the websocket
                    self.websocket = None
                    
            except Exception as e:
                logging.error(f"✗ Error closing WebSocket: {e}")
                # Force close the websocket if async close fails
                self.websocket = None

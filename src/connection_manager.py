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
        
    async def connect(self) -> bool:
        """Connect to RIPE RIS WebSocket service."""
        try:
            self.websocket = await websockets.connect('wss://ris-live.ripe.net/v1/ws/')
            logging.info("Connected to RIPE RIS WebSocket")
            return True
        except Exception as e:
            logging.error(f"Failed to connect to RIPE RIS: {e}")
            return False
            
    async def subscribe(self, collector: str) -> bool:
        """Subscribe to a specific collector."""
        if not self.websocket:
            return False
            
        try:
            subscription = {
                "type": "ris_subscribe",
                "data": {
                    "host": collector,
                    "type": "UPDATE",
                    "require": "announcements",
                    "socketOptions": {
                        "acknowledge": True
                    }
                }
            }
            
            await self.websocket.send(json.dumps(subscription))
            response = await self.websocket.recv()
            response_data = json.loads(response)
            
            if response_data.get("type") == "ris_error":
                logging.error(f"Subscription error for {collector}: {response_data}")
                return False
                
            logging.info(f"Subscribed to collector: {collector}")
            return True
            
        except Exception as e:
            logging.error(f"Error subscribing to {collector}: {e}")
            return False
            
    async def listen(self):
        """Listen for messages from WebSocket."""
        if not self.websocket:
            return
            
        self._event_loop = asyncio.get_event_loop()
        self._listen_task = asyncio.create_task(self._listen_loop())
        try:
            await self._listen_task
        except asyncio.CancelledError:
            logging.info("Listen task cancelled")
        except Exception as e:
            logging.error(f"Listen task error: {e}")
        finally:
            if self.websocket:
                await self.websocket.close()
                self.websocket = None
            
    async def _listen_loop(self):
        """Internal loop for listening to messages."""
        try:
            while self.running and self.websocket:
                try:
                    message = await self.websocket.recv()
                    if message:
                        # Parse message once here
                        try:
                            data = json.loads(message)
                            if data.get("type") == "ris_message":
                                if self.message_callback:
                                    await self.message_callback(data)
                            elif data.get("type") == "ris_error":
                                logging.error(f"Received error: {data}")
                        except json.JSONDecodeError:
                            logging.error("Invalid message format received")
                        except Exception as e:
                            logging.error(f"Error processing message: {str(e)}")
                except websockets.exceptions.ConnectionClosed:
                    logging.info("WebSocket connection closed")
                    break
                except Exception as e:
                    logging.error(f"Error receiving message: {str(e)}")
                    break
        finally:
            self.running = False
            if self.websocket:
                await self.websocket.close()
                self.websocket = None
            
    def stop(self):
        """Stop the connection manager."""
        self.running = False
        if self._listen_task and not self._listen_task.done():
            self._listen_task.cancel()
        if self._event_loop and self.websocket:
            self._event_loop.create_task(self.websocket.close())

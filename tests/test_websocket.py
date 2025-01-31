import asyncio
import websockets
import json

async def test_websocket():
    uri = "wss://ris-live.ripe.net/v1/ws/"
    
    async with websockets.connect(uri, ssl=True) as websocket:
        print("Connected to RIPE RIS WebSocket")
        
        # Subscribe to BGP updates
        subscription = {
            "type": "ris_subscribe",
            "data": {
                "type": "UPDATE",
                "require": "announcements"
            }
        }
        
        await websocket.send(json.dumps(subscription))
        print("Subscription sent, waiting for messages...")
        
        # Wait for 3 messages
        for _ in range(3):
            message = await websocket.recv()
            print(f"\nReceived message: {message}")

if __name__ == "__main__":
    asyncio.run(test_websocket())

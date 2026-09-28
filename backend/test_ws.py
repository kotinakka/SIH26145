import asyncio
import json
import websockets


async def main():
    uri = "ws://127.0.0.1:8000/ws/alerts"
    async with websockets.connect(uri) as ws:
        await ws.send(json.dumps({
            "pcap_file": "../data/port_scan.pcap",
            "speed_factor": 50
        }))

        while True:
            message = await ws.recv()
            event = json.loads(message)
            print(event)
            if event.get("type") == "summary":
                break


asyncio.run(main())
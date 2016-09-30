#!/usr/bin/env python
import asyncio
import websockets
import json


async def hello(websocket, path):
    while True:
        data = await websocket.recv()
        print("< {}".format(json.dumps(data)))


def main():
    start_server = websockets.serve(hello, 'localhost', 5678)

    print("Web server running on 5678")
    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()


if __name__  == '__main__':
    main()

"""Insight module for real time analytics.

"""
import asyncio
import threading
from uuid import uuid4
import logging
import json

import websockets


LOG = logging.getLogger(__name__)


def register_session(session):
    LOG.debug("Starting up insight message sender thread.")
    send_thread = MessageSender()
    send_thread.start()
    session.register('before-parameter-build', send_thread.on_parameter_build)


class InsightEventHandler(object):
    def __init__(self, queue, loop):
        self.queue = queue
        self.loop = loop

    def on_parameter_build(self, model, context, **kwargs):
        service_name = model.service_model.service_name
        operation_name = model.name
        context['request_id'] = str(uuid4())
        # TODO: I need to plumb these into botocore, I don't think I can
        # get this on before-parameter-build.
        retry_count = 0
        retry_delay = 0
        message = self._request_send_message(
            service_name, operation_name, context['request_id'],
            retry_count, retry_delay)
        LOG.debug("Queueing message from bcore event handler for insight.")
        self.loop.call_soon_threadsafe(self.queue.put_nowait, message)

    def _request_send_message(self, service_name, operation_name, request_id,
                              retry_count, retry_delay):
        return json.dumps({
            'type': 'RequestSent',
            'service': service_name,
            'operation': operation_name,
            'sdk': 'python',
            'id': request_id,
            'retryCount': retry_count,
            'retryDelay': retry_delay,
        })


class MessageSender(threading.Thread):
    def __init__(self):
        self.queue = None
        self.loop = None
        threading.Thread.__init__(self)
        self.daemon = True
        self.event_handler = None

    def on_parameter_build(self, **kwargs):
        self.event_handler.on_parameter_build(**kwargs)

    def run(self):
        self.loop = asyncio.new_event_loop()
        self.queue = asyncio.Queue(loop=self.loop)
        self.event_handler = InsightEventHandler(queue=self.queue,
                                                 loop=self.loop)
        self.loop.run_until_complete(self._handler())

    async def _handler(self):
        async with websockets.connect('ws://localhost:5678/publish',
                                      loop=self.loop) as websocket:
            while True:
                try:
                    message = await self.queue.get()
                except Exception as e:
                    print("Received exception: %s" % e)
                LOG.debug("MessageSender thread successfully awaited "
                          "message: %s", message)
                await websocket.send(message)
                LOG.debug("MessageSender thread successfully send message to "
                          "socket channel.")

"""Insight module for real time analytics.

NOTE: This is a one off customization not meant for general purpose
usage.  If you want to try this:

    * You must use python3.7
    * Be sure to install the setup.py, this customization has additional
    dependencies.

"""
import time
import asyncio
import threading
from uuid import uuid4
import logging
import json
import socket
import os

import websockets
import uvloop


LOG = logging.getLogger(__name__)

CLIENT_NAME = 'python-sdk-client'
INSIGHT_SERVER_DEFAULT = os.environ.get('INSIGHT_SERVER')


def register_session(session, client_name=CLIENT_NAME,
                     insight_server=INSIGHT_SERVER_DEFAULT):
    LOG.debug("Starting up insight message sender thread.")
    send_thread = MessageSender(client_name, insight_server)
    send_thread.start()
    session.register('before-parameter-build', send_thread.on_parameter_build)
    session.register('request-created', send_thread.on_request_created)
    session.register('response-received', send_thread.on_response_received)
    session.register('after-call', send_thread.on_api_call_finished)
    session.register('after-call-error', send_thread.on_api_call_finished)
    return send_thread


class InsightEventHandler(object):
    def __init__(self, queue, loop, client_name=CLIENT_NAME,
                 localname=socket.gethostname()):
        self.queue = queue
        self.loop = loop
        self.client_name = client_name
        self.localname = localname
        self._last_response_received_message = None

    def on_api_call_finished(self, context, **kwargs):
        request_attempts = context['request_attempts']
        # NOTE: For now, this optimization is disabled.  I think
        # post-processing is much easier if you can just look for
        # APICallFinished events.  If this ends up being too slow,
        # uncomment out the if statement.  Original comment:
        #
        # This is hooked up to after-call and after-call-error.
        # We try this as an optimization.  If there were multiple
        # API call attempts, then we'll emit a new message with some
        # aggregate stats.  However, if there was only one API call attempt
        # then there's nothing to aggregate and we can omit sending this
        # message, because it's going to have no new information.
        # if request_attempts == 1:
        #     return
        context['request_api_call_duration'] = (
            time.time() - context['request_api_call_start']
        )
        if 'exception' in kwargs:
            status = 'failure'
        elif 'parsed' in kwargs:
            error_code = kwargs['parsed'].get('Error', {}).get('Code')
            if error_code is not None:
                status = 'failure'
            else:
                status = 'success'
        else:
            status = 'success'
        client_name = context.get('client_name', self.client_name)
        message = self._request_api_call_finished_message(
            context['service_name'], context['operation_name'],
            context['request_id'], request_attempts - 1,
            client_name, context['request_api_call_duration'],
            status,
        )
        self.loop.call_soon_threadsafe(self.queue.put_nowait, message)

    def on_request_created(self, request, operation_name, **kwargs):
        context = request.context
        request.headers['X-Amz-Insight-Id'] = context['request_id']
        service_name = context['service_name']
        operation_name = context['operation_name']
        context['request_created'] = time.time()
        context['request_attempts'] += 1
        client_name = context.get('client_name', self.client_name)
        # If this is the first time sending the request (attempt #1), then
        # we've retried 0 times so we need the ``- 1``.
        retry_count = context['request_attempts'] - 1
        # Is retry_delay worth plumbing into botocore?  Not currently exposed.
        retry_delay = 0
        message = self._request_send_message(
            service_name, operation_name, context['request_id'],
            retry_count, retry_delay, client_name)
        LOG.debug("Queueing message from bcore event handler for insight.")
        self.loop.call_soon_threadsafe(self.queue.put_nowait, message)

    def on_parameter_build(self, context, model, **kwargs):
        # before-parameter-build happens once per client method call.
        # Keep in mind one client method call, e.g. s3.list_objects()
        # can result in multiple HTTP requests.  However, all of those
        # HTTP requests should be tracked under a single request_id.
        # This request_id creation is hooked up to before-parameter-build
        # because that maps to a client method call (vs. HTTP requests).
        # We're also setting up some initial state and context that we
        # won't have latter on in the request lifecycle.
        context['request_id'] = str(uuid4())
        context['operation_name'] = model.name
        context['service_name'] = model.service_model.service_name
        # The number of times we attempt to send a request.  Every time
        # in request_created we increment this number.  Retry attempts
        # will always create a new request object.
        context['request_attempts'] = 0
        context['request_api_call_start'] = time.time()

    def on_response_received(self, response_dict, parsed_response,
                             context, exception, **kwargs):
        # This is hooked up to response-received,
        # which is emitted from the client,
        # this gives us a final yes/no success case.
        service_name = context['service_name']
        operation_name = context['operation_name']
        request_id = context['request_id']
        request_duration = time.time() - context['request_created']
        client_name = context.get('client_name', self.client_name)
        if exception is None:
            # We got a response of some type from the service, but
            # we still have to check if it's an error or success.
            status_code = response_dict['status_code']
            status = 'success'
            error_code = parsed_response.get('Error', {}).get('Code')
            max_retries_reached = parsed_response['ResponseMetadata'].get(
                'MaxAttemptsReached', False
            )
            if error_code is not None:
                # We received a response from a server, but it was an
                # error of some type.
                status = 'failure'
            message = self._response_received_message(
                service_name, operation_name, request_id, status,
                error_code, status_code, max_retries_reached,
                request_duration, client_name
            )
        else:
            # If we received an exception (such as a ConnectionError)
            # we don't have as much information available to us.
            # We don't have a status code we can report, and we don't
            # know if we've reached max attempts because we inject that
            # information in the ResponseMetadata, which requires
            # a parsed response.
            message = self._response_received_message(
                service_name, operation_name, request_id, 'failure',
                exception.__class__.__name__, -1, False,
                request_duration, client_name,
            )
        self._last_response_received_message = message
        self.loop.call_soon_threadsafe(self.queue.put_nowait, message)

    def _response_received_message(self, service_name, operation_name,
                                   request_id, status, error_code, status_code,
                                   max_retries, total_seconds, client_name):
        return json.dumps({
            'type': 'ResponseReceived',
            'service': service_name,
            'operation': operation_name,
            'clientName': client_name,
            'id': request_id,
            'status': status,
            'errorCode': error_code,
            'statusCode': status_code,
            'maxRetries': max_retries,
            'totalSeconds': total_seconds,
            'timestamp': time.time(),
            'localHostname': self.localname,
        })

    def _request_send_message(self, service_name, operation_name, request_id,
                              retry_count, retry_delay, client_name):
        return json.dumps({
            'type': 'RequestSent',
            'service': service_name,
            'operation': operation_name,
            'clientName': client_name,
            'id': request_id,
            'retryCount': retry_count,
            'retryDelay': retry_delay,
            'timestamp': time.time(),
            'localHostname': self.localname,
        })

    def _request_api_call_finished_message(self, service_name, operation_name,
                                           request_id, retry_count,
                                           client_name, total_duration,
                                           status):
        return json.dumps({
            'type': 'APICallFinished',
            'service': service_name,
            'operation': operation_name,
            'clientName': client_name,
            'id': request_id,
            'status': status,
            'retryCount': retry_count,
            'apiCallDuration': total_duration,
            'timestamp': time.time(),
            'localHostname': self.localname,
        })


class MessageSender(threading.Thread):

    _SHUTDOWN = object()

    def __init__(self, client_name, server_address):
        self.queue = None
        self.loop = None
        threading.Thread.__init__(self)
        self.daemon = True
        self.event_handler = None
        self.client_name = client_name
        if server_address is None:
            server_address = 'ws://localhost:5678/publish'
        self.server_address = server_address

    def on_parameter_build(self, **kwargs):
        self.event_handler.on_parameter_build(**kwargs)

    def on_response_received(self, **kwargs):
        self.event_handler.on_response_received(**kwargs)

    def on_request_created(self, **kwargs):
        self.event_handler.on_request_created(**kwargs)

    def on_api_call_finished(self, **kwargs):
        self.event_handler.on_api_call_finished(**kwargs)

    def run(self):
        self.loop = uvloop.new_event_loop()
        self.queue = asyncio.Queue(loop=self.loop)
        self.event_handler = InsightEventHandler(
            queue=self.queue, loop=self.loop, client_name=self.client_name)
        self.loop.run_until_complete(self._handler())

    def request_stop(self):
        if self.loop is not None:
            self.loop.call_soon_threadsafe(self.queue.put_nowait,
                                           self._SHUTDOWN)

    async def _handler(self):
        count = 0
        async with websockets.connect(self.server_address,
                                      loop=self.loop) as websocket:
            while True:
                try:
                    message = await self.queue.get()
                    if message is self._SHUTDOWN:
                        LOG.debug("Shutting down as requested.")
                        return
                except Exception as e:
                    LOG.error("Received exception waiting on queue",
                              exc_info=True)
                    continue
                LOG.debug("MessageSender thread successfully awaited "
                          "message: %s", message)
                try:
                    await websocket.send(message)
                    count += 1
                except Exception:
                    LOG.error("Received exception trying to send message: %s",
                              message, exc_info=True)
                    continue
                LOG.debug("MessageSender thread successfully send message to "
                          "socket channel.")
                if count % 100 == 0:
                    LOG.info("Total messages sent to insight: %s", count)

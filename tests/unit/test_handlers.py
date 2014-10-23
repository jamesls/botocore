# Copyright 2012-2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
from tests import BaseSessionTest

import base64
import mock

from botocore.compat import quote
from botocore import handlers
from botocore.endpoint import Endpoint
from botocore import auth


class TestHandlers(BaseSessionTest):

    def test_get_console_output(self):
        parsed = {'Output': base64.b64encode(b'foobar').decode('utf-8')}
        handlers.decode_console_output(parsed)
        self.assertEqual(parsed['Output'], 'foobar')

    def test_get_console_output_cant_be_decoded(self):
        parsed = {'Output': 1}
        handlers.decode_console_output(parsed)
        self.assertEqual(parsed['Output'], 1)

    def test_decode_quoted_jsondoc(self):
        value = quote('{"foo":"bar"}')
        converted_value = handlers.decode_quoted_jsondoc(value)
        self.assertEqual(converted_value, {'foo': 'bar'})

    def test_cant_decode_quoted_jsondoc(self):
        value = quote('{"foo": "missing end quote}')
        converted_value = handlers.decode_quoted_jsondoc(value)
        self.assertEqual(converted_value, value)

    def test_switch_to_sigv4(self):
        event = self.session.create_event('service-data-loaded', 's3')
        mock_session = mock.Mock()
        mock_session.get_scoped_config.return_value = {
            's3': {'signature_version': 's3v4'}
        }
        kwargs = {'service_data': {'signature_version': 's3'},
                  'service_name': 's3', 'session': mock_session}
        self.session.emit(event, **kwargs)
        self.assertEqual(kwargs['service_data']['signature_version'], 's3v4')

    def test_noswitch_to_sigv4(self):
        event = self.session.create_event('service-data-loaded', 's3')
        mock_session = mock.Mock()
        mock_session.get_scoped_config.return_value = {}
        kwargs = {'service_data': {'signature_version': 's3'},
                  'service_name': 's3', 'session': mock_session}
        self.session.emit(event, **kwargs)
        self.assertEqual(kwargs['service_data']['signature_version'], 's3')

    def test_quote_source_header(self):
        for op in ('UploadPartCopy', 'CopyObject'):
            event = self.session.create_event(
                'before-call', 's3', op)
            params = {'headers': {'x-amz-copy-source': 'foo++bar.txt'}}
            m = mock.Mock()
            self.session.emit(event, params=params, model=m)
            self.assertEqual(
                params['headers']['x-amz-copy-source'], 'foo%2B%2Bbar.txt')

    def test_copy_snapshot_encrypted(self):
        operation = mock.Mock()
        source_endpoint = mock.Mock()
        signed_request = mock.Mock()
        signed_request.url = 'SIGNED_REQUEST'
        source_endpoint.auth.credentials = mock.sentinel.credentials
        source_endpoint.create_request.return_value = signed_request
        operation.service.get_endpoint.return_value = source_endpoint
        endpoint = mock.Mock()
        endpoint.region_name = 'us-east-1'

        params = {'SourceRegion': 'us-west-2'}
        handlers.copy_snapshot_encrypted(operation, {'body': params}, endpoint)
        self.assertEqual(params['PresignedUrl'], 'SIGNED_REQUEST')
        # We created an endpoint in the source region.
        operation.service.get_endpoint.assert_called_with('us-west-2')
        # We should also populate the DestinationRegion with the
        # region_name of the endpoint object.
        self.assertEqual(params['DestinationRegion'], 'us-east-1')

    def test_destination_region_left_untouched(self):
        # If the user provides a destination region, we will still
        # override the DesinationRegion with the region_name from
        # the endpoint object.
        operation = mock.Mock()
        source_endpoint = mock.Mock()
        signed_request = mock.Mock()
        signed_request.url = 'SIGNED_REQUEST'
        source_endpoint.auth.credentials = mock.sentinel.credentials
        source_endpoint.create_request.return_value = signed_request
        operation.service.get_endpoint.return_value = source_endpoint
        endpoint = mock.Mock()
        endpoint.region_name = 'us-west-1'

        # The user provides us-east-1, but we will override this to
        # endpoint.region_name, of 'us-west-1' in this case.
        params = {'SourceRegion': 'us-west-2', 'DestinationRegion': 'us-east-1'}
        handlers.copy_snapshot_encrypted(operation, {'body': params}, endpoint)
        # Always use the DestinationRegion from the endpoint, regardless of
        # whatever value the user provides.
        self.assertEqual(params['DestinationRegion'], 'us-west-1')

    def test_500_status_code_set_for_200_response(self):
        http_response = mock.Mock()
        http_response.status_code = 200
        http_response.content = """
            <Error>
              <Code>AccessDenied</Code>
              <Message>Access Denied</Message>
              <RequestId>id</RequestId>
              <HostId>hostid</HostId>
            </Error>
        """
        handlers.check_for_200_error((http_response, {}))
        self.assertEqual(http_response.status_code, 500)

    def test_200_response_with_no_error_left_untouched(self):
        http_response = mock.Mock()
        http_response.status_code = 200
        http_response.content = "<NotAnError></NotAnError>"
        handlers.check_for_200_error((http_response, {}))
        # We don't touch the status code since there are no errors present.
        self.assertEqual(http_response.status_code, 200)

    def test_500_response_can_be_none(self):
        # A 500 response can raise an exception, which means the response
        # object is None.  We need to handle this case.
        handlers.check_for_200_error(None)

    def test_sse_headers(self):
        prefix = 'x-amz-server-side-encryption-customer-'
        for op in ('HeadObject', 'GetObject', 'PutObject', 'CopyObject',
                   'CreateMultipartUpload', 'UploadPart', 'UploadPartCopy'):
            event = self.session.create_event(
                'before-call', 's3', op)
            params = {'headers': {
                prefix + 'algorithm': 'foo',
                prefix + 'key': 'bar'
                }}
            self.session.emit(event, params=params, model=mock.Mock())
            self.assertEqual(
                params['headers'][prefix + 'key'], 'YmFy')
            self.assertEqual(
                params['headers'][prefix + 'key-MD5'],
                'N7UdGUp1E+RbVvZSTy1R8g==')


class TestRetryHandlerOrder(BaseSessionTest):
    def get_handler_names(self, responses):
        names = []
        for response in responses:
            handler = response[0]
            if hasattr(handler, '__name__'):
                names.append(handler.__name__)
            elif hasattr(handler, '__class__'):
                names.append(handler.__class__.__name__)
            else:
                names.append(str(handler))
        return names

    def test_s3_special_case_is_before_other_retry(self):
        service = self.session.get_service('s3')
        operation = service.get_operation('CopyObject')
        responses = self.session.emit(
            'needs-retry.s3.CopyObject',
            response=(mock.Mock(), {}), endpoint=mock.Mock(), operation=operation,
            request=mock.Mock(), attempts=1, caught_exception=None)
        # This is implementation specific, but we're trying to verify that
        # the check_for_200_error is before any of the retry logic in
        # botocore.retryhandlers.
        # Technically, as long as the relative order is preserved, we don't
        # care about the absolute order.
        names = self.get_handler_names(responses)
        self.assertIn('check_for_200_error', names)
        self.assertIn('RetryHandler', names)
        s3_200_handler = names.index('check_for_200_error')
        general_retry_handler = names.index('RetryHandler')
        self.assertTrue(s3_200_handler < general_retry_handler,
                        "S3 200 error handler was supposed to be before "
                        "the general retry handler, but it was not.")

    def test_do_not_auto_switch_to_sigv4(self):
        endpoint = mock.Mock(spec=Endpoint)
        endpoint.auth = mock.sentinel.ORIGINAL_AUTH
        # If we don't have an error message telling us to switch to sigv4
        # we don't switch out the auth.
        response = (None, {})
        request = mock.Mock()
        handlers.auto_switch_sigv4(endpoint, response, request)
        self.assertEqual(endpoint.auth, mock.sentinel.ORIGINAL_AUTH)

    def test_do_not_switch_if_response_is_none(self):
        endpoint = mock.Mock(spec=Endpoint)
        endpoint.auth = mock.sentinel.ORIGINAL_AUTH
        request = mock.Mock()
        handlers.auto_switch_sigv4(endpoint=endpoint, response=None,
                                   request=request)
        self.assertEqual(endpoint.auth, mock.sentinel.ORIGINAL_AUTH)

    @mock.patch('botocore.handlers.find_region_via_dns')
    def test_switch_to_sigv4_on_specific_error(self, find_region_via_dns):
        find_region_via_dns.return_value = 'eu-central-1'
        endpoint = mock.Mock(spec=Endpoint)
        original_auth = mock.Mock()
        endpoint.auth = original_auth
        request = mock.Mock()
        http_response = mock.Mock()
        http_response.request.url = 'http://bucket.s3.amazonaws.com'
        response = (http_response, {
            'Error': {'Message': 'Please use AWS4-HMAC-SHA256'}})
        handlers.auto_switch_sigv4(endpoint, response, request)
        self.assertIsInstance(endpoint.auth, auth.S3SigV4Auth)

    @mock.patch('botocore.handlers.find_region_via_dns')
    def test_switch_to_siv4_for_307_redirect(self, find_region_via_dns):
        find_region_via_dns.return_value = 'eu-central-1'
        endpoint = mock.Mock(spec=Endpoint)
        original_auth = mock.Mock()
        endpoint.auth = original_auth
        request = mock.Mock()
        request.original.headers = {}
        http_response = mock.Mock()
        http_response.request.url = (
            'https://bucket.s3.eu-central-1.amazonaws.com')
        response = (http_response, {
            'Error': {'Message': 'Please use AWS4-HMAC-SHA256'}})
        handlers.auto_switch_sigv4(endpoint, response, request)
        self.assertIsInstance(endpoint.auth, auth.S3SigV4Auth)
        self.assertEqual(request.original.headers['Host'],
                         'bucket.s3.eu-central-1.amazonaws.com')

    def test_cname_to_region_with_region_dots(self):
        self.assertEqual(
            handlers.cname_to_region('s3-w.eu-central-1.amazonaws.com'),
            'eu-central-1'
        )

    def test_cname_with_region_within_subdomain(self):
        self.assertEqual(
            handlers.cname_to_region('s3-us-west-2-w.amazonaws.com'),
            'us-west-2'
        )

    def test_cname_for_us_east_1(self):
        self.assertEqual(
            handlers.cname_to_region('s3-1-w.amazonaws.com'),
            'us-east-1'
        )
        self.assertEqual(
            handlers.cname_to_region('s3-2-w.amazonaws.com'),
            'us-east-1'
        )

    def test_cname_for_eu_west_1(self):
        self.assertEqual(
            handlers.cname_to_region('s3-3-w.amazonaws.com'),
            'eu-west-1'
        )

    @mock.patch('socket.getaddrinfo')
    def test_find_region_via_dns(self, getaddrinfo):
        # This test is highly specific to the getaddrinfo socket
        # call, so we're mostly just we handle the expected output properly.
        getaddrinfo.return_value = [
            [None, None, None, 's3-w.eu-central-1.amazonaws.com']]
        self.assertEqual(
            handlers.find_region_via_dns('mybucket'),
            'eu-central-1')


if __name__ == '__main__':
    unittest.main()

# Copyright (c) 2013 Amazon.com, Inc. or its affiliates.  All Rights Reserved
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, dis-
# tribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the fol-
# lowing conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABIL-
# ITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#

from botocore.compat import unittest
from botocore.paginate import Paginator
from botocore.operation import Operation

import mock


class TestPagination(unittest.TestCase):
    def setUp(self):
        self.operation = mock.Mock()
        self.paginate_config = {
            'output_token': 'NextToken',
            'input_token': 'NextToken',
        }
        self.operation.pagination = self.paginate_config
        self.paginator = Paginator(self.operation)

    def test_no_next_token(self):
        response = {'not_the_next_token': 'foobar'}
        self.operation.call.return_value = None, response
        actual = list(self.paginator.paginate(None))
        self.assertEqual(actual, [(None, {'not_the_next_token': 'foobar'})])

    def test_next_token_in_response(self):
        responses = [(None, {'NextToken': 'token1'}),
                     (None, {'NextToken': 'token2'}),
                     (None, {'not_next_token': 'foo'})]
        self.operation.call.side_effect = responses
        actual = list(self.paginator.paginate(None))
        self.assertEqual(actual, responses)
        # The first call has no next token, the second and third call should
        # have 'token1' and 'token2' respectively.
        self.assertEqual(self.operation.call.call_args_list,
                         [mock.call(None), mock.call(None, NextToken='token1'),
                          mock.call(None, NextToken='token2')])

    def test_any_passed_in_args_are_unmodified(self):
        responses = [(None, {'NextToken': 'token1'}),
                     (None, {'NextToken': 'token2'}),
                     (None, {'not_next_token': 'foo'})]
        self.operation.call.side_effect = responses
        actual = list(self.paginator.paginate(None, Foo='foo', Bar='bar'))
        self.assertEqual(actual, responses)
        self.assertEqual(
            self.operation.call.call_args_list,
            [mock.call(None, Foo='foo', Bar='bar'),
             mock.call(None, Foo='foo', Bar='bar', NextToken='token1'),
             mock.call(None, Foo='foo', Bar='bar', NextToken='token2')])


class TestPaginatorObjectConstruction(unittest.TestCase):
    def test_default_paginator_is_created(self):
        op = Operation(None, {})
        # Technically an implementation detail, but still
        # useful to check.
        self.assertIsInstance(op._paginator, Paginator)

    def test_pagination_delegates_to_paginator(self):
        paginator_cls = mock.Mock()
        service = mock.Mock()
        service.type = 'json'
        endpoint = mock.Mock()
        op = Operation(service, {}, paginator_cls)
        op.paginate(endpoint, foo='bar')

        paginator_cls.return_value.paginate.assert_called_with(
            endpoint, foo='bar')

    def test_can_paginate(self):
        op_data = {'pagination': {'foo': 'bar'}}
        op = Operation(None, op_data)
        self.assertTrue(op.can_paginate)


if __name__ == '__main__':
    unittest.main()

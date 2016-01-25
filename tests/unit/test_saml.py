# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
from botocore import credentials
import mock
import base64
from datetime import datetime, timedelta
from dateutil.tz import tzlocal, tzutc
from botocore.credentials import EnvProvider, create_assume_role_refresher
from botocore import saml
from botocore.vendored import requests
import botocore.exceptions
import botocore.session
from tests import unittest, BaseEnvVar, IntegerRefresher


class TestFormParser(unittest.TestCase):
    def test_form2str(self):
        html_input = """
            <input type="button" value="nameless button at outside of form"/>
            <form action="/path/login/?foo=foo&amp;bar=bar">
            <div>The &nbsp; in the form will not confuse our parser.</div>
            <input name="foo" value="bar&amp;baz"/>
            <input name="username"/><input name="password"/>
            </form>
            <input type="button" value="nameless button at outside of form"/>
            </html>
        """
        html_output = (
            '<form action="/path/login/?foo=foo&amp;bar=bar">'
            '<input name="foo" value="bar&amp;baz"/>'
            '<input name="username"/><input name="password"/>'
            '</form>'
        )
        p = saml.FormParser()
        p.feed(html_input)
        self.assertEqual(p.extract_form(0), html_output)


class TestSAMLGenericFormsBasedAuthenticator(unittest.TestCase):
    LOGIN_FORM = """<html><form action="login">
        <div>The &nbsp; in the form will not confuse our parser.</div>
        <input name="foo" value="bar"/>
        <input name="username"/><input name="password"/>
        </form></html>
    """

    def setUp(self):
        self.requests_session = mock.Mock(spec=requests.Session)
        self.password_prompter = lambda text: "mypassword"
        self.authenticator = saml.GenericFormsBasedAuthenticator(
            self.password_prompter,
            self.requests_session,
        )
        self.config = {
            'saml_endpoint': 'https://notexist.com',
            'saml_authentication_type': 'form',
            'saml_username': 'joe',
        }

    def test_missing_required_config_raises_exception(self):
        # Remove a required config param
        del self.config['saml_username']
        with self.assertRaisesRegexp(botocore.exceptions.SAMLError,
                                     '[Mm]issing required'):
            self.authenticator.retrieve_saml_assertion(self.config)

    def test_login_form_not_exist(self):
        self.requests_session.get.return_value = mock.Mock(
            text='<html>wrong</html>', status_code=200)
        self.assertTrue(self.authenticator.is_suitable(self.config))
        with self.assertRaisesRegexp(botocore.exceptions.SAMLError, 'form'):
            self.authenticator.retrieve_saml_assertion(self.config)

    def test_can_extract_saml_assertion(self):
        self.requests_session.post.return_value = mock.Mock(
            text='<form><input name="SAMLResponse" value="fakeassertion"/></form>',
            status_code=200
        )
        self.requests_session.get.return_value = mock.Mock(
            text=self.LOGIN_FORM, status_code=200)

        assertion = self.authenticator.retrieve_saml_assertion(self.config)
        self.assertEqual(assertion, 'fakeassertion')

        self.requests_session.post.assert_called_with(
            "https://notexist.com/login", verify=True,
            data={'foo': 'bar', 'username': 'joe', 'password': 'mypassword'})

    def test_non_200_response_on_form_retrieval(self):
        self.requests_session.get.return_value = mock.Mock(
            text='<html>Not Found</html>',
            status_code=404,
            url='https://foo')
        with self.assertRaisesRegexp(botocore.exceptions.SAMLError, 'non-200'):
            self.authenticator.retrieve_saml_assertion(self.config)

    def test_expected_form_fields_not_found_raises_error(self):
        missing_form_fields = (
            'html><form action="login">'
            '<div>The &nbsp; in the form will not confuse our parser.</div>'
            '<input name="foo" value="bar"/>'
            # Here instead of 'username' and 'password',
            # we have input fields that aren't named what we expect.
            '<input name="NOT-USERNAME"/><input name="NOT-PASSWORD"/>'
            '</form></html>'
        )
        self.requests_session.get.return_value = mock.Mock(
            text=missing_form_fields, status_code=200)
        with self.assertRaisesRegexp(botocore.exceptions.SAMLError,
                                     'could not find'):
            assertion = self.authenticator.retrieve_saml_assertion(self.config)

    def test_not_able_to_authenticate_bad_status_code(self):
        # This happens if the user provides the wrong password.
        self.requests_session.get.return_value = mock.Mock(
            text=self.LOGIN_FORM, status_code=200)
        self.requests_session.post.return_value = mock.Mock(
            text='<form><input name="SAMLResponse" value="fakeassertion"/></form>',
            # Here we have the case where the IdP responds with a 401
            # status code to indicate an auth failure.
            status_code=401,
        )
        with self.assertRaisesRegexp(botocore.exceptions.SAMLError,
                                     'failed'):
            assertion = self.authenticator.retrieve_saml_assertion(self.config)

    def test_no_saml_assertion_in_response(self):
        # This fake response can happen sometimes if the login fails.
        # The IdP will return a 200 response but with an HTML response
        # that contains error text.
        self.requests_session.post.return_value = mock.Mock(
            text='<html>login failed</html>', status_code=200)
        self.requests_session.get.return_value = mock.Mock(
            text=self.LOGIN_FORM, status_code=200)
        self.assertTrue(self.authenticator.is_suitable(self.config))
        with self.assertRaisesRegexp(botocore.exceptions.SAMLError,
                                     'failed'):
            self.authenticator.retrieve_saml_assertion(self.config)



class TestAssumeRoleWithSAMLProvider(unittest.TestCase):

    ASSERTION = base64.b64encode(b"""<?xml version="1.0" encoding="UTF-8"?>
        <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
                <saml2:AttributeValue>arn:aws:iam::123456789012:saml-provider/Example,arn:aws:iam::123456789012:role/joe</saml2:AttributeValue>
                <saml2:AttributeValue>arn:aws:iam::123456789012:saml-provider/Example,arn:aws:iam::123456789012:role/ray</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:Assertion>
        </saml2p:Response>""")

    def create_client_creator(self, with_response=None):
        # Create a mock sts client that returns a specific response
        # for assume_role_with_saml.
        client = mock.Mock()
        client.assume_role_with_saml.return_value = with_response or {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': (datetime.now(tzlocal()) + timedelta(days=1)).isoformat(),
            },
        }
        return mock.Mock(return_value=client)

    def load_cred(self, profile):
        provider = credentials.AssumeRoleWithSAMLProvider(
            lambda: {'profiles': {'saml': profile}},
            self.create_client_creator(), cache={}, profile_name='saml',
            password_prompter=lambda prompt: 'secret')
        creds = provider.load()
        with self.assertRaises(botocore.exceptions.RefreshUnsupportedError):
            # access_key is a property that will refresh credentials.
            # Forms-based SAML authentication will currently raise an exception
            creds.access_key

    def test_assume_role_with_okta(self):
        profile = {
            'saml_endpoint': 'https://example.com/login.asp',
            'saml_authentication_type': 'form',
            'saml_provider': 'okta',
            'saml_username': 'joe',
            'role_arn': 'arn:aws:iam::123456789012:role/joe',
        }
        mock_form_auth = mock.Mock(spec=saml.SAMLAuthenticator)
        mock_form_auth.retrieve_saml_assertion.return_value = self.ASSERTION
        provider = credentials.AssumeRoleWithSAMLProvider(
            load_config=lambda: {'profiles': {'saml': profile}},
            client_creator=self.create_client_creator(),
            cache={},
            profile_name='saml',
            password_prompter=lambda prompt: 'password',
            authenticators=[mock_form_auth],
        )
        creds = provider.load().get_frozen_credentials()

        self.assertEqual(creds.access_key, 'foo')
        self.assertEqual(creds.secret_key, 'bar')
        self.assertEqual(creds.token, 'baz')

    def test_assume_role_with_adfs(self):
        # TODO: Assume a role with adfs.  Not needed?
        pass

    def test_unmatch_role(self):
        # TODO: Test when we want to assume a role that is not listed.
        pass

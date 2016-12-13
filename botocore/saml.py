from botocore.exceptions import SAMLError
from botocore.compat import six
from botocore.compat import escape
from botocore.compat import urlsplit
from botocore.compat import urljoin
from botocore.compat import json
from botocore.vendored import requests
import xml.etree.ElementTree as ET
import botocore.vendored.requests as requests


class SAMLAuthenticator(object):
    def is_suitable(self, config):
        """Return True if this instance intends to perform authentication.

        :type config: dict
        :param config: It is the profile dictionary loaded from user's profile,
            i.e. {'saml_endpoint': 'https://...', 'saml_provider': '...', ...}
        """
        raise NotImplementedError("is_suitable")

    def retrieve_saml_assertion(self, config):
        """Returns SAML assertion when login succeeds, or None otherwise."""
        raise NotImplementedError("authenticate")


class GenericFormsBasedAuthenticator(SAMLAuthenticator):
    """Retrieve SAML assertion using form based auth.

    This class can retrieve a SAML assertion by using form
    based auth.  The supported workflow is:

        * Make a GET request to ``saml_endpoint``
        * Parse the HTML to look for an HTML form
        * Fill in the form data with the username, password
        * Make a POST request to the URL indicated by the form
          action with the filled in form data.
        * Parse the HTML returned from the service and
          extract out the SAMLAssertion.

    """
    USERNAME_FIELD = 'username'
    PASSWORD_FIELD = 'password'

    _ERROR_BAD_RESPONSE = (
        'Received a non-200 response (%s) when making a request to: %s'
    )
    _ERROR_NO_FORM = (
        'Could not find login form from: %s'
    )
    _ERROR_MISSING_FORM_FIELD = (
        'Error parsing HTML form, could not find the form field: "%s"'
    )
    _ERROR_LOGIN_FAILED_NON_200 = (
        'Login failed, received non 200 response: %s'
    )
    _ERROR_LOGIN_FAILED = (
        'Login failed, could not retrieve SAML assertion. '
        'Double check you have entered your password correctly.'
    )
    _ERROR_MISSING_CONFIG = (
        'Missing required config value for SAML: "%s"'
    )

    def __init__(self, password_prompter, requests_session=None):
        if requests_session is None:
            requests_session = requests.Session()
        self._requests_session = requests_session
        self._password_prompter = password_prompter

    def is_suitable(self, config):
        return config.get('saml_authentication_type') == 'form'

    def retrieve_saml_assertion(self, config):
        """Retrive SAML assertion using form based auth.

        This is a generic form based authenticator that will
        make an HTTP request to retrieve an HTML form, fill in the
        form fields with username/password, and submit the form.

        :type config: dict
        :param config: The config associated with the profile.  Contains:

            * saml_endpoint
            * saml_username

        :raises SAMLError: Raised when we are unable to retrieve a
            SAML assertion.

        :rtype: str
        :return: The base64 encoded SAML assertion if the login process
            was successful.

        """
        # precondition: self.is_suitable() returns true.
        # We still need other values in the config dict to work
        # properly, so we have to validate config params before
        # going any further.
        self._validate_config_values(config)
        endpoint = config['saml_endpoint']
        login_url, form_data = self._retrieve_login_form_from_endpoint(
            endpoint)
        self._fill_in_form_values(config, form_data)
        response = self._send_form_post(login_url, form_data)
        return self._extract_saml_assertion_from_response(response)

    def _validate_config_values(self, config):
        for required in ['saml_endpoint', 'saml_username']:
            if required not in config:
                raise SAMLError(detail=self._ERROR_MISSING_CONFIG % required)

    def _retrieve_login_form_from_endpoint(self, endpoint):
        response = self._requests_session.get(endpoint, verify=True)
        self._assert_non_error_response(response)
        login_form_html_node = self._parse_form_from_html(response.text)
        if login_form_html_node is None:
            raise SAMLError(detail=self._ERROR_NO_FORM % endpoint)
        form_action = urljoin(endpoint,
                              login_form_html_node.attrib.get('action', ''))
        if not form_action.lower().startswith('https://'):
            raise SAMLError(detail='Your SAML IdP must use HTTPS connection')
        payload = dict((tag.attrib['name'], tag.attrib.get('value', ''))
                       for tag in login_form_html_node.findall(".//input"))
        return form_action, payload

    def _assert_non_error_response(self, response):
        if response.status_code != 200:
            raise SAMLError(
                detail=self._ERROR_BAD_RESPONSE % (response.status_code,
                                                   response.url))

    def _parse_form_from_html(self, html):
        # Scrape a form from html page, and return it as an elementtree element
        p = FormParser()
        p.feed(html)
        if p.forms:
            return ET.fromstring(p.extract_form(0))

    def _fill_in_form_values(self, config, form_data):
        username = config['saml_username']
        if self.USERNAME_FIELD not in form_data:
            raise SAMLError(
                detail=self._ERROR_MISSING_FORM_FIELD % self.USERNAME_FIELD)
        if self.USERNAME_FIELD in form_data:
            form_data[self.USERNAME_FIELD] = username
        if self.PASSWORD_FIELD in form_data:
            form_data[self.PASSWORD_FIELD] = self._password_prompter(
                "Password: ")

    def _send_form_post(self, login_url, form_data):
        response = self._requests_session.post(
            login_url, data=form_data, verify=True
        )
        if response.status_code != 200:
            raise SAMLError(detail=self._ERROR_LOGIN_FAILED_NON_200 %
                            response.status_code)
        return response.text

    def _extract_saml_assertion_from_response(self, response_body):
        parsed = self._parse_form_from_html(response_body)
        if parsed is not None:
            return self._get_value_of_first_tag(
                parsed, 'input', 'name', 'SAMLResponse')
        # We can reach here in two cases.
        # First, we were able to login but for some reason we can't find the
        # SAMLResponse in the response body.  The second (and more likely)
        # reason is that the login has failed.  For example, if you provide an
        # invalid password when trying to login, many IdPs will return a 200
        # status code and return HTML content that indicates an error occurred.
        # This is the error we'll present to the user.
        raise SAMLError(detail=self._ERROR_LOGIN_FAILED)

    def _get_value_of_first_tag(self, root, tag, attr, trait):
        for element in root.findall(tag):
            if element.attrib.get(attr) == trait:
                return element.attrib.get('value')


class OktaAuthenticator(GenericFormsBasedAuthenticator):
    def retrieve_saml_assertion(self, config):
        self._validate_config_values(config)
        endpoint = config['saml_endpoint']
        hostname = urlsplit(endpoint).netloc
        auth_url = 'https://%s/api/v1/authn' % hostname
        username = config['saml_username']
        password = self._password_prompter("Password: ")
        response = requests.post(
            auth_url,
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
                     data=json.dumps({'username': username,
                                      'password': password}))
        parsed = json.loads(response.content)
        session_token = parsed['sessionToken']
        saml_url = endpoint + '?sessionToken=%s' % session_token
        response = requests.get(saml_url)
        r = self._extract_saml_assertion_from_response(response.content)
        return r

    def is_suitable(self, config):
        return (config.get('saml_authentication_type') == 'form' and
                config.get('saml_provider') == 'okta')


class ADFSFormsBasedAuthenticator(GenericFormsBasedAuthenticator):
    USERNAME_FIELD = 'ctl00$ContentPlaceHolder1$UsernameTextBox'
    PASSWORD_FIELD = 'ctl00$ContentPlaceHolder1$PasswordTextBox'

    def is_suitable(self, config):
        return (config.get('saml_authentication_type') == 'form' and
                config.get('saml_provider') == 'adfs')


class FormParser(six.moves.html_parser.HTMLParser):
    def __init__(self):
        six.moves.html_parser.HTMLParser.__init__(self)
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        if tag == 'form':
            self._current_form = dict(attrs)
        if tag == 'input' and self._current_form is not None:
            self._current_form.setdefault('_fields', []).append(dict(attrs))

    def handle_endtag(self, tag):
        if tag == 'form' and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def _dict2str(self, d):
        # When input contains things like "&amp;", HTMLParser will unescape it.
        # But we need to use escape() here to nullify the default behavior,
        # so that the output will be suitable to be fed into an ET later.
        return ' '.join(sorted(
            '%s="%s"' % (k, escape(v)) for k, v in d.items()))

    def extract_form(self, index):
        form = dict(self.forms[index])  # Will raise exception if out of bound
        fields = form.pop('_fields', [])
        return '<form %s>%s</form>' % (
            self._dict2str(form),
            ''.join('<input %s/>' % self._dict2str(f) for f in fields))

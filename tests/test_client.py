import json
import urllib.parse
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from django.contrib.sites.models import Site
from django.test import RequestFactory, override_settings

from microsoft_auth.client import MicrosoftClient

from . import TestCase

STATE = "test_state"
CLIENT_ID = "test_client_id"
REDIRECT_URI = "https://testserver/microsoft/auth-callback/"
ACCESS_TOKEN = "test_access_token"


@override_settings(SITE_ID=1)
class ClientTests(TestCase):
    @classmethod
    def setUpClass(self):
        super().setUpClass()

    def setUp(self):
        super().setUp()

        self.factory = RequestFactory()

    def _get_auth_url(self, base_url, scopes=MicrosoftClient.SCOPE_MICROSOFT):
        args = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": " ".join(scopes),
            "state": STATE,
            "response_mode": "form_post",
        }
        return (base_url + "?" + urllib.parse.urlencode(args), STATE)

    def _assert_auth_url(self, expected, actual):
        # parse urls
        e_url = urlparse(expected[0])
        e_qs = parse_qs(e_url.query)
        a_url = urlparse(actual[0])
        a_qs = parse_qs(a_url.query)

        # assert url
        self.assertEqual(e_url.scheme, a_url.scheme)
        self.assertEqual(e_url.path, a_url.path)
        self.assertEqual(e_url.netloc, a_url.netloc)
        self.assertEqual(len(e_qs.items()), len(a_qs.items()))
        for key, value in e_qs.items():
            self.assertEqual(value, a_qs[key])

        # assert state
        self.assertEqual(expected[1], actual[1])

    def test_scope(self):
        expected_scopes = " ".join(MicrosoftClient.SCOPE_MICROSOFT)

        auth_client = MicrosoftClient()
        self.assertEqual(expected_scopes, auth_client.scope)

    def test_state(self):
        auth_client = MicrosoftClient(state=STATE)
        self.assertEqual(STATE, auth_client.state)

    def test_redirect_uri(self):
        auth_client = MicrosoftClient()
        self.assertEqual(REDIRECT_URI, auth_client.redirect_uri)

    @override_settings(MICROSOFT_AUTH_CLIENT_ID=CLIENT_ID)
    def test_authorization_url(self):
        auth_client = MicrosoftClient(state=STATE)

        base_url = auth_client.openid_config["authorization_endpoint"]
        expected_auth_url = self._get_auth_url(base_url)

        self._assert_auth_url(
            expected_auth_url, auth_client.authorization_url()
        )

    def test_valid_scopes(self):
        scopes = MicrosoftClient.SCOPE_MICROSOFT

        auth_client = MicrosoftClient()
        self.assertTrue(auth_client.valid_scopes(scopes))

    def test_valid_scopes_invalid(self):
        scopes = ["fake"]

        auth_client = MicrosoftClient()
        self.assertFalse(auth_client.valid_scopes(scopes))

    @override_settings(
        SITE_ID=None, ALLOWED_HOSTS=["example.com", "testserver"]
    )
    def test_alternative_site(self):
        self.assertEqual(Site.objects.get(pk=1).domain, "testserver")

        Site.objects.create(domain="example.com", name="example.com")

        request = self.factory.get("/", HTTP_HOST="example.com")

        self.assertEqual(
            Site.objects.get_current(request).domain, "example.com"
        )

        client = MicrosoftClient(request=request)

        self.assertIn("example.com", client.authorization_url()[0])

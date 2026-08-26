"""
Shared authentication for the AlgoSec AppViz library.

AppVizAuth handles everything both API versions need in common: region
selection, credential resolution (explicit args or environment.py /
.env), and access-key login against /api/algosaas/auth/v1/access-keys/login
to obtain a bearer token. It does NOT provide any HTTP request helpers --
each API version (AppViz for v2, AppVizV3 for v3) implements its own,
since they hit different base paths and may shape requests differently.

Both AppViz() and AppVizV3() authenticate independently when instantiated;
they are not required to share a login/session.
"""

import logging
from datetime import datetime, timedelta

import requests

from . import environment

logger = logging.getLogger(__name__)

REGIONS = {
    'eu': 'eu.app.algosec.com',
    'us': 'us.app.algosec.com',
    'anz': 'anz.app.algosec.com',
    'me': 'me.app.algosec.com',
    'uae': 'uae.app.algosec.com',
    'ind': 'ind.app.algosec.com',
    'sgp': 'sgp.app.algosec.com',
}

#: How much headroom (seconds) to leave before actual expiry when deciding
#: whether the token needs to be refreshed.
_TOKEN_REFRESH_MARGIN = timedelta(seconds=60)


class AppVizAuth:
    """
    Base class providing AlgoSec AppViz access-key authentication.

    Subclasses get: self.url, self.region, self.tenant_id,
    self._token_type, self._token, self._token_expires, all populated
    after __init__ runs (login happens eagerly, same as before).
    """

    def __init__(self, region='eu', tenant_id=None, client_id=None,
                 client_secret=None, proxies=None):
        if region not in REGIONS.keys():
            raise ValueError(f"Invalid region, must be one of: {', '.join(REGIONS.keys())}")

        self.proxies = proxies
        self.region = region
        self.tenant_id = tenant_id or environment.get_tenant_id()
        self._client_id = client_id or environment.get_client_id()
        self._client_secret = client_secret or environment.get_client_secret()

        self.url = 'https://' + REGIONS[self.region]

        self._token_type = None
        self._token = None
        self._token_expires = None

        self._init_token()

    def _init_token(self):
        login_url = f"https://{REGIONS[self.region]}/api/algosaas/auth/v1/access-keys/login"
        data = {
            "tenantId": self.tenant_id,
            "clientId": self._client_id,
            "clientSecret": self._client_secret,
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        logger.info("Authenticating to AppViz (region=%s, tenant=%s)",
                    self.region, self.tenant_id)
        response = requests.post(login_url, json=data, headers=headers,
                                  proxies=self.proxies)
        if response.status_code != 200:
            logger.error("Authentication to AppViz failed (status=%s): %s",
                         response.status_code, response.text)
            raise ConnectionError(f"Authentication to AppViz failed: {response.text}")

        body = response.json()
        self._token_type = body['token_type']
        self._token = body['access_token']
        self._token_expires = datetime.now() + timedelta(seconds=body['expires_in'])
        logger.info("AppViz authentication succeeded, token expires at %s",
                    self._token_expires)

    def _ensure_token(self):
        """Refresh the token if it's missing or close to expiry."""
        if (self._token is None or self._token_expires is None
                or datetime.now() >= self._token_expires - _TOKEN_REFRESH_MARGIN):
            logger.debug("AppViz token missing or near expiry, refreshing")
            self._init_token()

    @property
    def _auth_header(self):
        """Ready-to-use Authorization header value, refreshing first if needed."""
        self._ensure_token()
        return f"{self._token_type} {self._token}"

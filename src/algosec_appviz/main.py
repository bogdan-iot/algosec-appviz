import requests
from algosec_appviz import environment
from mydict import MyDict

regions = {
    'eu': 'eu.app.algosec.com',
    'us': 'us.app.algosec.com',
    'anz': 'anz.app.algosec.com',
    'me': 'me.app.algosec.com',
    'uae': 'uae.app.algosec.com',
    'ind': 'ind.app.algosec.com',
    'sgp': 'sgp.app.algosec.com'
}


class AppViz:
    def __init__(self, region='eu', tenant_id=None, client_id=None, client_secret=None, proxies=None):
        if region not in regions.keys():
            raise ValueError(f"Invalid region, must be one of: {', '.join(regions.keys())}")

        self.proxies = proxies

        login_url = f"https://{regions[region]}/api/algosaas/auth/v1/access-keys/login"
        data = {
            "tenantId": tenant_id or environment.get_tenant_id(),
            "clientId": client_id or environment.get_client_id(),
            "clientSecret": client_secret or environment.get_client_secret()
        }

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        response = requests.post(login_url, json=data, headers=headers, proxies=self.proxies)
        if response.status_code != 200:
            raise ConnectionError(f"Authentication to AppViz failed: {response.text}")

        self.url = 'https://' + regions[region]
        self._token_type = response.json()['token_type']
        self._token = response.json()['access_token']

    def create_application(self, name=None, **kwargs):
        if not name:
            raise ValueError("Name is required")

        body = {
            'name': name,
            **kwargs
        }

        result = self._make_api_call('POST',
                                     '/BusinessFlow/rest/v1/applications/new',
                                     body=body)

        return result

    def create_network_object(self, name=None, obj_type=None, content=None, **kwargs):
        valid_object_types = ['Range', 'Host', 'Group', 'Abstract']

        if not name:
            raise ValueError("Object name is required")
        if not obj_type:
            raise ValueError("Object type is required")
        if obj_type not in valid_object_types:
            raise ValueError(f"Object type invalid, allowed values: {', '.join(valid_object_types)}")

        body = {
            'name': name,
            'type': obj_type,
            'content': content,
            **kwargs
        }

        result = self._make_api_call('POST',
                                     '/BusinessFlow/rest/v1/network_objects/new',
                                     body=body)

        return result

    def get_applications(self):
        response = self._make_api_call('GET',
                                       '/BusinessFlow/rest/v1/applications')

        return [MyDict(x) for x in response]

    def list_network_objects(self, page_number=1, page_size=1000):
        response = self._make_api_call('GET',
                                       '/BusinessFlow/rest/v1/network_objects/',
                                       params={'page_number': page_number, 'page_size': page_size})

        return [MyDict(x) for x in response]

    def search_exact_object(self, content):
        response = self._make_api_call('GET',
                                       '/BusinessFlow/rest/v1/network_objects/find',
                                       params={'address': content, 'type': 'EXACT'})

        return [MyDict(x) for x in response]

    def _make_api_call(self, method, url_path, body=None, params=None):
        headers = {
            'Accept': 'application/json',
            'Authorization': f'{self._token_type} {self._token}'
        }

        url = self.url + url_path

        if method.lower() == 'get':
            response = requests.get(url, headers=headers, json=body, params=params, proxies=self.proxies)
        elif method.lower() == 'post':
            response = requests.post(url, headers=headers, json=body, params=params, proxies=self.proxies)
        else:
            raise ValueError("Invalid method, must be: 'GET' or 'POST'")

        response.raise_for_status()
        return response.json()

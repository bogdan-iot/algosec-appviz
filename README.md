# AlgoSec AppViz Python Library

Unofficial library to interact with AlgoSec AppViz in Python. Official API documentation can be found here:  
https://api-docs.algosec.com/docs/appvizsaas-api-docs/lr8pw057bsh37-welcome-to-the-app-viz-api-reference

## API Endpoint
**Important Note:** If not specified, the EU region will be used. If your tenant is provisioned in a different
region, this needs to be provided when creating the class instance.

## Installation

```shell
$ pip install algosec_appviz
```

## Environment Variables

The following Environment Variables will be automatically read if set:  
TENANT_ID  
CLIENT_ID  
CLIENT_SECRET

## Usage

```python
from algosec_appviz import AppViz

# Use automatically loaded environment variables as mentioned above
appviz_inst = AppViz()

# Provide parameters in code
appviz_inst = AppViz(region='us', tenant_id='xxx', client_id='xxx', client_secret='xxx')
```

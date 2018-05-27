Unifi API library and cli tool
================================

ALPHA API tool

.. code-block:: python

  import unifiapi
  c = unifiapi.controller(endpoint='https://unifi:8443', usernane='ubnt', password='ubnt', verify=False)
  s = c.sites['default']()
  s.devices()

For simple access please define a unifiapi.yaml file in the cwd or ~/.unifiapi_yaml with the following syntax::

  default:
    endpoint: 'https://unifi.mydomain.com'
    username: 'myusername'
    password: '12345'
    verify: False
  other:
    endpoint: 'https://unifi.myothersite.com'
    username: 'bob'
    password: '42'
    verify: True
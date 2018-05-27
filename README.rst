Unifi API library and cli tool
================================

ALPHA API tool.  This is still very perliminary and much documentation has yet to be written.  Examples will follow.

.. code-block:: python

  import unifiapi
  c = unifiapi.controller(endpoint='https://unifi:8443', usernane='ubnt', password='ubnt', verify=False)
  s = c.sites['default']()
  s.devices()

For simple access please define a unifiapi.yaml file in the cwd or ~/.unifiapi_yaml with the following syntax

.. code-block:: yaml

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

--------
Examples
--------

Change mss_clamp from disabled to auto

.. code-block::

  >>> import unifiapi
  >>> # Get controller object
  >>> c2 = unifiapi.controller(endpoint='https://192.168.111.20:8443', verify=False)
  Please enter credentials for Unifi https://192.168.111.20:8443
  Username (CR=erice): foo
  foo Password :
  >>> # get site object
  >>> s = c2.sites['default']()
  >>> settings = s.settings()
  >>> settings['usg']
  {'_id': '5ad52945be0777002184bc4a', 'broadcast_ping': False, 'echo_server': 'ping.ubnt.com', 'ftp_module': True, 'gre_module': True, 'h323_module': True, 'key': 'usg', 'lldp_enable_all': True, 'mdns_enabled': True, 'mss_clamp': 'disabled', 'mss_clamp_mss': 1452, 'offload_accounting': True, 'offload_l2_blocking': True, 'offload_sch': True, 'pptp_module': True, 'receive_redirects': False, 'send_redirects': True, 'sip_module': False, 'site_id': '5ad52944be0777002184bc41', 'syn_cookies': True, 'tftp_module': True, 'upnp_enabled': True, 'upnp_nat_pmp_enabled': True, 'upnp_secure_mode': True, 'upnp_wan_interface': 'wan'}
  >>> settings['usg']['mss_clamp'] = 'auto'
  >>> settings['usg'].endpoint
  'rest/setting/usg/5ad52945be0777002184bc4a'
  >>> # Use put for updates
  >>> s.put(settings['usg'].endpoint, **settings['usg'])
  Unifi Response rest/setting/usg/5ad52945be0777002184bc4a: data 1 meta {'rc': 'ok'}
  >>> settings = s.settings()
  >>> settings['usg']
  {'_id': '5ad52945be0777002184bc4a', 'broadcast_ping': False, 'echo_server': 'ping.ubnt.com', 'ftp_module': True, 'gre_module': True, 'h323_module': True, 'key': 'usg', 'lldp_enable_all': True, 'mdns_enabled': True, 'mss_clamp': 'auto', 'mss_clamp_mss': 1452, 'offload_accounting': True, 'offload_l2_blocking': True, 'offload_sch': True, 'pptp_module': True, 'receive_redirects': False, 'send_redirects': True, 'sip_module': False, 'site_id': '5ad52944be0777002184bc41', 'syn_cookies': True, 'tftp_module': True, 'upnp_enabled': True, 'upnp_nat_pmp_enabled': True, 'upnp_secure_mode': True, 'upnp_wan_interface': 'wan'}
  
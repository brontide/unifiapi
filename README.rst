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
  
List backups

.. code-block::

  >>> backups = s.c_backups()
  >>> for item in backups:
  ...     print("{datetime} {filename} {size}".format(**item))
  ...
  2018-05-06T00:00:00Z autobackup_5.7.23_20180506_0000_1525564800026.unf 13915648
  2018-05-13T00:00:00Z autobackup_5.7.23_20180513_0000_1526169600008.unf 22216336
  2018-05-19T00:00:00Z autobackup_5.7.23_20180519_0000_1526688000016.unf 24923824
  2018-05-20T00:00:00Z autobackup_5.7.23_20180520_0000_1526774400013.unf 25360096
  2018-05-21T00:00:00Z autobackup_5.7.23_20180521_0000_1526860800007.unf 25751888
  2018-05-22T00:00:00Z autobackup_5.7.23_20180522_0000_1526947200012.unf 26076656
  2018-05-23T00:00:00Z autobackup_5.7.23_20180523_0000_1527033600013.unf 26448416
  2018-05-24T00:00:00Z autobackup_5.7.23_20180524_0000_1527120000007.unf 26862720
  2018-05-25T00:00:00Z autobackup_5.7.23_20180525_0000_1527206400013.unf 27250960
  2018-05-26T00:00:00Z autobackup_5.7.23_20180526_0000_1527292800011.unf 27546816
  2018-05-27T00:00:00Z autobackup_5.7.23_20180527_0000_1527379200013.unf 28005568

  
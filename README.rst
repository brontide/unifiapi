Unifi API library and examples
================================

ALPHA API tool.  This is still very perliminary and much documentation has yet to be written.  This is written for
python 3 but I will make every attempt to keep it working under python 2.

At the heart of this are some very simple RESTful wrappers.  The UnifiClient base implements get, put, post, and delete calls
while adding whatever prefix they were started with.  The controller has no prefix and the site has api/s/{sitename}.  The
return values from the API are wrapped to preseve fidelety of the data and meta.  The response object is a UserList so it acts
like a list most of the time but has additional properties.  It can be indexed with strings and it will try to do the right 
thing ( see sites['default'] in examples ).  There is a meta property which has the full meta returned by the server.


.. code-block:: python

  import unifiapi
  c = unifiapi.controller(endpoint='https://unifi:8443', username='ubnt', password='ubnt', verify=False)
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
    endpoint: 'https://10.11.12.13:8443'
    username: 'bob'
    password: '42'
    verify: True

--------
Examples
--------

Toggle syn cookies.

.. code-block::

  >>> from unifiapi import controller
  >>> # Get controller object
  >>> c = controller(endpoint='https://192.168.111.20:8443', verify=False)
  Please enter credentials for Unifi https://192.168.111.20:8443
  Username (CR=erice): foo
  foo Password :
  >>> s = c.sites[0]()
  >>> settings = s.settings()
  >>> settings['dpi']
  {'_id': '5ad52945be0777002184bc49', 'enabled': True, 'key': 'dpi', 'site_id': '5ad52944be0777002184bc41'}
  >>> settings['usg']
  {'_id': '5ad52945be0777002184bc4a', 'broadcast_ping': False, 'echo_server': 'ping.ubnt.com', 'ftp_module': True, 'gre_module': True, 'h323_module': True, 'key': 'usg', 'lldp_enable_all': True, 'mdns_enabled': True, 'mss_clamp': 'auto', 'mss_clamp_mss': 1452, 'offload_accounting': True, 'offload_l2_blocking': True, 'offload_sch': True, 'pptp_module': True, 'receive_redirects': False, 'send_redirects': True, 'sip_module': False, 'site_id': '5ad52944be0777002184bc41', 'syn_cookies': True, 'tftp_module': True, 'upnp_enabled': True, 'upnp_nat_pmp_enabled': True, 'upnp_secure_mode': True, 'upnp_wan_interface': 'wan'}
  >>> settings['usg']['syn_cookies'] = False
  >>> settings['usg'].update()
  [{'_id': '5ad52945be0777002184bc4a', 'broadcast_ping': False, 'echo_server': 'ping.ubnt.com', 'ftp_module': True, 'gre_module': True, 'h323_module': True, 'key': 'usg', 'lldp_enable_all': True, 'mdns_enabled': True, 'mss_clamp': 'auto', 'mss_clamp_mss': 1452, 'offload_accounting': True, 'offload_l2_blocking': True, 'offload_sch': True, 'pptp_module': True, 'receive_redirects': False, 'send_redirects': True, 'sip_module': False, 'site_id': '5ad52944be0777002184bc41', 'syn_cookies': False, 'tftp_module': True, 'upnp_enabled': True, 'upnp_nat_pmp_enabled': True, 'upnp_secure_mode': True, 'upnp_wan_interface': 'wan'}]
  >>> settings['usg']['syn_cookies'] = True
  >>> settings['usg'].update()
  [{'_id': '5ad52945be0777002184bc4a', 'broadcast_ping': False, 'echo_server': 'ping.ubnt.com', 'ftp_module': True, 'gre_module': True, 'h323_module': True, 'key': 'usg', 'lldp_enable_all': True, 'mdns_enabled': True, 'mss_clamp': 'auto', 'mss_clamp_mss': 1452, 'offload_accounting': True, 'offload_l2_blocking': True, 'offload_sch': True, 'pptp_module': True, 'receive_redirects': False, 'send_redirects': True, 'sip_module': False, 'site_id': '5ad52944be0777002184bc41', 'syn_cookies': True, 'tftp_module': True, 'upnp_enabled': True, 'upnp_nat_pmp_enabled': True, 'upnp_secure_mode': True, 'upnp_wan_interface': 'wan'}]
  
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

Show the temperatures of all units with sensors

.. code-block::

  >>> devs = s.devices()
  >>> for item in devs.filter_by('has_temperature', True):
  ...     print('{ip} - {general_temperature}C'.format(**item))
  ...
  10.11.10.6 - 58C

#!/usr/bin/env python3

# Simple text-based report of devices and active clients
#
# $ python3 devices_clients.py
# =======================================================================
# ====  DEVICES  ========================================================
#
# Name        IP             Type    Model    Version
# ----------  -------------  ------  -------  --------------
# ap1         192.168.1.63   uap     U7LR     4.3.20.11298
# switch1     192.168.1.10   usw     US8P60   4.3.20.11298
# gateway     1.2.3.4        ugw     UGW3     4.4.51.5287926
#
# =======================================================================
# ====  CLIENTS  ========================================================
#
# Name             Hostname                 IP (Static)          OUI
# ---------------  -----------------------  -------------------  --------
# nest             09EF01AC78132FA7         192.168.1.37 (No)    NestLabs
# ipad             iPad                     192.168.1.50 (No)    Apple
# <none>           pihole                   192.168.1.98 (Yes)   Raspberr
#
# ...

import unifiapi
from pprint import pprint
from tabulate import tabulate

c = unifiapi.controller()
s = c.sites['default']()

print('=======================================================================')
print('====  DEVICES  ========================================================')
print()
table = []
for device in s.devices():
  row = [device['name'], device['ip'], device['type'], device['model'], device['version']]
  table.append(row)
print(tabulate(table, headers=['Name', 'IP', 'Type', 'Model', 'Version']))

print()

print('=======================================================================')
print('====  CLIENTS  ========================================================')
print()
table = []
for client in s.active_clients():
  row = []
  if 'name' in client.keys():
    row.append(client['name'])
  else:
    row.append('<none>')
  if 'hostname' in client.keys():
    row.append(client['hostname'])
  else:
    row.append('<none>')
  ip = client['ip']
  if 'use_fixedip' in client.keys():
    if client['use_fixedip']:
      ip += ' (Yes)'
    else:
      ip += ' (No)'
  else:
    ip += ' (No)'
  row.append(ip)
  row.append(client['oui'])
  table.append(row)
print(tabulate(table, headers=['Name', 'Hostname', 'IP (Static)', 'OUI']))

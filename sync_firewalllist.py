#!/usr/bin/env python3

#
# Simple script to show off how easy it is to automate the controller API.  This script shows off enumerating the
# current backups, downloading, and optionally deleting all the backups from the controller
#

import unifiapi
import requests

sync_list = {
    'Spamhaus EDROP': 'https://www.spamhaus.org/drop/edrop.txt',
#    'Emerging Threats': 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
#    'TOR Exit Nodes': 'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1',
}


def download_ips(url):
    ''' given an ip, download a list of ips '''
    out = requests.get(url, stream=True)
    out.raise_for_status()
    for line in out.iter_lines(decode_unicode=True):
        if not line[0].isdigit():
            continue
        candidate = line.split()[0]
        if candidate:
            yield candidate

def new_firewall_group(name, list_members, group_type='address-group'):
    return {'name': name, 'group_type': group_type, 'group_members': list(list_members) }

print("Logging into controller")
c = unifiapi.controller()
s = c.sites['default']()
print("Getting firewall listing")
fwg = s.firewallgroups()

for list_name, url in sync_list.items():
    print(f'Syncing {list_name}')
    list_ips = sorted(set((download_ips(url))))
    try:
        unififw = fwg['list_name']
        print("Found existing list {} with {} members - download list has {} members".format(list_name, len(unififw), len(list_ips)))
    except:
        print("No list {} found".format(list_name))
    


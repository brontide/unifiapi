#!/usr/bin/env python3

#
# Script pulls in IP address/ranges from these URLs and updates the list on the unifi controller to match
#

import unifiapi
import requests
import json

sync_list = {
    'Spamhaus_EDROP': 'https://www.spamhaus.org/drop/edrop.txt',
    'Emerging_Threats': 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
    'TOR Exit Nodes': 'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1',
    'Bad_Packets_List': 'https://raw.githubusercontent.com/tg12/bad_packets_blocklist/master/bad_packets_list.txt'
}


def download_ips(url):
    ''' given a URL, download a list of ips '''
    out = requests.get(url, stream=True)
    out.raise_for_status()
    for line in out.iter_lines(decode_unicode=True):
        if not line or not str(line[0]).isdigit():
            continue
        candidate = line.split()[0]
        if candidate:
            yield candidate


def new_firewall_group(name, list_members, group_type='address-group'):
    return json.dumps({
        'name': name,
        'group_type': group_type,
        'group_members': list(list_members)})


print("Logging into controller")
c = unifiapi.controller()
s = c.sites['default']()
print("Getting firewall listing")
fwg = s.firewallgroups()

for list_name, url in sync_list.items():
    print(f'Syncing {list_name}')
    list_ips = sorted(set((download_ips(url))))
    try:
        # this will raise KeyError and fall back to adding the firewall
        curfw = fwg[list_name]
        curips = sorted(set(curfw['group_members']))
        if curips == list_ips:
            print(
                "Found IDENTICAL existing list {} with {} members - download list has {} members".format(
                    list_name,
                    len(curips),
                    len(list_ips)))
        else:
            print("List has changed, updating")
            curfw['group_members'] = list_ips
            curfw.update()  # Update the record.
    except KeyError:
        print("No list {} found, adding".format(list_name))
        r = s.firewallgroups(new_firewall_group(list_name, list_ips))

#!/usr/bin/env python3

#
# Script to show bandwidth usage by client over a definable threshold
#

from unifiapi import controller
import time
from datetime import datetime

tracking = 'tx_bytes' # download = tx_bytes / upload = rx_bytes
threshold = (1*1024*1024)/8 # 1.5 mbps
interval = '5minutes'
interval_sec = 5*60 # 300 seconds in 5 mintues to calculate bandwidth

print("Logging into controller")
c = controller()
s = c.sites['default']()

print("Fetching and processing client lists")
clients = s.clients()

def best_name(client):
    if 'name' in client:
        return "{name} ({mac})".format(**client)
    if 'hostname' in client:
        return "{hostname} ({mac})".format(**client)
    return "UKN ({mac})".format(**client)

mac_to_name = dict(( (x['mac'], best_name(x)) for x in clients ))

end = time.time()*1000
start = end-(86400*1000)

print("Fetching bandwidth per user report")
bandwidth_per_user = s.user_report(interval=interval, end=end, start=start)

timestamps = set((x['time'] for x in bandwidth_per_user))

users_per_time = {}
for timestamp in sorted(timestamps):
    users_per_time[timestamp] = []

# Let's filter our records for ones above our threshold
for record in bandwidth_per_user:
    if record[tracking] > ( threshold * interval_sec):
        users_per_time[record['time']].append(record)

for timestamp in sorted(timestamps):
    if users_per_time[timestamp]:
        print(datetime.fromtimestamp(timestamp/1000).strftime('%m-%d %I:%M %p'))
        for user in users_per_time[timestamp]:
            speed = int((user[tracking]/interval_sec)/1024)*8
            name = mac_to_name[user['user']]
            print(name, speed, "kbps")

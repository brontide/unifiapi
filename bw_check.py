'''THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''

# Bitcoin Cash (BCH)   qpz32c4lg7x7lnk9jg6qg7s4uavdce89myax5v5nuk
# Ether (ETH) -        0x843d3DEC2A4705BD4f45F674F641cE2D0022c9FB
# Litecoin (LTC) -     Lfk5y4F7KZa9oRxpazETwjQnHszEPvqPvu
# Bitcoin (BTC) -      34L8qWiQyKr8k4TnHDacfjbaSqQASbBtTd

# contact :- github@jamessawyer.co.uk



#!/usr/bin/env python3

#
# Script to show bandwidth usage by client over a definable threshold
#
# The 5 minutes averages seem to poorly catch the peaks that you might see on the
# dashboard graph.
#

'''
Logging into controller
Fetching and processing client lists
Fetching bandwidth per user report
05-30 04:00 PM
iPad 1416 kbps
05-30 05:50 PM
iPad 1344 kbps
05-30 05:55 PM
iPad 1432 kbps
05-30 06:00 PM
iPad 1424 kbps
05-30 10:15 PM
Basselope 3344 kbps
05-30 10:20 PM
Basselope 11896 kbps
05-30 10:25 PM
Basselope 6568 kbps
05-31 12:15 AM
DESKTOP-20CSORF 3336 kbps
'''

from unifiapi import controller
import time
from datetime import datetime

tracking = 'rx_bytes'  # download = tx_bytes / upload = rx_bytes
threshold = (1 * 1024 * 1024) / 8  # 1.5 mbps
interval = '5minutes'
interval_sec = 5 * 60  # 300 seconds in 5 mintues to calculate bandwidth

print("Logging into controller")
c = controller()
s = c.sites['default']()

print("Fetching and processing client lists")
clients = s.clients()


def best_name(client):
    if 'name' in client:
        return "{name}".format(**client)
    if 'hostname' in client:
        return "{hostname}".format(**client)
    return "UKN ({mac})".format(**client)


mac_to_name = dict(((x['mac'], best_name(x)) for x in clients))

end = time.time() * 1000
start = end - (60 * 60 * 24 * 1000)

print("Fetching bandwidth per user report")
bandwidth_per_user = s.user_report(interval=interval, end=end, start=start)

timestamps = set((x['time'] for x in bandwidth_per_user))

users_per_time = {}
for timestamp in sorted(timestamps):
    users_per_time[timestamp] = []

# Let's filter our records for ones above our threshold
for record in bandwidth_per_user:
    if record[tracking] > (threshold * interval_sec):
        users_per_time[record['time']].append(record)

for timestamp in sorted(timestamps):
    if users_per_time[timestamp]:
        print(
            datetime.fromtimestamp(
                timestamp /
                1000).strftime('%m-%d %I:%M %p'))
        for user in users_per_time[timestamp]:
            speed = int((user[tracking] / interval_sec) / 1024) * 8
            name = mac_to_name[user['user']]
            print(name, speed, "kbps")

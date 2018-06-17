from influxdb import InfluxDBClient
from unifiapi import controller, UnifiApiError
from random import randint
from time import sleep
from datetime import datetime
from pprint import pprint
from time import time

# EDIT
profile = 'byip'
site_name = 'default'

default_tags = None

client = InfluxDBClient('localhost', 8086)

# END EDIT

c = controller(profile=profile)
s = c.sites[site_name]()

try:
    default_tags = {
        'hostname': s.sysinfo()[0]['hostname'],
        'site': site_name,
        'desc': c.sites[site_name]['desc']
    }
except:
    print("Could not generate site default tags")

client.create_database('unifi')
client.switch_database('unifi')

current_data = {}
last_app_dpi = 0
last_cat_dpi = 0

dups = {}
def is_dup(point):
    cts = time()
    _id = [ point['measurement'] ]
    _id.extend( point['tags'].values() )
    xid = '-'.join(_id)
    yid = '-'.join( map(str, point['fields'].values()) )
    if xid in dups:
        ( ts, cyid ) = dups[xid]
        if cyid == yid and (cts-ts)<60:
            return True
    dups[xid] = (cts, yid)
    return False

def time_str(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

def dev_to_measures(dev):
    for field in ['rx_bytes', 'rx_packets', 'rx_dropped', 'rx_errors', 'tx_bytes','tx_packets', 'tx_dropped', 'tx_errors']:
        yield dev['mac'], field, dev['uplink'][field]
    yield dev['mac'], 'num_sta', dev['num_sta']

def client_markup(client, devs):
    if 'ap_mac' in client:
        # try to get the name
        try:
            ap = devs.filter_by('mac',client['ap_mac'])
            client.data['ap_name'] = ap[0]['name']
        except:
            pass

def client_to_measures(client):
    for field in ['rx_bytes', 'rx_packets', 'tx_bytes','tx_packets', 'ap_name', 'essid', 'rssi', 'rx_rate', 'tx_rate', 'channel']:
        try:
            yield client['mac'], field, client[field]
        except:
            pass

def client_best_name(client):
    if 'name' in client:
        return client['name']
    if 'hostname' in client:
        return client['hostname']
    return "UNKN-{}".format(client['mac'])

while True:
    json = []
    ts = datetime.utcnow()

    try:
        # Device uplink data
        devs = s.devices()

        for dev in devs:
            temp_json = {
                'measurement': 'uplink',
                'tags': {
                    'name': dev['name'],
                    'mac': dev['mac'],
                    'type': dev['type'],
                    },
                'time': time_str(ts),
                'fields': {}
                }
            for mac,field,value in dev_to_measures(dev):
                cur_value, cur_ts = current_data.get((mac,field), [0,datetime.fromtimestamp(10000)])
                if value != cur_value or (ts-cur_ts).total_seconds() > 30+randint(0,10):
                    current_data[(mac,field)] = [value, ts]
                    temp_json['fields'][field] = value
            if temp_json['fields']:
                json.append(temp_json)

            # device system stats
            temp_json = {
                'measurement': 'system-stats',
                'tags': {
                    'name': dev['name'],
                    'mac': dev['mac'],
                    'type': dev['type'],
                    },
                'time': time_str(ts),
                'fields': {}
                }
            field['cpu'] = float(dev['system-stats']['cpu'])
            field['mem'] = float(dev['system-stats']['mem'])
            try:
                field['temp'] = float(dev['general_temperature'])
            except:
                pass
            try:
                field['fan_level'] = int(dev['fan_level'])
            except:
                pass
            if not is_dup(temp_json):
                json.append(temp_json)

        # client activity
        clients = s.active_clients()
        for cli in clients:
            client_markup(cli,devs)
            temp_json = {
                'measurement': 'client',
                'tags': {
                    'name': client_best_name(cli),
                    'mac': cli['mac'],
                    },
                'time': time_str(ts),
                'fields': {}
                }
            for mac,field,value in client_to_measures(cli):
                cur_value, cur_ts = current_data.get((mac,field), [0,datetime.fromtimestamp(10000)])
                if value != cur_value or (ts-cur_ts).total_seconds() > 60+randint(0,30):
                    current_data[(mac,field)] = [value, ts]
                    temp_json['fields'][field] = value
            if temp_json['fields']:
                print(temp_json)
                json.append(temp_json)


        # Site DPI
        dpi = s.dpi(type='by_app')
        dpi[0].translate()
        for row in dpi[0]['by_app']:
            tags = {
                    'appid': (row['cat']<<16)+row['app'],
                    'application': row['application'],
                    }
            fields = { 
                    'category': row['category'],
                    'rx_bytes': row['rx_bytes'],
                    'rx_packets': row['rx_packets'],
                    'tx_bytes': row['tx_bytes'],
                    'tx_packets': row['tx_packets'],
                    }
            cur_field = current_data.get(tuple(tags.items()), {})
            if tuple(fields.items()) != tuple(cur_field.items()):
                #print(tags,fields)
                current_data[tuple(tags.items())] = fields
                json.append({
                    'time': time_str(ts),
                    'measurement': 'dpi_site_by_app',
                    'tags': tags,
                    'fields': fields,
                    })
    except UnifiApiError:
        print("exception in controller, wait 30 and try logging in again")
        sleep(30)
        c = controller(profile=profile)
        s = c.sites[site_name]()
    except:
        print("exception in gather")
        pass
                    
    if json:
        while not client.write_points(json, tags=default_tags):
            # keep trying every second to post results
            sleep(1)
        #pprint(json)
    print(ts)
    sleep(10)

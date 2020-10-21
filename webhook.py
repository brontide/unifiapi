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



from unifiapi import controller
from time import sleep
from requests import post

# create a file secrets.py and define
# url = "slack comptible endpoint url"
from secrets import url

c = controller()
s = c.sites['default']()
site_name = c.sites['default']['desc']

hlth = None
alerts = None


def find_name(alert):
    for key in alert:
        if 'name' in key:
            return alert[key]


def alert_to_attachment(alerts, previous=None):
    res = []
    already_seen = []
    if previous:
        already_seen = set((x['_id'] for x in previous))
    for alert in alerts:
        if alert['_id'] not in already_seen:
            # New alert
            name = find_name(alert)
            msg = alert['msg']
            foo = f"{name} - {msg}"
            res.append({'ts': alert['time'] / 1000,
                        'fallback': foo, 'text': foo})
    return res


def status_to_color(status):
    if status == 'ok':
        return 'good'
    if status in ['warning', 'unknown']:
        return 'warning'
    return 'danger'


def health_to_attachments(health, previous=None, ignore_unknown=False):
    hlth = dict(((x['subsystem'], x)for x in health))
    res = []
    if previous:
        hlth2 = dict(((x['subsystem'], x)for x in previous))
        for key in list(hlth.keys()):
            try:
                if hlth[key]['status'] == hlth2[key]['status']:
                    del hlth[key]
            except KeyError:
                pass
    if ignore_unknown:
        for key in list(hlth.keys()):
            try:
                if hlth[key]['status'] == 'unknown':
                    del hlth[key]
            except KeyError:
                pass
    for key, name in [('vpn', 'VPN'), ('www', 'Internet'),
                      ('wan', 'Firewall'), ('lan', 'LAN'), ('wlan', 'WiFi')]:
        if key in hlth:
            status = hlth[key]['status']
            color = status_to_color(status)
            res.append({
                'text': f'{name} is {status}',
                'fallback': f'{name} is {status}',
                'color': color
            })
    return res


while True:
    new = s.health()
    res = health_to_attachments(new, previous=hlth, ignore_unknown=False)
    if res:
        data = {
            'username': 'Health Status',
            'text': f'Health for {site_name}',
            'attachments': res}
        post(url, json=data)
    hlth = new

    new = s.alerts(args={'archived': 'false'})
    res = alert_to_attachment(new, alerts)
    if res:
        data = {
            'username': 'Alerts',
            'text': f'Alerts for {site_name}',
            'attachments': res}
        post(url, json=data)
    alerts = new
    sleep(10)

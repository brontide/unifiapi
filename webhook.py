from unifiapi import controller
from time import sleep
from requests import post

url = 'https://discordapp.com/api/webhooks/458364719699591168/Hehms2ae1546BEvcRzNYzBlAHM-H1soFcPlPcPk5rcgGZdM575zKDocRzoPKw6uXYCi7/slack'
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
        already_seen = set(( x['_id'] for x in previous ))
    for alert in alerts:
        if not alert['_id'] in already_seen:
            # New alert
            name = find_name(alert)
            msg = alert['msg']
            foo = f"{name} - {msg}"
            res.append({'ts': alert['time']/1000, 'fallback': foo, 'text':foo})
    return res

def health_to_attachments(health, previous=None, ignore_unknown=False):
	hlth = dict(((x['subsystem'],x)for x in health))
	res = []
	if previous:
		hlth2 = dict(((x['subsystem'],x)for x in previous))
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
	if 'vpn' in hlth:
		status = hlth['vpn']['status']
		if status == 'ok':
			color = 'good'
		elif status == 'unknown':
			color = 'warning'
		else:
			color = 'danger'
		res.append( {
			'text': f'VPN is {status}',
			'fallback': f'VPN is {status}',
			'color': color
			} )
	if 'www' in hlth:
		status = hlth['www']['status']
		if status == 'ok':
			color = 'good'
		elif status == 'unknown':
			color = 'warning'
		else:
			color = 'danger'
		res.append( {
			'text': f'Internet is {status}',
			'fallback': f'Internet is {status}',
			'color': color
			} )
	if 'wan' in hlth:
		status = hlth['wan']['status']
		if status == 'ok':
			color = 'good'
		elif status == 'unknown':
			color = 'warning'
		else:
			color = 'danger'
		res.append( {
			'text': f'Firewall is {status}',
			'fallback': f'Firewall is {status}',
			'color': color
			} )
	if 'lan' in hlth:
		status = hlth['lan']['status']
		if status == 'ok':
			color = 'good'
		elif status == 'unknown':
			color = 'warning'
		else:
			color = 'danger'
		res.append( {
			'text': f'LAN is {status}',
			'fallback': f'LAN is {status}',
			'color': color
			} )
	if 'wlan' in hlth:
		status = hlth['wlan']['status']
		if status == 'ok':
			color = 'good'
		elif status == 'unknown':
			color = 'warning'
		else:
			color = 'danger'
		res.append( {
			'text': f'WiFi is {status}',
			'fallback': f'WiFi is {status}',
			'color': color
			} )
	return res	

while True:
    new = s.health()
    res = health_to_attachments(new, previous=hlth, ignore_unknown=True)
    if res:
        data = { 'username': 'Health Status', 'text': f'Health for {site_name}', 'attachments': res }
        post(url, json=data)
    hlth = new

    new = s.alerts(args={'archived': 'false'})
    res = alert_to_attachment(new, alerts)
    if res:
        data = { 'username': 'Alerts', 'text': f'Alerts for {site_name}', 'attachments': res }
        post(url, json=data)
    alerts = new    
    sleep(10)
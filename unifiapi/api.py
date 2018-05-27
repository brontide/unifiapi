
''' Client tools for Unifi restful api '''

#
# BEGIN py2 compatibility section
#

# print function
from __future__ import print_function


# This is a hack to allow partialmethod on py2
try:
    from functools import partialmethod
except BaseException:
    # python 2 hack https://gist.github.com/carymrobbins/8940382
    from functools import partial

    class partialmethod(partial):
        def __get__(self, instance, owner):
            if instance is None:
                return self
            return partial(self.func, instance,
                           *(self.args or ()), **(self.keywords or {}))

# Make input() work the same
try:
    input = raw_input
except NameError:
    pass

# urllib
from future.standard_library import install_aliases
install_aliases()

#
# END py2 compatibility cruft
#

import requests
import logging
from getpass import getpass, getuser
import os
import sys
from urllib.parse import urlparse,quote
import time
from collections import UserList, UserDict
from json import dumps
import yaml
import json
import pkg_resources
    
def quiet():
    ''' This function turns off InsecureRequestWarnings '''
    try:
        # old vendored packages
        requests.packages.urllib3.disable_warnings() #pylint: disable=E1101
    except:
        # New way
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

def jsonKeys2int(x):
    if isinstance(x, dict):
            try:
                return {int(k):v for k,v in x.items()}
            except:
                pass
    return x

def cat_app_to_dpi(cat, app):
    ''' convert numeric category and app codes to dpi_id for
        lookup in the application list '''
    return int(cat)<<16+int(app)

def dpi_to_cat_app(dpi_id):
    ''' convert dpi_id to category and app codes '''
    return int(dpi_id)>>16, int(dpi_id)&65536

# FIXME: should be in data/
DEVICES = json.load(open(pkg_resources.resource_filename('unifiapi','unifi_devices.json')))
DPI = json.load(open(pkg_resources.resource_filename('unifiapi','unifi_dpi.json')), object_hook=jsonKeys2int)

def get_username_password(endpoint, username=None):
    # Query for interactive credentials

    # only works for ttys
    if not sys.stdin.isatty():
        logger.warning(
            "Session not ready and no interactive credentials, this will probably fail")

    if not username:
        # if no username was supplied use the logged in username
        username = getuser()
    def_username = username
    

    # Start interactive login
    username  = input(
        "Please enter credentials for Unifi {}\nUsername (CR={}): ".format(
            endpoint,
            username))

    if username == "":
        # User hit enter, use default
        username = def_username
    
    password = getpass("{} Password : ".format(username), sys.stderr)

    return username, password

def controller(profile=None, endpoint=None, username=None, password=None, verify=None):
    ''' Controller factory gived a profile or endpoint, username, password
    will return a controller object.  If profile and endpoint are both None
    the function will automatically try the default profile config '''
    if not endpoint and not profile:
        profile = 'default'

    if profile:
        # Load YAML profile details, verify and endpoint
        # should go into **kwargs.  Username and password
        # into self
        profile_config = {}
        for filename in ('unifiapi.yaml', os.path.expanduser('~/.unifiapi_yaml')):
            try:
                profile_config = yaml.safe_load(open(filename))[profile]
                logger.debug('Found config for profile %s', profile)
                break
            except:
                pass
        endpoint = profile_config['endpoint']
        if not username:
            username = profile_config.get('username', None)
        if not password:
            password = profile_config.get('password', None)
        if 'verify' in profile_config:
            verify = profile_config.get('verify', None)
        # Finished loading profile defaults
    if verify is None:
        verify = True
    
    if not username or not password:
        # If we don't have full credentials, get them
        username, password = get_username_password(endpoint, username)

    logger.debug("Attempting to login to endpoint %s with username %s and verify %s", endpoint, username, repr(verify))

    c = UnifiController(endpoint=endpoint, verify=verify)
    c.login(username, password)
    return c


class UnifiError(Exception):
    pass

class UnifiApiError(UnifiError):
    ''' Wapper around UniFi errors which attempts to pull the error from the json if possible '''

    def __init__(self, out):
        self.request_response = out
        try:
            data = out.json()
            UnifiError.__init__(self, "Error {} when connecting to url {}".format(
                data['meta']['msg'], out.url))
        except BaseException:
            UnifiError.__init__(
                self, "URL: {} status code {}".format(
                    out.url, out.status_code))

class UnifiData(UserDict):

    def __init__(self, session, call, data):

        self._client = session
        self.data = data
        if not '_id' in data:
            self._path = None
        elif 'key' in data:
            self._path = '/'.join([call, data['key'], data['_id']])
        else:
            self._path = '/'.join([call, data['_id']])

    @property
    def endpoint(self):
        return self._path

class UnifiSiteData(UnifiData):

    def to_site(self):
        try:
            return self._site #pylint: disable=E0203
        except: pass
        self._site = UnifiSite(session = self._client._s, 
                endpoint = '/'.join([self._client.endpoint, 'api/s', self.data['name']]))
        return self._site
    
    def __call__(self):
        return self.to_site()

class UnifiAutoBackupData(UnifiData):

    def download(self):
        ''' download the backup referenced by the current record
        Unifi doesn't make this easy since it's relative to the
        controller and not the site '''
        p = urlparse(self._client.endpoint)
        url = '{}://{}/dl/autobackup/{}'.format(p.scheme,p.netloc,self.data['filename'])
        r = self._client._s.get(url, stream=True)
        return r.raw

    def delete(self):
        ''' Delete the referenced backup file '''
        return self._client.c_delete_backup(self.data['filename'])

# For some responses we want to monkeypatch some of the calls to make
# them easier to use, in this case being able to convert a list of sites
# into a fisrt class site object
#

DATA_OVERRIDE = {
    'api/self/sites': UnifiSiteData,
    'cmd/backup': UnifiAutoBackupData,
}

def data_factory(endpoint):
    return DATA_OVERRIDE.get(endpoint, UnifiData)


def imatch( x, y ):
    ''' case insensitive match which folds exceptions into
    False for simplicity '''
    try:
        return x.lower() == y.lower()
    except:
        pass
    return False



class UnifiResponse(UserList):
    ''' Wrapper around Unifi api return values '''

    def __init__(self, session, call, out):
        ''' takes the Request out and breaks it down '''

        self._client = session
        self.endpoint = call
        self._out = out
        data_wrapper = data_factory(call)
        try:
            self._orig = out.json()
            self.data = [ data_wrapper(session, call, x) for x in self._orig['data'] ]
        except:
            raise

        if 'count' in self.meta and len(self.data) != int(self.meta['count']):
            logger.warning("Truncated API response")
            self._truncated = True
        else:
            self._truncated = False

        common_keys = None
        for stuff in self.data:
            if common_keys:
                common_keys &= set(stuff.keys())
            else:
                common_keys = set(stuff.keys())
        if common_keys:
            self.keys = common_keys
        else:
            self.keys = set()

        for bar in ['key', 'name', 'mac' ]:
            if bar in self.keys:
                self.values = [ x[bar] for x in self.data ]
                break

        
    def __getitem__(self, key):
        ''' Try to act as both list and dict where possible '''
        if isinstance(key, int):
            return self.data[key]
        for keying in [ 'key', 'name', 'mac' ]:
            if keying in self.keys:
                foo = self.filter_by(keying, key, unwrap=True)
                if foo: return foo
        raise KeyError("{} not found".format(key))

    @property
    def meta(self):
        return self._orig['meta']

    @property
    def is_truncated(self):
        return self._truncated

    @property
    def is_ok(self):
        return self.meta['rc'] == 'ok'

    def filter_by(self, tag, value, unwrap=False):
        ret = list(filter(lambda x: x.get(tag,'') == value, self.data))
        if not unwrap: return ret
        if not ret: return None
        if len(ret) == 1: return ret[0]
        raise Exception("Asked to unwrap more than 1 value")

    def ifilter_by(self, tag, value, unwrap=False):
        ret = list(filter(lambda x: imatch(x.get(tag,''), value), self.data))
        if not unwrap: return ret
        if not ret: return None
        if len(ret) == 1: return ret[0]
        raise Exception("Asked to unwrap more than 1 value")

    by_name = partialmethod(filter_by, 'name')
    by_iname = partialmethod(ifilter_by, 'name')
    by_type = partialmethod(filter_by, 'type')
    by_key = partialmethod(filter_by, 'key')

    
class UnifiClientBase(object):
    ''' Bare bones Unifi RESTful client designed for utter simplicity '''

    def __init__(
            self,
            session=None,
            endpoint=None,
            verify=True):

        if not session:
            self._s = requests.Session()
            self._s.headers['User-Agent'] = 'unifiapi library based on requests'
        else:
            self._s = session

        self.endpoint = endpoint.rstrip('/')
        self._s.verify = verify
        if not verify:
            quiet()

    def __repr__(self):
        return "{}: {}".format(self.__class__.__name__,self.endpoint)

    def request(
            self,
            method,
            endpoint,
            raise_on_error=True,
            args=None,
            stream=False,
            **params):
        '''
        Main function that does the heavy lifting.  This is not called direcly but
        used with the partialmethod below to determine what kind of request we are
        making
        '''
        if params and method == 'GET':
            method = 'POST'

        url = '/'.join([self.endpoint, quote(endpoint)])
        logger.debug("%s %s <- %s", method, url, repr(json)[:20])
        out = self._s.request(
            method,
            url,
            json=params,
            stream=stream,
            params=args)
        
        logger.debug("Results from %s status %i preview %s",
                     out.url, out.status_code, out.text[:20])
        if raise_on_error and out.status_code != requests.codes['ok']:
            raise UnifiApiError(out)
        try:
            ret = UnifiResponse(self, endpoint, out)
            if raise_on_error and not ret.is_ok:
                raise Exception()
        except:
            raise UnifiApiError(out)

        return ret

    # Primary calls are just wrappers around request
    get = partialmethod(request, 'GET')
    head = partialmethod(request, 'HEAD')
    post = partialmethod(request, 'POST')
    put = partialmethod(request, 'PUT')
    delete = partialmethod(request, 'DELETE')



class UnifiController(UnifiClientBase):

    status = partialmethod(UnifiClientBase.request, 'GET', 'status')
    admins = partialmethod(UnifiClientBase.request, 'GET', 'api/stat/admin')
    logout = partialmethod(UnifiClientBase.request, 'GET', 'api/logout')
    _sites = partialmethod(UnifiClientBase.request, 'GET', 'api/self/sites')

    def __init__(self, *args, **kwargs):

        UnifiClientBase.__init__(self, *args, **kwargs)
        status = self.status()
        self.version = status.meta['server_version']

    def login(self, username=None, password=None, remember=True):
        ret =  self.post('api/login', username=username, password=password, remember=remember)
        self.sites = self._sites()
        return ret
    
class UnifiSite(UnifiClientBase): 

    def __init__(self,*args, **kwargs):
        UnifiClientBase.__init__(self, *args, **kwargs)
        self.cache = {}
        self.cache['ccode']     = self.ccodes()
        self.cache['channels']  = self.channels()
        self.cache['clients']   = self.clients()
        

    def _api_cmd(self, mgr, command, _req_params='', **params):
        for param in _req_params:
            if param not in params:
                raise ValueError("{mgr}.{command} requires paramater {param}".format(**locals()))
        params['cmd'] = command
        return self.post('/'.join(['cmd',mgr]), **params)

    def mac_by_type(self, unifi_type):
        return [ x['mac'] for x in self.devices_basic().by_type(unifi_type) ]

    def list_by_type(self, unifi_type):
        return self.devices(macs=self.mac_by_type(unifi_type))

    # Restful commands
    alerts          = partialmethod(UnifiClientBase.request, 'GET', 'rest/alarm')
    events          = partialmethod(UnifiClientBase.request, 'GET', 'rest/event')
    devices_basic   = partialmethod(UnifiClientBase.request, 'GET', 'stat/device-basic')
    devices         = partialmethod(UnifiClientBase.request, 'GET', 'stat/device')
    ccodes          = partialmethod(UnifiClientBase.request, 'GET', 'stat/ccode')
    channels        = partialmethod(UnifiClientBase.request, 'GET', 'stat/current-channel')
    health          = partialmethod(UnifiClientBase.request, 'GET', 'stat/health')
    active_clients  = partialmethod(UnifiClientBase.request, 'GET', 'stat/sta')
    clients         = partialmethod(UnifiClientBase.request, 'GET', 'rest/user')
    sysinfo         = partialmethod(UnifiClientBase.request, 'GET', 'stat/sysinfo')
    this_user       = partialmethod(UnifiClientBase.request, 'GET', 'self')
    settings        = partialmethod(UnifiClientBase.request, 'GET', 'rest/setting')
    routing         = partialmethod(UnifiClientBase.request, 'GET', 'rest/routing')
    firewallrules   = partialmethod(UnifiClientBase.request, 'GET', 'rest/firewallrule')
    firewallgroups  = partialmethod(UnifiClientBase.request, 'GET', 'rest/firewallgroup')
    tags            = partialmethod(UnifiClientBase.request, 'GET', 'rest/tag')
    neighbors       = partialmethod(UnifiClientBase.request, 'GET', 'stat/rogueap')
    dpi             = partialmethod(UnifiClientBase.request, 'GET', 'stat/dpi')
    dynamicdns      = partialmethod(UnifiClientBase.request, 'GET', 'stat/dynamicdns')
    portprofiles    = partialmethod(UnifiClientBase.request, 'GET', 'rest/portconf')
    spectrumscan    = partialmethod(UnifiClientBase.request, 'GET', 'stat/spectrumscan')
    radiusprofiles  = partialmethod(UnifiClientBase.request, 'GET', 'rest/radiusprofile')
    account         = partialmethod(UnifiClientBase.request, 'GET', 'rest/account')

    c_archive_events      = partialmethod(_api_cmd, 'evtmgr', 'archive-all-alarms')
    c_create_site         = partialmethod(_api_cmd, 'sitemgr', 'add-site', _req_params=['desc'])
    c_delete_site         = partialmethod(_api_cmd, 'sitemgr', 'delete-site', _req_params=['name'])
    c_update_site         = partialmethod(_api_cmd, 'sitemgr', 'update-site', _req_params=['desc'])
    c_delete_device       = partialmethod(_api_cmd, 'sitemgr', 'delete-device', _req_params=['mac'])
    c_move_device         = partialmethod(_api_cmd, 'sitemgr', 'move-device', _req_params=['mac', 'site_id'])
    c_block_client        = partialmethod(_api_cmd, 'stamgr', 'block-sta', _req_params=['mac']) 
    c_unblock_client      = partialmethod(_api_cmd, 'stamgr', 'unblock-sta', _req_params=['mac']) 
    c_disconnect_client   = partialmethod(_api_cmd, 'stamgr', 'kick-sta', _req_params=['mac']) 
    c_reboot              = partialmethod(_api_cmd, 'devmgr', 'reboot', _req_params=['mac']) 
    c_poe_power_cycle     = partialmethod(_api_cmd, 'devmgr', 'power-cycle', _req_params=['mac', 'port_idx']) 
    c_adopt               = partialmethod(_api_cmd, 'devmgr', 'adopt', _req_params=['mac']) 
    c_speedtest           = partialmethod(_api_cmd, 'devmgr', 'speedtest') 
    c_speedtest_status    = partialmethod(_api_cmd, 'devmgr', 'speedtest-status') 
    c_set_locate          = partialmethod(_api_cmd, 'devmgr', 'set-locate', _req_params=['mac']) 
    c_unset_locate        = partialmethod(_api_cmd, 'devmgr', 'unset-locate', _req_params=['mac']) 
    c_upgrade             = partialmethod(_api_cmd, 'devmgr', 'upgrade', _req_params=['mac']) 
    c_upgrade_external    = partialmethod(_api_cmd, 'devmgr', 'upgrade-external', _req_params=['mac', 'url']) 
    c_spectrum_scan       = partialmethod(_api_cmd, 'devmgr', 'spectrum-scan', _req_params=['mac']) 
    c_backups             = partialmethod(_api_cmd, 'backup', 'list-backups')
    c_delete_backup       = partialmethod(_api_cmd, 'backup', 'delete-backup', _req_params=['filename'])
    c_make_backup         = partialmethod(_api_cmd, 'system', 'backup')


''' A little python magic to automatically add device_macs and list_device for all known device 
types into the UnifiSite object '''
for dev_id in set(( x['type'] for x in DEVICES.values())):
    setattr(UnifiSite, "{}_macs".format(dev_id), partialmethod(UnifiSite.mac_by_type, dev_id) )
    setattr(UnifiSite, "list_{}".format(dev_id), partialmethod(UnifiSite.list_by_type, dev_id) )





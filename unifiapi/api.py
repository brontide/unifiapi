
''' Client tools for Isilon restful api '''

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
import sys
from http.cookiejar import LWPCookieJar as fcj
import os
from functools import partial
from datetime import datetime
from urllib.parse import urlparse,quote
import time
from tarfile import filemode
from collections import UserList, UserDict
from copy import deepcopy
from json import dumps
from difflib import Differ
import yaml
import json
import pkg_resources

# FIXME: should be in data/
DEVICES = json.load(open(pkg_resources.resource_filename('unifiapi','unifi_devices.json')))
DPI = json.load(open(pkg_resources.resource_filename('unifiapi','unifi_dpi.json')))
    
def multi_filter(input_dict, list_of_items=None, notfound_error=False):
    ret = dict()
    if notfound_error:
        for item in list_of_items:
            ret[item] = input_dict[item]
    else:
        for item in list_of_items:
            if item in input_dict:
                ret[item] = input_dict[item]
    return ret

try:
    quiet = requests.packages.urllib3.disable_warnings
except:
    def quiet():
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

KNOWN_GOOD_API_VERSIONS = [ 
        '5.7.23',
        ]

WARNED_API = []

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
        self.data = deepcopy(data)
        self.orig = deepcopy(data)
        if not '_id' in data:
            self._path = None
        elif 'key' in data:
            self._path = '/'.join([call, data['key'], data['_id']])
        else:
            self._path = '/'.join([call, data['_id']])

    @property
    def endpoint(self):
        return self._path

    def diff(self):
        origs = dumps(self.orig, sort_keys=True, indent=4, separators=(',', ': '))
        datas = dumps(self.data, sort_keys=True, indent=4, separators=(',', ': '))
        d = Differ()
        return d.compare(origs,datas)

class UnifiSiteData(UnifiData):

    def to_site(self):
        try:
            return self._site
        except: pass
        self._site = UnifiSite(session = self._client._s, 
                endpoint = '/'.join([self._client.endpoint, 'api/s', self.data['name']]))
        return self._site

def imatch( x, y ):
    try:
        return x.lower() == y.lower()
    except:
        pass
    return False

class UnifiResponse(UserList):
    ''' Wrapper around Unifi api return values '''

    def __init__(self, session, call, out, data_wrapper=UnifiData):
        ''' takes the Request out and breaks it down '''

        self._client = session
        self.endpoint = call
        self._out = out
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
        if isinstance(key, int):
            return self.data[key]
        for keying in [ 'key', 'name', 'mac' ]:
            if keying in self.keys:
                foo = self.filter_by(keying, key, unwrap=True)
                if foo: return foo
        raise KeyError("{} not found".format(key))

    def __repr__(self):
        return "Unifi Response {}: data {} meta {}".format(self.endpoint, len(self.data), self.meta)

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
            self._cookiejar_path = os.path.expanduser('~/.unifiapi_cookiejar')
            self._s = requests.Session()
            self._s.headers['User-Agent'] = 'unifiapi library based on requests'
            self._s.cookies = fcj()
            try:
                self._s.cookies.load(
                    self._cookiejar_path,
                    ignore_discard=True,
                    ignore_expires=True)
            except BaseException:
                logger.warning(
                    "Could not load cookies from %s",
                    self._cookiejar_path)
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
            data_wrapper=UnifiData,
            json=None,
            stream=False,
            **params):
        '''
        Main function that does the heavy lifting.  This is not called direcly but
        used with the partialmethod below to determine what kind of request we are
        making
        '''
        if json and method == 'GET':
            method = 'POST'

        url = '/'.join([self.endpoint, quote(endpoint)])
        logger.debug("%s %s <- %s", method, url, repr(json)[:20])
        out = self._s.request(
            method,
            url,
            json=json,
            stream=stream,
            params=params)
        
        logger.debug("Results from %s status %i preview %s",
                     out.url, out.status_code, out.text[:20])
        if raise_on_error and out.status_code != requests.codes['ok']:
            raise UnifiApiError(out)
        try:
            ret = UnifiResponse(self, endpoint, out, data_wrapper)
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

    def __init__(self, *args, profile=None, username=None, password=None, **kwargs):
        if not kwargs.get('endpoint', None):
            # Presume if no endpoint set that we are
            # loading the default profile
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
                except BaseException as e:
                    pass
            kwargs['endpoint'] = profile_config['endpoint']
            self.username = profile_config.get('username', None)
            self.password = profile_config.get('password', None)

        if username: self.username = username
        if password: self.password = password

        UnifiClientBase.__init__(self, *args, **kwargs)

        if self.username and self.password:
            self.login(quiet=True)

    def _test_connection(self):
        try:
            out = self.get('status', raise_on_error=False)
            self.server_version = out.meta['server_version']
            logger.debug('Found server version %s at %s', self.server_version, self.endpoint)
            if self.server_version not in KNOWN_GOOD_API_VERSIONS and  self.server_version not in WARNED_API:
                logger.warning("API version %s has not been tested", self.server_version)
                WARNED_API.append(self.server_version)
            out = self.get('api/self',  raise_on_error=False)
            name = out[0]['name']
            if not self.username:
                self.username = name
            if name == self.username:
                self.authenticated = True
        except:
            #raise
            self.authenticated = False
    
    def login(self, username=None, password=None, quiet=False):
        if username: self.username = username
        if password: self.password = password
        if not self.username and not self.password and not quiet:
            self.auth()
        login_auth = {'username': self.username, 'password': self.password, 'remember': True}
        out = self.post('api/login', json=login_auth)
        self._test_connection()
        if self.authenticated:
            self._s.cookies.save(self._cookiejar_path,                                                  
                                 ignore_discard=True,                                                   
                                 ignore_expires=True)                       
            self.sites = self.get('api/self/sites',data_wrapper=UnifiSiteData)
        else:
            logger.warning("Login failure")

    def logout(self):
        ''' logout of a valid session / destroy cookie and 
            authentication tokens '''
        out = self.get('api/logout', x_add_site=False)
        self._s.cookies.save(self._cookiejar_path,                                                  
                             ignore_discard=True,                                                   
                             ignore_expires=True)                       

    def auth(self):
        # Query for interactive credentials

        # only works for ttys
        if not sys.stdin.isatty():
            logger.warning(
                "Session not ready and no interactive credentials, this will probably fail")

        # Start interactive login
        print(
            "Please enter credentials for Unifi {}\nUsername (CR={}): ".format(
                self.endpoint,
                getuser()),
            file=sys.stderr,
            end='')
        username = input()
        if username == "":
            username = getuser()
        password = getpass("{} Password : ".format(username), sys.stderr)

        self.username = username
        self.password = password

    admins = partialmethod(UnifiClientBase.request, 'GET', 'api/stat/admin')


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
        return self.post('/'.join(['cmd',mgr]), json=params)

    def mac_by_type(self, unifi_type):
        return [ x['mac'] for x in self.devices_basic().by_type(unifi_type) ]

    def list_by_type(self, unifi_type):
        return self.devices(json={'macs': self.mac_by_type(unifi_type)})

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





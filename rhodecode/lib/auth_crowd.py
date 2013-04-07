import urllib2
import base64
import json
import formencode
import rhodecode.lib.auth
from rhodecode.model import validators as v
import logging
log = logging.getLogger(__name__)

from rhodecode.model.db import RhodeCodeSetting

class CrowdServer():
    def __init__(self, *args, **kwargs):
        """Create a new CrowdServer object that points to IP/Address 'host',
        on the given port, and using the given method (https/http). user and
        passwd can be set here or with set_credentials. If unspecified,
        "version" defaults to "latest".

        example:
            cserver = CrowdServer(host="127.0.0.1",
                                  port="8095",
                                  user="some_app",
                                  passwd="some_passwd",
                                  version="1")
        """
        if not "port" in kwargs:
            kwargs["port"] = "8095"
        self._logger = kwargs.get("logger", logging.getLogger(__name__))
        self._uri = "%s://%s:%s/crowd" % (kwargs.get("method", "http"),
                                    kwargs.get("host", "127.0.0.1"),
                                    kwargs.get("port", "8095"))
        self.set_credentials(kwargs.get("user", ""),
                             kwargs.get("passwd", ""))
        self._version = kwargs.get("version", "latest")
        self._url_list = None
        self._appname = "crowd"

    def set_credentials(self, user, passwd):
        self.user = user
        self.passwd = passwd
        self._make_opener()

    def _make_opener(self):
        mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, self._uri, self.user, self.passwd)
        handler = urllib2.HTTPBasicAuthHandler(mgr)
        self.opener = urllib2.build_opener(handler)

    def _request(self, url, body=None, headers=None,
                 method=None, noformat=False,
                 empty_response_ok=False):
        _headers = {"Content-type": "application/json",
                    "Accept": "application/json"}
        if self.user and self.passwd:
            authstring = base64.b64encode("%s:%s" % (self.user, self.passwd))
            _headers["Authorization"] = "Basic %s" % authstring
        if headers:
            _headers.update(headers)
        log.debug("Sent crowd: \n{}".format(json.dumps({"url": url, "body": body, "headers": _headers}, indent=4, sort_keys=True)))
        request = urllib2.Request(url, body, _headers)
        if method:
            request.get_method = lambda: method
        #print "="*32
        #print "%s %s" % (request.get_method(), url)
        #print body
        #print headers
        #print "="*32
        global msg
        msg = ""
        try:
            rdoc = self.opener.open(request)
            msg = "".join(rdoc.readlines())
            if not msg and empty_response_ok:
                rval = {}
                rval["status"] = True
                rval["error"] = "Response body was empty"
            elif not noformat:
                rval = json.loads(msg)
                rval["status"] = True
            else:
                rval = "".join(rdoc.readlines())
        except Exception, e:
            if not noformat:
                rval = {"status": False,
                        "body": body,
                        "error": str(e) + "\n" + msg}
            else:
                rval = None
        return rval

    def user_auth(self, username, password):
        """Authenticate a user against crowd. Returns brief information about
        the user."""
        url = ("{}/rest/usermanagement/{}/authentication?username={}"
               "".format(self._uri, self._version, username))
        body = json.dumps({"value": password})
        return self._request(url, body)

    def user_groups(self, username):
        """Retrieve a list of groups to which this user belongs."""
        url = ("{}/rest/usermanagement/{}/user/group/nested?username={}"
               "".format(self._uri, self._version, username))
        return self._request(url)

class RhodeCodeAuthPlugin(rhodecode.lib.auth.RhodeCodeAuthPlugin):
    def name(self):
        return "crowd"

    def settings(self):
        """
        Return a dictionary of the form:
        {
            "OPTION_NAME": {
                "type": "[bool|password|string|int|select|multiselect]",
                ["values": ["opt1", "opt2", ...]]
                "validator": "expr"
                "description": "A short description of the option" [,
                "default": Default Value],
                ["formname": "Friendly Name for Forms"]
            } [, ...]
        }

        This is used to interrogate the authentication plugin as to what
        settings it expects to be present and configured.

        'type' is a shorthand notation for what kind of value this option is.
        This is primarily used by the auth web form to control how the option
        is configured.
                bool : checkbox
                password : password input box
                string : input box
                select : single select dropdown
                multiselect : multiple select choice dialog, returned to you
                    as a single comma delimited string

        'validator' is an instantiated form field validator object, ala
        formencode. Feel free to use the rhodecode validators here as well.
        """

        settings = [
            {
                "name": "host",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "The FQDN or IP of the Atlassian CROWD Server",
                "default": "127.0.0.1",
                "formname": "Host"
                },
           {
                "name": "port",
                "validator": v.Number(strip=True),
                "type": "int",
                "description": "The Port in use by the Atlassian CROWD Server",
                "default": 8095,
                "formname": "Port"
                },
            {
                "name": "app_name",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "The Application Name to authenticate to CROWD",
                "default": "",
                "formname": "Application Name"
                },
            {
                "name": "app_password",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "The password to authenticate to CROWD",
                "default": "",
                "formname": "Application Password"
                },
            {
                "name": "admin_groups",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "A comma separated list of group names that identify users as RhodeCode Administrators",
                "formname": "Admin Groups"
                }
            ]
        return settings

    def use_fake_password(self):
        return True

    def auth(self, userobj, user, passwd, settings):
        """
        Given a user name, a plaintext password, and a settings object (containing all the keys
        needed as listed in settings() ), authenticate this user's login attempt.

        Return None on failure. On success, return a dictionary of the form:

        {
            "name": "short user name",
            "firstname": "first name",
            "lastname": "last name",
            "email": "email address",
            "groups": ["list", "of", "groups"],
            "extern_name": "name in external source of record",
            "admin": True|False
        }
        """
        log.debug("Crowd settings: \n{}".format(json.dumps(settings, indent=4, sort_keys=True)))
        server = CrowdServer(**settings)
        server.set_credentials(settings["app_name"], settings["app_password"])
        crowdUser = server.user_auth(user, passwd)
        log.debug("Crowd returned: \n{}".format(json.dumps(crowdUser, indent=4, sort_keys=True)))
        if not crowdUser["status"]:
            return None

        res = server.user_groups(crowdUser["name"])
        log.debug("Crowd groups: \n{}".format(json.dumps(res, indent=4, sort_keys=True)))
        crowdUser["groups"] = [x["name"] for x in res["groups"]]

        rcuser = {}
        rcuser["firstname"] = crowdUser["first-name"]
        rcuser["lastname"] = crowdUser["last-name"]
        rcuser["email"] = crowdUser["email"]
        rcuser["active"] = True
        rcuser["extern_name"] = crowdUser["name"]
        rcuser["groups"] = crowdUser["groups"]
        rcuser["admin"] = False
        for group in settings["admin_groups"]:
            if group in rcuser["groups"]:
                rcuser["admin"] = True

        log.debug("Final crowd user object: \n{}".format(json.dumps(rcuser, indent=4, sort_keys=True)))
        return rcuser

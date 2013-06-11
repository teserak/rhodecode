"""
Authentication modules
"""
import logging
import traceback

from rhodecode.lib.compat import importlib
from rhodecode.lib.utils2 import str2bool
from rhodecode.lib.compat import formatted_json
from rhodecode.lib.auth import PasswordGenerator
from rhodecode.model.user import UserModel
from rhodecode.model.db import RhodeCodeSetting, User
from rhodecode.model.meta import Session

log = logging.getLogger(__name__)


class RhodeCodeAuthPluginBase(object):
    auth_func_attrs = {
        "username": "unique username",
        "firstname": "first name",
        "lastname": "last name",
        "email": "email address",
        "groups": '["list", "of", "groups"]',
        "extern_name": "name in external source of record",
        "admin": 'True|False defines if user should be RhodeCode super admin',
        "active": 'True|False defines active state of user internally for RhodeCode',
        "active_from_extern": "True|False\None, active state from the external auth, "
                              "None means use definition from RhodeCode extern_type active value"
    }

    @property
    def validators(self):
        """
        Exposes RhodeCode validators modules
        """
        from rhodecode.model import validators as v
        # this is a hack to overcome issues with pylons threadlocals and
        # translator object _() not beein registered properly.
        class ProxyGet(object):
            def __getattribute__(self, name):
                return getattr(v, name)
        return ProxyGet()

    def name(self):
        """
        Returns the name of this authentication plugin.

        :returns: string
        """
        raise NotImplementedError("Not implemented in base class")

    def settings(self):
        """
        Return a list of the form:
        [
            {
                "name": "OPTION_NAME",
                "type": "[bool|password|string|int|select]",
                ["values": ["opt1", "opt2", ...]]
                "validator": "expr"
                "description": "A short description of the option" [,
                "default": Default Value],
                ["formname": "Friendly Name for Forms"]
            } [, ...]
        ]

        This is used to interrogate the authentication plugin as to what
        settings it expects to be present and configured.

        'type' is a shorthand notation for what kind of value this option is.
        This is primarily used by the auth web form to control how the option
        is configured.
                bool : checkbox
                password : password input box
                string : input box
                select : single select dropdown

        'validator' is an instantiated form field validator object, ala
        formencode. Feel free to use the rhodecode validators here as well.
        """
        raise NotImplementedError("Not implemented in base class")

    def plugin_settings(self):
        """
        This method is called by the authentication framework, not the .settings()
        method. This method adds a few default settings (e.g., "active"), so that
        plugin authors don't have to maintain a bunch of boilerplate.

        OVERRIDING THIS METHOD WILL CAUSE YOUR PLUGIN TO FAIL.
        """

        rcsettings = self.settings()
        rcsettings.insert(0,
            {
                "name": "enabled",
                "validator": self.validators.StringBoolean(if_missing=False),
                "type": "bool",
                "description": "Enable or Disable this Authentication Plugin",
                "formname": "Enabled"
            }
        )
        return rcsettings

    def user_activation_state(self):
        """
        Defines user activation state when creating new users

        :returns: boolean
        """
        raise NotImplementedError("Not implemented in base class")

    def auth(self, userobj, username, passwd, settings, **kwargs):
        """
        Given a user object (which may be null), username, a plaintext password,
        and a settings object (containing all the keys needed as listed in settings()),
        authenticate this user's login attempt.

        Return None on failure. On success, return a dictionary of the form:

            see: RhodeCodeAuthPluginBase.auth_func_attrs
        This is later validated for correctness
        """
        raise NotImplementedError("not implemented in base class")

    def _authenticate(self, userobj, username, passwd, settings, **kwargs):
        """
        Wrapper to call self.auth() that validates call on it

        :param userobj: userobj
        :param username: username
        :param passwd: plaintext password
        :param settings: plugin settings
        """
        auth = self.auth(userobj, username, passwd, settings, **kwargs)
        if auth:
            return self._validate_auth_return(auth)
        return auth

    def _validate_auth_return(self, ret):
        if not isinstance(ret, dict):
            raise Exception('returned value from auth must be a dict')
        for k in self.auth_func_attrs:
            if k not in ret:
                raise Exception('Missing %s attribute from returned data' % k)
        return ret


class RhodeCodeExternalAuthPlugin(RhodeCodeAuthPluginBase):
    def use_fake_password(self):
        """
        Return a boolean that indicates whether or not we should set the user's
        password to a random value when it is authenticated by this plugin.
        If your plugin provides authentication, then you will generally want this.

        :returns: boolean
        """
        raise NotImplementedError("Not implemented in base class")

    def _authenticate(self, userobj, username, passwd, settings, **kwargs):
        auth = super(RhodeCodeExternalAuthPlugin, self)._authenticate(
            userobj, username, passwd, settings, **kwargs)
        if auth:
            # if user is not active from our extern type we should fail to authe
            # this can prevent from creating users in RhodeCode when using
            # external authentication, but if it's inactive user we shouldn't
            # create that user anyway
            if auth['active_from_extern'] is False:
                log.warning("User %s authenticated against %s, but is inactive"
                            % (username, self.__module__))
                return None

            if self.use_fake_password():
                # Randomize the PW because we don't need it, but don't want
                # them blank either
                passwd = PasswordGenerator().gen_password(length=8)

            UserModel().create_or_update(
                username=auth['username'],
                password=passwd,
                email=auth["email"],
                firstname=auth["firstname"],
                lastname=auth["lastname"],
                active=auth["active"],
                admin=auth["admin"],
                extern_name=auth["extern_name"],
                extern_type=self.name()
            )
            Session().commit()
        return auth


def loadplugin(plugin):
    """
    Load and return the authentication plugin in the module named by plugin
    (e.g., plugin='rhodecode.lib.auth_modules.auth_rhodecode'). Returns an
    instantiated RhodeCodeAuthPluginBase subclass on success, raises exceptions
    on failure.

    raises:
        AttributeError -- no RhodeCodeAuthPlugin class in the module
        TypeError -- if the RhodeCodeAuthPlugin is not a subclass of ours RhodeCodeAuthPluginBase
        ImportError -- if we couldn't import the plugin at all
    """
    log.debug("Importing %s" % plugin)
    PLUGIN_CLASS_NAME = "RhodeCodeAuthPlugin"
    try:
        module = importlib.import_module(plugin)
    except (ImportError, TypeError):
        log.error(traceback.format_exc())
        # TODO: make this more error prone, if by some accident we screw up
        # the plugin name, the crash is preatty bad and hard to recover
        raise

    log.debug("Loaded auth plugin from %s (module:%s, file:%s)"
              % (plugin, module.__name__, module.__file__))

    pluginclass = getattr(module, PLUGIN_CLASS_NAME)
    if not issubclass(pluginclass, RhodeCodeAuthPluginBase):
        raise TypeError("Authentication class %s.RhodeCodeAuthPlugin is not "
                        "a subclass of %s" % (plugin, RhodeCodeAuthPluginBase))
    plugin = pluginclass()
    if plugin.plugin_settings.im_func != RhodeCodeAuthPluginBase.plugin_settings.im_func:
        raise TypeError("Authentication class %s.RhodeCodeAuthPluginBase "
                        "has overriden the plugin_settings method, which is "
                        "forbidden." % plugin)
    return plugin


def authenticate(username, password, environ=None):
    """
    Authentication function used for access control,
    It tries to authenticate based on enabled authentication modules.

    :param username: username
    :param password: password
    :returns: None if auth failed, plugin_suer dict if auth is correct
    """

    user = User.get_by_username(username)
    if not user:
        user = User.get_by_username(username, case_insensitive=True)

    auth_plugins = RhodeCodeSetting.get_auth_plugins()

    for module in auth_plugins:
        try:
            plugin = loadplugin(module)
        except (ImportError, AttributeError, TypeError), e:
            raise ImportError('Failed to load authentication module %s : %s'
                              % (module, str(e)))

        plugin_name = plugin.name()
        if user and user.extern_type and user.extern_type != plugin_name:
            log.debug('User %s should authenticate using %s this is %s, skipping'
                      % (user, user.extern_type, plugin_name))
            continue

        # load plugin settings from RhodeCode database
        plugin_settings = {}
        for v in plugin.plugin_settings():
            conf_key = "auth_%s_%s" % (plugin_name, v["name"])
            setting = RhodeCodeSetting.get_by_name(conf_key)
            plugin_settings[v["name"]] = setting.app_settings_value if setting else None
        log.debug(formatted_json(plugin_settings))

        if not str2bool(plugin_settings["enabled"]):
            log.info("Authentication plugin %s is disabled, skipping for %s"
                     % (module, username))
            continue

        log.info('Authenticating user using %s plugin' % plugin.__module__)
        plugin_user = plugin._authenticate(user, username, password,
                                           plugin_settings,
                                           environ=environ or {})
        if plugin_user:
            return plugin_user

        # we failed to Auth because .auth() method didn't return proper the user
        log.warning("User %s failed to authenticate against %s"
                    % (username, plugin.__module__))
    return None

from rhodecode import __platform__, is_windows, is_unix
import rhodecode.lib.auth

import json

import logging
log = logging.getLogger(__name__)

class RhodeCodeAuthPlugin(rhodecode.lib.auth.RhodeCodeAuthPlugin):
    def __init__(self):
        pass

    def name(self):
        return "rhodecode"

    def settings(self):
        return []

    def use_fake_password(self):
        return False

    def auth(self, userobj, username, password, settings):
        if (not userobj) or ((userobj.extern_type) and (userobj.extern_type != "rhodecode")):
            return False

        user_attrs = {
            "firstname": userobj.firstname,
            "lastname": userobj.lastname,
            "groups": [],
            "email": userobj.email,
            "admin": userobj.admin,
            "active": userobj.active,
            "extern_name": ""
            }

        log.debug(json.dumps(user_attrs, indent=4, sort_keys=True))
        log.info('Authenticating user using RhodeCode account')
        if userobj.active:
            if userobj.username == 'default' and userobj.active:
                log.info('user %s authenticated correctly as anonymous user' %
                         username)
                return user_attrs

            elif userobj.username == username and rhodecode.lib.auth.RhodeCodeCrypto.hash_check(password,
                                                                                                userobj.password):
                log.info('user %s authenticated correctly' % username)
                return user_attrs
            log.error("user %s had a bad password" % username)
        else:
            log.warning('user %s tried auth but is disabled' % username)
        return False

# -*- coding: utf-8 -*-
"""
    rhodecode.lib.auth_modules.auth_rhodecode
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    RhodeCode authentication plugin for built in internal auth

    :created_on: Created on Nov 17, 2012
    :author: marcink
    :copyright: (C) 2010-2012 Marcin Kuzminski <marcin@python-works.com>
    :license: GPLv3, see COPYING for more details.
"""
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
from rhodecode.lib import auth
from rhodecode.lib import auth_modules
from rhodecode.lib.compat import json, formatted_json
from rhodecode.model.db import User


log = logging.getLogger(__name__)


class RhodeCodeAuthPlugin(auth_modules.RhodeCodeAuthPluginBase):
    def __init__(self):
        pass

    def name(self):
        return "rhodecode"

    def settings(self):
        return []

    def use_fake_password(self):
        return False

    @classmethod
    def user_activation_state(cls):
        def_user_perms = User.get_by_username('default').AuthUser.permissions['global']
        return 'hg.register.auto_activate' in def_user_perms

    def auth(self, userobj, username, password, settings, **kwargs):
        if not userobj:
            log.debug('userobj was:%s skipping' % (userobj, ))
            return None
        if userobj.extern_type != self.name():
            log.warn("userobj:%s extern_type mismatch got:`%s` expected:`%s`"
                     % (userobj, userobj.extern_type, self.name()))
            return None

        user_attrs = {
            "username": userobj.username,
            "firstname": userobj.firstname,
            "lastname": userobj.lastname,
            "groups": [],
            "email": userobj.email,
            "admin": userobj.admin,
            "active": userobj.active,
            "active_from_extern": userobj.active,
            "extern_name": userobj.user_id
        }

        log.debug(formatted_json(user_attrs))
        if userobj.active:
            password_match = auth.RhodeCodeCrypto.hash_check(password, userobj.password)
            if userobj.username == User.DEFAULT_USER and userobj.active:
                log.info('user %s authenticated correctly as anonymous user' %
                         username)
                return user_attrs

            elif userobj.username == username and password_match:
                log.info('user %s authenticated correctly' % user_attrs['username'])
                return user_attrs
            log.error("user %s had a bad password" % username)
        else:
            log.warning('user %s tried auth but is disabled' % username)
        return None

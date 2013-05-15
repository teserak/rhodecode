# -*- coding: utf-8 -*-
"""
    rhodecode.lib.auth_modules.auth_container
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    RhodeCode container based authentication plugin

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
from rhodecode.lib import auth_modules
from rhodecode.lib.utils2 import str2bool
from rhodecode.lib.compat import json, formatted_json
from rhodecode.model.db import User

log = logging.getLogger(__name__)


class RhodeCodeAuthPlugin(auth_modules.RhodeCodeAuthPluginBase):
    def __init__(self):
        pass

    def name(self):
        return "container"

    def settings(self):

        settings = [
            {
                "name": "header",
                "validator": self.validators.UnicodeString(strip=True),
                "type": "string",
                "description": "Header to extract the user from",
                "default": "REMOTE_USER",
                "formname": "Header"
            },
            {
                "name": "fallback_header",
                "validator": self.validators.UnicodeString(strip=True),
                "type": "string",
                "description": "Header to extract the user from when main one fails",
                "default": "HTTP_X_FORWARDED_USER",
                "formname": "Fallback header"
            },
            {
                "name": "clean_username",
                "validator": self.validators.UnicodeString(strip=True),
                "type": "bool",
                "description": "Perform cleaning of user, if passed user has @ in username"
                               "then first part before @ is taken. "
                               "If there's \\\\ in the username only the part after \\\\ is taken",
                "default": "True",
                "formname": "Clean username"
            },
        ]
        return settings

    def use_fake_password(self):
        return True

    def user_activation_state(self):
        def_user_perms = User.get_by_username('default').AuthUser.permissions['global']
        return 'hg.extern_activate.auto' in def_user_perms

    def _clean_username(self, username):
        # Removing realm and domain from username
        username = username.partition('@')[0]
        username = username.rpartition('\\')[2]
        return username

    def auth(self, userobj, username, password, settings, **kwargs):
        """
        Get's the container_auth username (or email). It tries to get username
        from REMOTE_USER if container_auth_enabled is enabled, if that fails
        it tries to get username from HTTP_X_FORWARDED_USER if proxypass_auth_enabled
        is enabled. clean_username extracts the username from this data if it's
        having @ in it.

        :param environ:
        :param config:
        :param clean_username:
        """
        username = None
        environ = kwargs.get('environ', {})
        if not environ:
            log.debug('got empty environ:' % environ)
        if settings.get('header'):
            header = settings.get('header')
            username = environ.get(header)
            log.debug('extracted %s:%s' % (header, username))

        # fallback mode
        if not username and settings.get('fallback_header'):
            header = settings.get('fallback_header')
            username = environ.get(header)
            log.debug('extracted %s:%s' % (header, username))

        if username and str2bool(settings.get('clean_username')):
            log.debug('Received username %s from container' % username)
            username = self._clean_username(username)
            log.debug('New cleanup user is: %s' % username)

        if not username:
            return None

        user_attrs = {
            'username': username,
            'firstname': username,
            'lastname': '',
            'groups': [],
            'email': '',
            'admin': False,
            'active': True,
            'active_from_extern': True,
            'extern_name': 'container'
        }

        log.info('user %s authenticated correctly' % user_attrs['username'])
        return user_attrs

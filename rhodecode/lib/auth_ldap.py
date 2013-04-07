# -*- coding: utf-8 -*-
"""
    rhodecode.controllers.changelog
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    RhodeCode authentication library for LDAP

    :created_on: Created on Nov 17, 2010
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
import traceback

from rhodecode.lib.utils2 import str2bool, safe_unicode
from rhodecode.lib.exceptions import LdapConnectionError, LdapUsernameError, \
    LdapPasswordError, LdapImportError
from rhodecode.lib.utils2 import safe_str
from rhodecode.lib.exceptions import LdapPasswordError, LdapUsernameError,\
    LdapImportError
from rhodecode.model import validators as v
import rhodecode.lib.auth
import formencode

log = logging.getLogger(__name__)


try:
    import ldap
except ImportError:
    # means that python-ldap is not installed
    ldap = None


class AuthLdap(object):

    def __init__(self, server, base_dn, port=389, bind_dn='', bind_pass='',
                 tls_kind='PLAIN', tls_reqcert='DEMAND', ldap_version=3,
                 ldap_filter='(&(objectClass=user)(!(objectClass=computer)))',
                 search_scope='SUBTREE', attr_login='uid'):
        if ldap is None:
            raise LdapImportError

        self.ldap_version = ldap_version
        ldap_server_type = 'ldap'

        self.TLS_KIND = tls_kind

        if self.TLS_KIND == 'LDAPS':
            port = port or 689
            ldap_server_type = ldap_server_type + 's'

        OPT_X_TLS_DEMAND = 2
        self.TLS_REQCERT = getattr(ldap, 'OPT_X_TLS_%s' % tls_reqcert,
                                   OPT_X_TLS_DEMAND)
        # split server into list
        self.LDAP_SERVER_ADDRESS = server.split(',')
        self.LDAP_SERVER_PORT = port

        # USE FOR READ ONLY BIND TO LDAP SERVER
        self.LDAP_BIND_DN = safe_str(bind_dn)
        self.LDAP_BIND_PASS = safe_str(bind_pass)
        _LDAP_SERVERS = []
        for host in self.LDAP_SERVER_ADDRESS:
            _LDAP_SERVERS.append("%s://%s:%s" % (ldap_server_type,
                                                     host.replace(' ', ''),
                                                     self.LDAP_SERVER_PORT))
        self.LDAP_SERVER = str(', '.join(s for s in _LDAP_SERVERS))
        self.BASE_DN = safe_str(base_dn)
        self.LDAP_FILTER = safe_str(ldap_filter)
        self.SEARCH_SCOPE = getattr(ldap, 'SCOPE_%s' % search_scope)
        self.attr_login = attr_login

    def authenticate_ldap(self, username, password):
        """
        Authenticate a user via LDAP and return his/her LDAP properties.

        Raises AuthenticationError if the credentials are rejected, or
        EnvironmentError if the LDAP server can't be reached.

        :param username: username
        :param password: password
        """

        from rhodecode.lib.helpers import chop_at

        uid = chop_at(username, "@%s" % self.LDAP_SERVER_ADDRESS)

        if not password:
            log.debug("Attempt to authenticate LDAP user "
                      "with blank password rejected.")
            raise LdapPasswordError()
        if "," in username:
            raise LdapUsernameError("invalid character in username: ,")
        try:
            if hasattr(ldap, 'OPT_X_TLS_CACERTDIR'):
                ldap.set_option(ldap.OPT_X_TLS_CACERTDIR,
                                '/etc/openldap/cacerts')
            ldap.set_option(ldap.OPT_REFERRALS, ldap.OPT_OFF)
            ldap.set_option(ldap.OPT_RESTART, ldap.OPT_ON)
            ldap.set_option(ldap.OPT_TIMEOUT, 20)
            ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
            ldap.set_option(ldap.OPT_TIMELIMIT, 15)
            if self.TLS_KIND != 'PLAIN':
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, self.TLS_REQCERT)
            server = ldap.initialize(self.LDAP_SERVER)
            if self.ldap_version == 2:
                server.protocol = ldap.VERSION2
            else:
                server.protocol = ldap.VERSION3

            if self.TLS_KIND == 'START_TLS':
                server.start_tls_s()

            if self.LDAP_BIND_DN and self.LDAP_BIND_PASS:
                log.debug('Trying simple_bind with password and given DN: %s'
                          % self.LDAP_BIND_DN)
                server.simple_bind_s(self.LDAP_BIND_DN, self.LDAP_BIND_PASS)

            filter_ = '(&%s(%s=%s))' % (self.LDAP_FILTER, self.attr_login,
                                     username)
            log.debug("Authenticating %r filter %s at %s", self.BASE_DN,
                      filter_, self.LDAP_SERVER)
            lobjects = server.search_ext_s(self.BASE_DN, self.SEARCH_SCOPE,
                                           filter_)

            if not lobjects:
                raise ldap.NO_SUCH_OBJECT()

            for (dn, _attrs) in lobjects:
                if dn is None:
                    continue

                try:
                    log.debug('Trying simple bind with %s' % dn)
                    server.simple_bind_s(dn, password)
                    attrs = server.search_ext_s(dn, ldap.SCOPE_BASE,
                                                '(objectClass=*)')[0][1]
                    break

                except ldap.INVALID_CREDENTIALS:
                    log.debug(
                        "LDAP rejected password for user '%s' (%s): %s" % (
                            uid, username, dn
                        )
                    )

            else:
                log.debug("No matching LDAP objects for authentication "
                          "of '%s' (%s)", uid, username)
                raise LdapPasswordError()

        except ldap.NO_SUCH_OBJECT:
            log.debug("LDAP says no such user '%s' (%s)" % (uid, username))
            raise LdapUsernameError()
        except ldap.SERVER_DOWN:
            raise LdapConnectionError("LDAP can't access "
                                      "authentication server")

        return (dn, attrs)

class RhodeCodeAuthPlugin(rhodecode.lib.auth.RhodeCodeAuthPlugin):
    def __init__(self):
        self._logger = logging.getLogger(__name__)
        self._tls_kind_values = ["PLAIN", "LDAPS", "START_TLS"]
        self._tls_reqcert_values = ["NEVER", "ALLOW", "TRY", "DEMAND", "HARD"]
        self._search_scopes = ["BASE", "ONELEVEL", "SUBTREE"]

    def name(self):
        return "ldap"

    def settings(self):
        settings = [
            {
                "name": "host",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "Host of the LDAP Server",
                "formname": "LDAP Host"
                },
            {
                "name": "port",
                "validator": v.Number(strip=True),
                "type": "string",
                "description": "Port that the LDAP server is listening on",
                "formname": "Port"
                },
            {
                "name": "dn_user",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "User to connect to LDAP",
                "formname": "Account"
                },
            {
                "name": "dn_pass",
                "validator": v.UnicodeString(strip=True),
                "type": "password",
                "description": "Password to connect to LDAP",
                "formname": "Password"
                },
            {
                "name": "tls_kind",
                "validator": v.OneOf(self._tls_kind_values),
                "type": "select",
                "values": self._tls_kind_values,
                "description": "TLS Type",
                "formname": "Connection Security"
                },
            {
                "name": "tls_reqcert",
                "validator": v.OneOf(self._tls_reqcert_values),
                "type": "select",
                "values": self._tls_reqcert_values,
                "description": "Require Cert over TLS?",
                "formname": "Certificate Checks"
                },
            {
                "name": "base_dn",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "Base DN to search (e.g., dc=mydomain,dc=com)",
                "formname": "Base DN"
                },
            {
                "name": "filter",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "Filter to narrow results (e.g., ou=Users, etc)",
                "formname": "LDAP Search Filter"
                },
            {
                "name": "search_scope",
                "validator": v.OneOf(self._search_scopes),
                "type": "select",
                "values": self._search_scopes,
                "description": "How deep to search LDAP",
                "formname": "LDAP Search Scope"
                },
            {
                "name": "attr_login",
                "validator": (formencode.All(
                        v.AttrLoginValidator(),
                        v.UnicodeString(strip=True))
                              ),
                "type": "string",
                "description": "LDAP Attribute to map to user name",
                "formname": "Login Attribute"
                },
            {
                "name": "attr_firstname",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "LDAP Attribute to map to first name",
                "formname": "First Name Attribute"
                },
            {
                "name": "attr_lastname",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "LDAP Attribute to map to last name",
                "formname": "Last Name Attribute"
                },
            {
                "name": "attr_email",
                "validator": v.UnicodeString(strip=True),
                "type": "string",
                "description": "LDAP Attribute to map to email address",
                "formname": "Email Attribute"
                }
            ]
        return settings

    def use_fake_password(self):
        return True

    def auth(self, userobj, user, password, settings):
        log.debug("Authenticating user using ldap")
        kwargs = {
            'server': settings.get('host', ''),
            'base_dn': settings.get('base_dn', ''),
            'port': settings.get('port'),
            'bind_dn': settings.get('dn_user'),
            'bind_pass': settings.get('dn_pass'),
            'tls_kind': settings.get('tls_kind'),
            'tls_reqcert': settings.get('tls_reqcert'),
            'ldap_filter': settings.get('filter'),
            'search_scope': settings.get('search_scope'),
            'attr_login': settings.get('attr_login'),
            'ldap_version': 3,
            }
        log.debug('Checking for ldap authentication')
        try:
            aldap = AuthLdap(**kwargs)
            (user_dn, ldap_attrs) = aldap.authenticate_ldap(user,
                                                            password)
            log.debug('Got ldap DN response %s' % user_dn)

            get_ldap_attr = lambda k: ldap_attrs.get(settings\
                                                         .get(k), [''])[0]

            user_attrs = {
                'firstname': safe_unicode(get_ldap_attr('attr_firstname')),
                'lastname': safe_unicode(get_ldap_attr('attr_lastname')),
                'groups': [],
                'email': get_ldap_attr('attr_email'),
                'admin': False,
                'active': True,
                'extern_name': user_dn
                }

            return user_attrs

        except (LdapUsernameError, LdapPasswordError, LdapImportError):
            log.error(traceback.format_exc())
            return None
        except (Exception,):
            log.error(traceback.format_exc())
            return None

        return None

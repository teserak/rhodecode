from sqlalchemy.orm.exc import NoResultFound

from rhodecode.tests import *
from rhodecode.tests.fixture import Fixture
from rhodecode.model.db import User, Permission
from rhodecode.lib.auth import check_password
from rhodecode.model.user import UserModel
from rhodecode.model import validators
from rhodecode.lib import helpers as h
from rhodecode.model.meta import Session

fixture = Fixture()


class TestAdminUsersController(TestController):
    test_user_1 = 'testme'

    @classmethod
    def teardown_class(cls):
        UserModel().delete(cls.test_user_1)
        Session().commit()

    def test_index(self):
        self.log_user()
        response = self.app.get(url('users'))
        # Test response...

    def test_index_as_xml(self):
        response = self.app.get(url('formatted_users', format='xml'))

    def test_create(self):
        self.log_user()
        username = 'newtestuser'
        password = 'test12'
        password_confirmation = password
        name = 'name'
        lastname = 'lastname'
        email = 'mail@mail.com'

        response = self.app.post(url('users'),
                             {'username': username,
                               'password': password,
                               'password_confirmation': password_confirmation,
                               'firstname': name,
                               'active': True,
                               'lastname': lastname,
                               'email': email})

        self.checkSessionFlash(response, '''Created user %s''' % (username))

        new_user = Session().query(User).\
            filter(User.username == username).one()

        self.assertEqual(new_user.username, username)
        self.assertEqual(check_password(password, new_user.password), True)
        self.assertEqual(new_user.name, name)
        self.assertEqual(new_user.lastname, lastname)
        self.assertEqual(new_user.email, email)

        response.follow()
        response = response.follow()
        response.mustcontain("""newtestuser""")

    def test_create_err(self):
        self.log_user()
        username = 'new_user'
        password = ''
        name = 'name'
        lastname = 'lastname'
        email = 'errmail.com'

        response = self.app.post(url('users'), {'username': username,
                                               'password': password,
                                               'name': name,
                                               'active': False,
                                               'lastname': lastname,
                                               'email': email})

        msg = validators.ValidUsername(False, {})._messages['system_invalid_username']
        msg = h.html_escape(msg % {'username': 'new_user'})
        response.mustcontain("""<span class="error-message">%s</span>""" % msg)
        response.mustcontain("""<span class="error-message">Please enter a value</span>""")
        response.mustcontain("""<span class="error-message">An email address must contain a single @</span>""")

        def get_user():
            Session().query(User).filter(User.username == username).one()

        self.assertRaises(NoResultFound, get_user), 'found user in database'

    def test_new(self):
        self.log_user()
        response = self.app.get(url('new_user'))

    def test_new_as_xml(self):
        response = self.app.get(url('formatted_new_user', format='xml'))

    @parameterized.expand(
        [('firstname', {'firstname': 'new_username'}),
         ('lastname', {'lastname': 'new_username'}),
         ('admin', {'admin': True}),
         ('admin', {'admin': False}),
         ('extern_type', {'extern_type': 'ldap'}),
         ('extern_type', {'extern_type': None}),
         ('extern_name', {'extern_name': 'test'}),
         ('extern_name', {'extern_name': None}),
         ('active', {'active': False}),
         ('active', {'active': True}),
         ('email', {'email': 'some@email.com'}),
        # ('new_password', {'new_password': 'foobar123',
        #                   'password_confirmation': 'foobar123'})
        ])
    def test_update(self, name, attrs):
        self.log_user()
        usr = fixture.create_user(self.test_user_1, password='qweqwe',
                                  email='testme@rhodecode.org',
                                  extern_type='rhodecode',
                                  extern_name=self.test_user_1,
                                  skip_if_exists=True)
        Session().commit()
        params = usr.get_api_data()
        params.update({'password_confirmation': ''})
        params.update({'new_password': ''})
        params.update(attrs)
        if name == 'email':
            params['emails'] = [attrs['email']]
        if name == 'extern_type':
            #cannot update this via form, expected value is original one
            params['extern_type'] = "rhodecode"
        if name == 'extern_name':
            #cannot update this via form, expected value is original one
            params['extern_name'] = self.test_user_1
            # special case since this user is not
                                          # logged in yet his data is not filled
                                          # so we use creation data

        response = self.app.put(url('user', id=usr.user_id), params)
        self.checkSessionFlash(response, 'User updated successfully')

        updated_user = User.get_by_username(self.test_user_1)
        updated_params = updated_user.get_api_data()
        updated_params.update({'password_confirmation': ''})
        updated_params.update({'new_password': ''})

        self.assertEqual(params, updated_params)


    def test_update_browser_fakeout(self):
        response = self.app.post(url('user', id=1), params=dict(_method='put'))

    def test_delete(self):
        self.log_user()
        username = 'newtestuserdeleteme'
        password = 'test12'
        name = 'name'
        lastname = 'lastname'
        email = 'todeletemail@mail.com'

        response = self.app.post(url('users'), {'username': username,
                                               'password': password,
                                               'password_confirmation': password,
                                               'firstname': name,
                                               'active': True,
                                               'lastname': lastname,
                                               'email': email})

        response = response.follow()

        new_user = Session().query(User)\
            .filter(User.username == username).one()
        response = self.app.delete(url('user', id=new_user.user_id))

        self.checkSessionFlash(response, 'Successfully deleted user')

    def test_delete_browser_fakeout(self):
        response = self.app.post(url('user', id=1),
                                 params=dict(_method='delete'))

    def test_show(self):
        response = self.app.get(url('user', id=1))

    def test_show_as_xml(self):
        response = self.app.get(url('formatted_user', id=1, format='xml'))

    def test_edit(self):
        self.log_user()
        user = User.get_by_username(TEST_USER_ADMIN_LOGIN)
        response = self.app.get(url('edit_user', id=user.user_id))

    def test_add_perm_create_repo(self):
        self.log_user()
        perm_none = Permission.get_by_key('hg.create.none')
        perm_create = Permission.get_by_key('hg.create.repository')

        user = UserModel().create_or_update(username='dummy', password='qwe',
                                            email='dummy', firstname='a',
                                            lastname='b')
        Session().commit()
        uid = user.user_id

        try:
            #User should have None permission on creation repository
            self.assertEqual(UserModel().has_perm(user, perm_none), False)
            self.assertEqual(UserModel().has_perm(user, perm_create), False)

            response = self.app.post(url('user_perm', id=uid),
                                     params=dict(_method='put',
                                                 create_repo_perm=True))

            perm_none = Permission.get_by_key('hg.create.none')
            perm_create = Permission.get_by_key('hg.create.repository')

            #User should have None permission on creation repository
            self.assertEqual(UserModel().has_perm(uid, perm_none), False)
            self.assertEqual(UserModel().has_perm(uid, perm_create), True)
        finally:
            UserModel().delete(uid)
            Session().commit()

    def test_revoke_perm_create_repo(self):
        self.log_user()
        perm_none = Permission.get_by_key('hg.create.none')
        perm_create = Permission.get_by_key('hg.create.repository')

        user = UserModel().create_or_update(username='dummy', password='qwe',
                                            email='dummy', firstname='a',
                                            lastname='b')
        Session().commit()
        uid = user.user_id

        try:
            #User should have None permission on creation repository
            self.assertEqual(UserModel().has_perm(user, perm_none), False)
            self.assertEqual(UserModel().has_perm(user, perm_create), False)

            response = self.app.post(url('user_perm', id=uid),
                                     params=dict(_method='put'))

            perm_none = Permission.get_by_key('hg.create.none')
            perm_create = Permission.get_by_key('hg.create.repository')

            #User should have None permission on creation repository
            self.assertEqual(UserModel().has_perm(uid, perm_none), True)
            self.assertEqual(UserModel().has_perm(uid, perm_create), False)
        finally:
            UserModel().delete(uid)
            Session().commit()

    def test_add_perm_fork_repo(self):
        self.log_user()
        perm_none = Permission.get_by_key('hg.fork.none')
        perm_fork = Permission.get_by_key('hg.fork.repository')

        user = UserModel().create_or_update(username='dummy', password='qwe',
                                            email='dummy', firstname='a',
                                            lastname='b')
        Session().commit()
        uid = user.user_id

        try:
            #User should have None permission on creation repository
            self.assertEqual(UserModel().has_perm(user, perm_none), False)
            self.assertEqual(UserModel().has_perm(user, perm_fork), False)

            response = self.app.post(url('user_perm', id=uid),
                                     params=dict(_method='put',
                                                 create_repo_perm=True))

            perm_none = Permission.get_by_key('hg.create.none')
            perm_create = Permission.get_by_key('hg.create.repository')

            #User should have None permission on creation repository
            self.assertEqual(UserModel().has_perm(uid, perm_none), False)
            self.assertEqual(UserModel().has_perm(uid, perm_create), True)
        finally:
            UserModel().delete(uid)
            Session().commit()

    def test_revoke_perm_fork_repo(self):
        self.log_user()
        perm_none = Permission.get_by_key('hg.fork.none')
        perm_fork = Permission.get_by_key('hg.fork.repository')

        user = UserModel().create_or_update(username='dummy', password='qwe',
                                            email='dummy', firstname='a',
                                            lastname='b')
        Session().commit()
        uid = user.user_id

        try:
            #User should have None permission on creation repository
            self.assertEqual(UserModel().has_perm(user, perm_none), False)
            self.assertEqual(UserModel().has_perm(user, perm_fork), False)

            response = self.app.post(url('user_perm', id=uid),
                                     params=dict(_method='put'))

            perm_none = Permission.get_by_key('hg.create.none')
            perm_create = Permission.get_by_key('hg.create.repository')

            #User should have None permission on creation repository
            self.assertEqual(UserModel().has_perm(uid, perm_none), True)
            self.assertEqual(UserModel().has_perm(uid, perm_create), False)
        finally:
            UserModel().delete(uid)
            Session().commit()

    def test_edit_as_xml(self):
        response = self.app.get(url('formatted_edit_user', id=1, format='xml'))

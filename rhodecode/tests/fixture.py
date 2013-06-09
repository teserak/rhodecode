"""
Helpers for fixture generation
"""
from rhodecode.model.user import UserModel
from rhodecode.tests import *
from rhodecode.model.db import Repository, User, RepoGroup, UserGroup
from rhodecode.model.meta import Session
from rhodecode.model.repo import RepoModel
from rhodecode.model.repo_group import RepoGroupModel
from rhodecode.model.user_group import UserGroupModel
from rhodecode.model.gist import GistModel

class Fixture(object):

    def __init__(self):
        pass

    def _get_repo_create_params(self, **custom):
        defs = dict(
            repo_name=None,
            repo_type='hg',
            clone_uri='',
            repo_group='',
            repo_description='DESC',
            repo_private=False,
            repo_landing_rev='tip'
        )
        defs.update(custom)
        if 'repo_name_full' not in custom:
            defs.update({'repo_name_full': defs['repo_name']})

        return defs

    def _get_group_create_params(self, **custom):
        defs = dict(
            group_name=None,
            group_description='DESC',
            group_parent_id=None,
            perms_updates=[],
            perms_new=[],
            enable_locking=False,
            recursive=False
        )
        defs.update(custom)

        return defs

    def _get_user_create_params(self, name, **custom):
        defs = dict(
            username=name,
            password='qweqwe',
            email='%s+test@rhodecode.org' % name,
            firstname='TestUser',
            lastname='Test',
            active=True,
            admin=False,
            extern_type='rhodecode',
            extern_name=None
        )
        defs.update(custom)

        return defs

    def _get_user_group_create_params(self, name, **custom):
        defs = dict(
            users_group_name=name,
            users_group_active=True,
        )
        defs.update(custom)

        return defs

    def create_repo(self, name, **kwargs):
        if 'skip_if_exists' in kwargs:
            del kwargs['skip_if_exists']
            r = Repository.get_by_repo_name(name)
            if r:
                return r

        if isinstance(kwargs.get('repos_group'), RepoGroup):
            #TODO: rename the repos_group !
            kwargs['repo_group'] = kwargs['repos_group'].group_id
            del kwargs['repos_group']

        form_data = self._get_repo_create_params(repo_name=name, **kwargs)
        cur_user = kwargs.get('cur_user', TEST_USER_ADMIN_LOGIN)
        RepoModel().create(form_data, cur_user)
        Session().commit()
        return Repository.get_by_repo_name(name)

    def create_fork(self, repo_to_fork, fork_name, **kwargs):
        repo_to_fork = Repository.get_by_repo_name(repo_to_fork)

        form_data = self._get_repo_create_params(repo_name=fork_name,
                                            fork_parent_id=repo_to_fork,
                                            repo_type=repo_to_fork.repo_type,
                                            **kwargs)
        form_data['update_after_clone'] = False

        #TODO: fix it !!
        form_data['description'] = form_data['repo_description']
        form_data['private'] = form_data['repo_private']
        form_data['landing_rev'] = form_data['repo_landing_rev']

        owner = kwargs.get('cur_user', TEST_USER_ADMIN_LOGIN)
        RepoModel().create_fork(form_data, cur_user=owner)
        Session().commit()
        r = Repository.get_by_repo_name(fork_name)
        assert r
        return r

    def destroy_repo(self, repo_name):
        RepoModel().delete(repo_name)
        Session().commit()

    def create_group(self, name, **kwargs):
        if 'skip_if_exists' in kwargs:
            del kwargs['skip_if_exists']
            gr = RepoGroup.get_by_group_name(group_name=name)
            if gr:
                return gr
        form_data = self._get_group_create_params(group_name=name, **kwargs)
        owner = kwargs.get('cur_user', TEST_USER_ADMIN_LOGIN)
        gr = RepoGroupModel().create(group_name=form_data['group_name'],
                                 group_description=form_data['group_name'],
                                 owner=owner, parent=form_data['group_parent_id'])
        Session().commit()
        gr = RepoGroup.get_by_group_name(gr.group_name)
        return gr

    def create_user(self, name, **kwargs):
        if 'skip_if_exists' in kwargs:
            del kwargs['skip_if_exists']
            user = User.get_by_username(name)
            if user:
                return user
        form_data = self._get_user_create_params(name, **kwargs)
        user = UserModel().create(form_data)
        Session().commit()
        user = User.get_by_username(user.username)
        return user

    def create_user_group(self, name, **kwargs):
        if 'skip_if_exists' in kwargs:
            del kwargs['skip_if_exists']
            gr = UserGroup.get_by_group_name(group_name=name)
            if gr:
                return gr
        form_data = self._get_user_group_create_params(name, **kwargs)
        owner = kwargs.get('cur_user', TEST_USER_ADMIN_LOGIN)
        user_group = UserGroupModel().create(name=form_data['users_group_name'],
                        owner=owner, active=form_data['users_group_active'])
        Session().commit()
        user_group = UserGroup.get_by_group_name(user_group.users_group_name)
        return user_group

    def create_gist(self, **kwargs):
        form_data = {
            'description': 'new-gist',
            'owner': TEST_USER_ADMIN_LOGIN,
            'gist_type': GistModel.cls.GIST_PUBLIC,
            'lifetime': -1,
            'gist_mapping': {'filename1.txt':{'content':'hello world'},}
        }
        form_data.update(kwargs)
        gist = GistModel().create(
            description=form_data['description'],owner=form_data['owner'],
            gist_mapping=form_data['gist_mapping'], gist_type=form_data['gist_type'],
            lifetime=form_data['lifetime']
        )
        Session().commit()

        return gist

    def destroy_gists(self, gistid=None):
        for g in GistModel.cls.get_all():
            if gistid:
                if gistid == g.gist_access_id:
                    GistModel().delete(g)
            else:
                GistModel().delete(g)
        Session().commit()

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from keystoneclient import exceptions as keystone_exceptions

from openstack_auth import exceptions
from openstack_auth import user as auth_user
from openstack_auth import utils

LOG = logging.getLogger(__name__)

KEYSTONE_CLIENT_ATTR = "_keystoneclient"


class BaseIdentityAuthentication(object):
    """A Base Authentication Plugin for authenticating against keystone.

    Django authentication backend for use with ``django.contrib.auth``.

    This provides a plugin base that handles the typical keystone token scoping
    and project discovery workflow. Other authentication systems may subclass
    this to customize the keystone authentication experience.

    NOTE: This class presents a public interface that may be relied upon by
    others.
    """

    def __init__(self):
        self._request = None

    def authenticate(self, auth_url=None, request=None, **kwargs):
        default_kwargs = self.get_default_arguments()
        default_kwargs.update(kwargs)

        if auth_url is None:
            auth_url = settings.OPENSTACK_KEYSTONE_URL

        auth_url = utils.fix_auth_url_version(auth_url)

        if not (request and auth_url):
            return None

        return self.do_authenticate(auth_url=auth_url,
                                    request=request,
                                    **default_kwargs)

    def get_user(self, user_id):
        """Returns the current user from the session data.

        If authenticated, this return the user object based on the user ID
        and session data.

        Note: this required monkey-patching the ``contrib.auth`` middleware
        to make the ``request`` object available to the auth backend class.
        """
        if not self._request:
            return None

        if user_id != self._request.session["user_id"]:
            return None

        token = self._request.session['token']
        endpoint = self._request.session['region_endpoint']
        services_region = self._request.session['services_region']
        return auth_user.create_user_from_token(self._request,
                                                token,
                                                endpoint,
                                                services_region)

    def get_group_permissions(self, user, obj=None):
        """Returns an empty set since Keystone doesn't support "groups"."""
        # Keystone V3 added "groups". The Auth token response includes the
        # roles from the user's Group assignment. It should be fine just
        # returning an empty set here.
        return set()

    def get_all_permissions(self, user, obj=None):
        """Returns a set of permission strings that the user has.

        This permission available to the user is derived from the user's
        Keystone "roles".

        The permissions are returned as ``"openstack.{{ role.name }}"``.
        """
        if user.is_anonymous() or obj is not None:
            return set()
        # TODO(gabrielhurley): Integrate policy-driven RBAC
        #                      when supported by Keystone.
        role_perms = set(["openstack.roles.%s" % role['name'].lower()
                          for role in user.roles])
        service_perms = set(["openstack.services.%s" % service['type'].lower()
                             for service in user.service_catalog
                             if user.services_region in
                             [endpoint.get('region', None) for endpoint
                              in service.get('endpoints', [])]])
        return role_perms | service_perms

    def has_perm(self, user, perm, obj=None):
        """Returns True if the given user has the specified permission."""
        if not user.is_active:
            return False
        return perm in self.get_all_permissions(user, obj)

    def has_module_perms(self, user, app_label):
        """Returns True if user has any permissions in the given app_label.

        Currently this matches for the app_label ``"openstack"``.
        """
        if not user.is_active:
            return False
        for perm in self.get_all_permissions(user):
            if perm[:perm.index('.')] == app_label:
                return True
        return False

    def get_default_arguments(self):
        return dict(
            interface=getattr(settings, 'OPENSTACK_ENDPOINT_TYPE', 'public'),
        )

    @property
    def keystone_client_class(self):
        return utils.get_keystone_client().Client

    @property
    def keystone_version(self):
        return utils.get_keystone_version()

    def _check_auth_expiry(self, auth_ref, margin=None):
        if not utils.is_token_valid(auth_ref, margin):
            msg = _("The authentication token issued by the Identity service "
                    "has expired.")
            LOG.warning("The authentication token issued by the Identity "
                        "service appears to have expired before it was "
                        "issued. This may indicate a problem with either your "
                        "server or client configuration.")
            raise exceptions.KeystoneAuthException(msg)
        return True

    def do_authenticate(self, request, auth_url, **kwargs):
        session = utils.get_session()
        interface = kwargs.pop('interface')

        unscoped_auth = self.get_unscoped_plugin(auth_url=auth_url, **kwargs)

        if not unscoped_auth:
            return None

        try:
            unscoped_auth_ref = unscoped_auth.get_access(session)
        except (keystone_exceptions.Unauthorized,
                keystone_exceptions.Forbidden,
                keystone_exceptions.NotFound) as exc:
            msg = _('Invalid user name or password.')
            LOG.debug(str(exc))
            raise exceptions.KeystoneAuthException(msg)
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            msg = _("An error occurred authenticating. "
                    "Please try again later.")
            LOG.debug(str(exc))
            raise exceptions.KeystoneAuthException(msg)

        # Check expiry for our unscoped auth ref.
        self._check_auth_expiry(unscoped_auth_ref)

        projects = self.get_projects(session, unscoped_auth)

        # Attempt to scope only to enabled projects
        projects = [project for project in projects if project.enabled]

        # Abort if there are no projects for this user
        if not projects:
            msg = _('You are not authorized for any projects.')
            raise exceptions.KeystoneAuthException(msg)

        # the recent project id a user might have set in a cookie
        recent_project = None
        if request:
            # Check if token is automatically scoped to default_project
            # grab the project from this token, to use as a default
            # if no recent_project is found in the cookie
            recent_project = request.COOKIES.get('recent_project',
                                                 unscoped_auth_ref.project_id)

        # if a most recent project was found, try using it first
        if recent_project:
            for pos, project in enumerate(projects):
                if project.id == recent_project:
                    # move recent project to the beginning
                    projects.pop(pos)
                    projects.insert(0, project)
                    break

        for project in projects:
            token = unscoped_auth_ref.auth_token
            scoped_auth = self.get_scoped_plugin(auth_url=auth_url,
                                                 token=token,
                                                 project=project)

            try:
                scoped_auth_ref = scoped_auth.get_access(session)
            except (keystone_exceptions.ClientException,
                    keystone_exceptions.AuthorizationFailure):
                pass
            else:
                break
        else:
            msg = _("Unable to authenticate to any available projects.")
            raise exceptions.KeystoneAuthException(msg)

        # Check expiry for our new scoped token.
        self._check_auth_expiry(scoped_auth_ref)

        # If we made it here we succeeded. Create our User!
        user = auth_user.create_user_from_token(
            request,
            auth_user.Token(scoped_auth_ref),
            scoped_auth_ref.service_catalog.url_for(endpoint_type=interface))

        if request is not None:
            request.session['unscoped_token'] = unscoped_auth_ref.auth_token
            request.user = user
            scoped_client = self.keystone_client_class(session=session,
                                                       auth=scoped_auth)

            # Support client caching to save on auth calls.
            setattr(request, KEYSTONE_CLIENT_ATTR, scoped_client)

        LOG.debug('Authentication completed for user')
        return user

    def get_unscoped_plugin(self, **kwargs):
        raise NotImplemented()

    def get_scoped_plugin(self, auth_url, token, project):
        return utils.get_token_auth_plugin(auth_url,
                                           token=token,
                                           project_id=project.id)

    def get_projects(self, session, auth):
        # We list all the user's projects
        unscoped_client = self.keystone_client_class(session=session,
                                                     auth=auth)

        try:
            if self.keystone_version >= 3:
                user_id = auth.get_user_id(session)
                projects = unscoped_client.projects.list(user=user_id)
            else:
                projects = unscoped_client.tenants.list()
        except (keystone_exceptions.ClientException,
                keystone_exceptions.AuthorizationFailure) as exc:
            msg = _('Unable to retrieve authorized projects.')
            LOG.debug(str(exc))
            raise exceptions.KeystoneAuthException(msg)

        return projects

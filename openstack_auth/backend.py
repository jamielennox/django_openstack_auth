# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Module defining the Django auth backend class for the Keystone API. """

import logging

from keystoneclient.auth.identity import v2 as v2_auth
from keystoneclient.auth.identity import v3 as v3_auth

from openstack_auth import base

LOG = logging.getLogger(__name__)


class KeystoneBackend(base.BaseIdentityAuthentication):
    """Authenticate against keystone using a username and password"""

    def get_unscoped_plugin(self, auth_url=None, username=None, password=None,
                            user_domain_name=None, **kwargs):
        if not all((auth_url, username, password)):
            return None

        plugin = None

        if self.keystone_version >= 3:
            plugin = v3_auth.Password(auth_url=auth_url,
                                      username=username,
                                      password=password,
                                      user_domain_name=user_domain_name)

        else:
            plugin = v2_auth.Password(auth_url=auth_url,
                                      username=username,
                                      password=password)

        return plugin

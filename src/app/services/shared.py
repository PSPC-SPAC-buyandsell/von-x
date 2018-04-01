#
# Copyright 2017-2018 Government of Canada
# Public Services and Procurement Canada - buyandsell.gc.ca
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Importing this file causes the standard settings to be loaded
and a standard service manager to be created. This allows services
to be properly initialized before the webserver process has forked.

If creating a custom ServiceManager or using services directly,
then don't import this file.
"""

import logging.config

from . import config, issuer, prover, manager


# Load application settings (environment)
ENV = config.load_settings()
print(ENV)

# Load and apply logging config
LOG_CONFIG = config.load_config(ENV.get('LOG_CONFIG_PATH'))
logging.config.dictConfig(LOG_CONFIG)


class SharedServiceManager(manager.ServiceManager):
    def init_services(self):
        # Issuer manager - handles ready, status, submit_claim
        self._services['issuer'] = issuer.init_issuer_manager(self)

        # Prover manager - handles construct_proof
        self._services['prover'] = prover.init_prover_manager(self)

MANAGER = SharedServiceManager(ENV)

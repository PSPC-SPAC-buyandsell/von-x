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
#pylint: disable=broad-except,ungrouped-imports

"""
Standard entry point for the application
"""

try:
    from app import APP, get_issuer_manager
except Exception:
    import logging
    import sys
    LOGGER = logging.getLogger(__name__)
    LOGGER.exception('Error while loading application:')
    sys.exit(1)

if __name__ == '__main__':
    import logging
    LOGGER = logging.getLogger(__name__)

    try:
        HOST = APP.config.get('HOST_IP', '0.0.0.0')
        PORT = int(APP.config.get('HOST_PORT', '8000'))
        LOGGER.info('Running server on %s:%s', HOST, PORT)
        APP.run(host=HOST, port=PORT, debug=APP.config.get('DEBUG'), workers=1)
    except Exception:
        LOGGER.exception('Error while running server:')
        sys.exit(1)

    MGR = get_issuer_manager()
    if MGR:
        MGR.join()

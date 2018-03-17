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

import json
import logging


class JsonRepr:
    """Utility class to avoid JSON encoding debug output unless needed"""
    def __init__(self, value, indent=2):
        self.value = value
        self.indent = indent

    def __repr__(self):
        return json.dumps(self.value, indent=self.indent)


def log_json(heading, data, logger=None):
    if not logger:
        logger = logging.getLogger()
    msg = """
        ============================================================================
        %s
        %s
        ============================================================================
    """
    logger.debug(msg, heading, JsonRepr(data))

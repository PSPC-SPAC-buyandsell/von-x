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

class IndyError(Exception):
    pass

class IndyClientError(IndyError):
    pass

class IndyConfigError(IndyError):
    pass

class IndyConnectionError(IndyError):
    """
    A generic exception representing an issue with a :class:`ConnectionBase` operation
    """

    def __init__(self, status_code, message: str, response=None):
        super(IndyConnectionError, self).__init__(message)
        self.status_code = status_code
        self.message = message
        self.response = response


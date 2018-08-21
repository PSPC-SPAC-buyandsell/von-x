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

import logging

from didauth.base import KeyFinderBase
from didauth.error import VerifierException
from didauth.headers import HeaderVerifier
from didauth.utils import decode_string

from vonx.indy.client import IndyClient

LOGGER = logging.getLogger(__name__)


async def verify_headers(
        headers, key_finder: KeyFinderBase,
        method=None, path=None, use_key_cache: bool = True):
    verifier = HeaderVerifier(key_finder)
    return await verifier.verify(headers, method, path, use_key_cache)


class IndyKeyFinder(KeyFinderBase):
    """
    Look up the public key for an issuer
    """

    def __init__(self, client: IndyClient, verifier_id: str, cache: KeyFinderBase = None):
        super(IndyKeyFinder, self).__init__(cache)
        self._client = client
        self._verifier_id = verifier_id

    async def lookup_key(self, key_id: str, key_type: str):
        assert key_type == "ed25519"
        if key_id.startswith("did:sov:"):
            short_key_id = key_id[8:]
        else:
            short_key_id = key_id
            key_id = "did:sov:" + short_key_id

        LOGGER.debug(
            "Fetching verkey for DID '{}' from ledger".format(key_id))
        nym_info = await self._client.resolve_nym(short_key_id, self._verifier_id)
        if nym_info.data:
            return decode_string(nym_info.data["verkey"], "base58")
        return None

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

from typing import Sequence

from ..common.exchange import RequestTarget

from .config import AgentType, IssuerTargetType

from .messages import (
    IndyServiceAck,
    IndyServiceError,
    LedgerStatusReq,
    LedgerStatus,
    RegisterWalletReq,
    WalletStatusReq,
    WalletStatus,
    RegisterAgentReq,
    AgentStatusReq,
    AgentStatus,
    RegisterIssuerSchemaReq,
    RegisterIssuerCredDefReq,
    RegisterIssuerTargetReq,
    IssuerTargetStatusReq,
    IssuerTargetStatus,
    RegisterConnectionReq,
    ConnectionStatusReq,
    ConnectionStatus,
    ServiceRequest,
)

class IndyClientError(Exception):
    pass

class IndyClient:
    """
    Wrap up message passing to the Indy service manager in a nicer interface
    """
    def __init__(self, target: RequestTarget):
        self._target = target

    async def _fetch(self, request: ServiceRequest, expect=None):
        result = await self._target.request(request)
        if isinstance(result, IndyServiceError):
            raise IndyClientError(result.value)
        elif expect and not isinstance(result, expect):
            raise IndyClientError("Unexpected result: {}".format(result))
        return result

    async def get_ledger_status(self):
        result = await self._fetch(LedgerStatusReq(), LedgerStatus)
        return result.status

    async def register_wallet(self, config: dict) -> str:
        result = await self._fetch(RegisterWalletReq(config), WalletStatus)
        return result.wallet_id

    async def register_issuer(self, wallet_id: str, config: dict) -> str:
        result = await self._fetch(
            RegisterAgentReq(AgentType.issuer.value, wallet_id, config),
            AgentStatus)
        return result.agent_id

    async def register_holder(self, config: dict) -> str:
        result = await self._fetch(
            RegisterAgentReq(AgentType.holder.value, config),
            AgentStatus)
        return result.agent_id

    async def register_issuer_schema(
            self,
            issuer_id: str,
            schema_name: str,
            schema_version: str,
            attr_names: Sequence,
            config: dict = None) -> None:
        await self._fetch(
            RegisterIssuerSchemaReq(
                issuer_id, schema_name, schema_version,
                attr_names, config),
            IndyServiceAck)

    async def register_issuer_cred_def(
            self,
            issuer_id: str,
            origin_did: str,
            schema_name: str,
            schema_version: str,
            config: dict = None) -> None:
        await self._fetch(
            RegisterIssuerCredDefReq(
                issuer_id, origin_did, schema_name, schema_version, config),
            IndyServiceAck)

    async def register_orgbook_target(self, config: dict) -> str:
        result = await self._fetch(
            RegisterIssuerTargetReq(IssuerTargetType.TheOrgBook.value, config),
            IssuerTargetStatus)
        return result.target_id

    async def register_vonx_target(self, config: dict) -> str:
        result = await self._fetch(
            RegisterIssuerTargetReq(IssuerTargetType.vonx.value, config),
            IssuerTargetStatus)
        return result.target_id

    async def register_connection(self, issuer_id: str, target_id: str, config: dict = None) -> str:
        result = await self._fetch(
            RegisterConnectionReq(issuer_id, target_id, config or {}), ConnectionStatus)
        return result.connection_id

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
Connection handling specific to using the OrgBook as a holder/prover
"""

import base64
import logging
import pathlib

from .connection import HttpConnection, HttpSession
from .errors import IndyConfigError, IndyConnectionError
from ..common.util import log_json

LOGGER = logging.getLogger(__name__)

CRED_TYPE_PARAMETERS = (
    "cardinality_fields",
    "claim_descriptions",
    "claim_labels",
    "credential",
    "details",
    "mapping",
    "topic",
    "visible_fields",
)


def encode_logo_image(config: dict, path_root: str) -> str:
    """
    Encode logo image as base64 for transmission
    """
    if config.get("logo_b64"):
        return config["logo_b64"]
    elif config.get("logo_path"):
        path = pathlib.Path(path_root, config["logo_path"])
        if path.is_file():
            content = path.read_bytes()
            if content:
                return base64.b64encode(content).decode("ascii")
        else:
            LOGGER.warning("No file found at logo path: %s", path)
    return None


def extract_translated(config: dict, field: str, defval=None, deflang: str = "en"):
    ret = {deflang: defval}
    if config:
        pfx = field + "_"
        for k,v in config.items():
            if k == field:
                ret[deflang] = v
            elif k.startswith(pfx):
                lang = k[len(pfx):]
                if lang:
                    ret[lang] = v
    return ret


def assemble_issuer_spec(config: dict) -> dict:
    """
    Create the issuer JSON definition which will be submitted to the OrgBook
    """

    config_root = config.get("config_root", ".")
    deflang = "en"

    issuer_did = config.get("did")
    if not issuer_did:
        raise IndyConfigError("Missing issuer DID")

    details = config.get("details", {})
    issuer_email = details.get("email")
    if not issuer_email:
        raise IndyConfigError("Missing issuer email address")

    abbrevs = extract_translated(details, "abbreviation", "", deflang)
    labels = extract_translated(details, "label", "", deflang)
    urls = extract_translated(details, "url", "", deflang)

    spec = {
        "did": issuer_did,
        "email": issuer_email,
        "logo_b64": encode_logo_image(details, config_root),
        "abbreviation": abbrevs[deflang],
        "name": labels[deflang] or issuer_email,
        "url": urls[deflang],
    }
    for k,v in abbrevs.items():
        spec["abbreviation_{}".format(k)] = v
    for k,v in labels.items():
        spec["label_{}".format(k)] = v
    for k,v in urls.items():
        spec["url_{}".format(k)] = v

    if not spec["name"]:
        raise IndyConfigError("Missing issuer name")

    cred_type_specs = config.get("credential_types")
    if not cred_type_specs:
        raise IndyConfigError("Missing credential_types")

    ctypes = []
    for type_spec in cred_type_specs:
        schema = type_spec["schema"]
        if not type_spec.get("topic"):
            raise IndyConfigError("Missing 'topic' for credential type")

        type_details = type_spec.get("details", {})
        labels = extract_translated(type_details, "label", schema.name, deflang)
        urls = extract_translated(type_details, "url", spec["url"], deflang)
        logo_b64 = encode_logo_image(type_details, config_root)

        ctype = {
            "schema": schema.name,
            "version": schema.version,
            "credential_def_id": type_spec["cred_def"]["id"],
            "name": labels[deflang],
            "endpoint": urls[deflang],
            "topic": type_spec["topic"],
            "logo_b64": logo_b64,
        }
        for k in labels:
            ctype["label_{}".format(k)] = labels[k]
        for k in urls:
            ctype["endpoint_{}".format(k)] = urls[k]
        for k in CRED_TYPE_PARAMETERS:
            if k != "details" and k in type_spec and k not in ctype:
                ctype[k] = type_spec[k]

        ctypes.append(ctype)

    return {
        "issuer": spec,
        "credential_types": ctypes,
    }


class TobConnection(HttpConnection):
    """
    A class for managing communication with the OrgBook API and performing the initial
    synchronization as an issuer
    """

    async def sync(self) -> None:
        """
        Submit the issuer JSON definition to the OrgBook to register our service
        """
        if self.agent_type == "issuer":
            spec = assemble_issuer_spec(self.agent_params)
            log_json("Issuer spec:", spec, LOGGER)
            response = await self.post_json(
                "indy/register-issuer", spec
            )
            result = response.get("result")
            if not response.get("success"):
                raise IndyConnectionError(
                    "Issuer service was not registered: {}".format(result),
                    400,
                    response,
                )

    @property
    def path_prefix(self):
        return "indy/"

    async def fetch_list(self, path: str) -> dict:
        """
        A standard request to a `list`-style API method

        Args:
            path: The relative path to the API method
        """
        url = self.get_api_url(path)
        LOGGER.debug("fetch_list: %s", url)
        async with HttpSession("fetch_list", self._http_client) as handler:
            response = await handler.client.get(url)
            await handler.check_status(response)
            return await response.json()

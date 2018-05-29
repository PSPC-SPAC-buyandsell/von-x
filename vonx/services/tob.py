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

LOGGER = logging.getLogger(__name__)


class TobClientError(Exception):
    """
    A generic exception representing an issue with a TobClient operation
    """

    def __init__(self, status_code, message, response):
        super(TobClientError, self).__init__(message)
        self.status_code = status_code
        self.message = message
        self.response = response


class TobClient:
    """
    A class for managing communication with TheOrgBook API and performing the initial
    synchronization as an issuer
    """

    def __init__(self, config=None):
        self.config = {}
        self.jurisdiction_id = None
        self.issuer_service_id = None
        self.synced = False
        if config:
            self.config.update(config)
        self.api_url = self.config.get("api_url")
        self.issuer_did = self.config.get("did")

    async def sync(self, http_client):
        """
        Register ourselves as an issuer in TheOrgBook

        Args:
            http_client: The :class:`ClientSession` instance responsible for adding
                authentication headers
        """
        if not self.api_url:
            raise ValueError("Missing TOB_API_URL")
        if not self.issuer_did:
            raise ValueError("Missing issuer DID")

        await self.register_issuer(http_client)

        self.synced = True
        LOGGER.info("TOB client synced: %s", self.config["id"])

    async def register_issuer(self, http_client):
        """
        Submit the issuer JSON definition to TheOrgBook to register our service

        Args:
            http_client: The :class:`ClientSession` instance responsible for adding
                authentication headers
        """
        spec = self.assemble_issuer_spec()
        response = await self.post_json(
            http_client, "indy/register-issuer", spec
        )
        result = response["result"]
        if not response["success"]:
            raise TobClientError(
                400,
                "Issuer service was not registered: {}".format(result),
                response,
            )
        # self.jurisdiction_id = result['jurisdiction']['id']
        self.issuer_service_id = result["issuer"]["id"]
        return result

    def assemble_issuer_spec(self) -> dict:
        """
        Create the issuer JSON definition which will be submitted to TheOrgBook
        """
        issuer_spec = {}
        issuer_email = self.config.get("email")
        if not issuer_email:
            raise ValueError("Missing issuer email address")

        jurisdiction_spec = self.config.get("jurisdiction")
        if not jurisdiction_spec or not "name" in jurisdiction_spec:
            raise ValueError("Missing jurisdiction.name")
        issuer_spec["jurisdiction"] = jurisdiction_spec

        issuer_spec["issuer"] = {
            "did": self.issuer_did,
            "name": self.config.get("name", ""),
            "abbreviation": self.config.get("abbreviation", ""),
            "email": issuer_email,
            "url": self.config.get("url", ""),
        }
        if not issuer_spec["issuer"]["name"]:
            raise ValueError("Missing issuer name")

        cred_type_specs = self.config.get("credential_types")
        if not cred_type_specs:
            raise ValueError("Missing credential_types")
        ctypes = []
        for type_spec in cred_type_specs:
            schema = type_spec["schema"]
            ctypes.append(
                {
                    "description": type_spec.get("description") or schema.name,
                    "endpoint": type_spec.get("issuer_url")
                    or issuer_spec["issuer"]["url"],
                    "schema": schema.name,
                    "version": schema.version,
                }
            )
        issuer_spec["credential-types"] = ctypes
        return issuer_spec

    def get_api_url(self, path: str = None) -> str:
        """
        Construct the URL for an API request

        Args:
            path: an optional path to be appended to the URL
        """
        url = self.api_url
        if not url.endswith("/"):
            url += "/"
        if path:
            url = url + path
        return url

    async def fetch_list(self, http_client, path: str) -> dict:
        """
        A standard request to a `list`-style API method

        Args:
            http_client: The :class:`ClientSession` instance responsible for adding
                authentication headers
            path: The relative path to the API method
        """
        url = self.get_api_url(path)
        LOGGER.debug("fetch_list: %s", url)
        response = await http_client.get(url)
        if response.status != 200:
            raise TobClientError(
                response.status,
                "Bad response from fetch_list: ({}) {}".format(
                    response.status, await response.text()
                ),
                response,
            )
        return await response.json()

    async def post_json(self, http_client, path: str, data):
        """
        A standard POST request to an API method

        Args:
            http_client: The :class:`ClientSession` instance responsible for adding
                authentication headers
            path: The relative path to the API method
            data: The body of the request, to be converted to JSON
        """
        url = self.get_api_url(path)
        LOGGER.debug("post_json: %s", url)
        response = await http_client.post(url, json=data)
        if response.status != 200 and response.status != 201:
            raise TobClientError(
                response.status,
                "Bad response from post_json: ({}) {}".format(
                    response.status, await response.text()
                ),
                response,
            )
        return await response.json()

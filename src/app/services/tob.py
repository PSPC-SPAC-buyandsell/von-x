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

from datetime import datetime
import logging

import aiohttp

LOGGER = logging.getLogger(__name__)


class TobClientError(Exception):
    def __init__(self, status_code, message, response):
        super(TobClientError, self).__init__(message)
        self.status_code = status_code
        self.message = message
        self.response = response


def current_date():
    return datetime.now().strftime("%Y-%m-%d")


class TobClient:
    def __init__(self, config=None):
        self.config = {}
        self.jurisdiction_id = None
        self.issuer_service_id = None
        self.synced = False
        if config:
            self.config.update(config)
        self.api_url = self.config.get('api_url')
        self.issuer_did = self.config.get('did')

    async def sync(self):
        if not self.api_url:
            raise ValueError("Missing TOB_API_URL")
        if not self.issuer_did:
            raise ValueError("Missing issuer DID")

        async with aiohttp.ClientSession(read_timeout=30) as http_client:
            await self.sync_jurisdiction(http_client)
            LOGGER.debug('synced jurisdiction')
            await self.sync_issuer_service(http_client)
            await self.sync_claim_types(http_client)

        self.synced = True
        LOGGER.info('TOB client synced: %s', self.config['id'])

    async def sync_jurisdiction(self, client):
        jurisdiction_spec = self.config.get('jurisdiction')
        if not jurisdiction_spec or not 'name' in jurisdiction_spec:
            raise ValueError('Missing jurisdiction.name')

        # Check if my jurisdiction exists by name
        jurisdictions = await self.fetch_list(client, 'jurisdictions')

        for jurisdiction in jurisdictions:
            if jurisdiction['name'] == jurisdiction_spec['name']:
                self.jurisdiction_id = jurisdiction['id']
                break

        # If it doesn't, then create it
        if not self.jurisdiction_id:
            jurisdiction = await self.post_json(client, 'jurisdictions', {
                'name':  jurisdiction_spec['name'],
                'abbrv': jurisdiction_spec.get('abbreviation'),
                'displayOrder':   0,
                'isOnCommonList': True,
                'effectiveDate':  current_date()
            })
            self.jurisdiction_id = jurisdiction['id']
        return self.jurisdiction_id

    async def sync_issuer_service(self, client):
        if not self.jurisdiction_id:
            raise ValueError("Cannot sync issuer service: jurisdiction_id not populated")
        issuer_name = self.config.get('name', '')
        issuer_abbr = self.config.get('abbreviation', '')
        issuer_url = self.config.get('url', '')
        if not issuer_name:
            raise ValueError('Missing issuer name')

        # Check if my issuer record exists by name
        issuer_services = await self.fetch_list(client, 'issuerservices')
        for issuer_service in issuer_services:
            if issuer_service['name'] == issuer_name and \
                    issuer_service['DID'] == self.issuer_did:
                self.issuer_service_id = issuer_service['id']
                break

        # If it doesn't, then create it
        if not self.issuer_service_id:
            issuer_service = await self.post_json(client, 'issuerservices', {
                'name':           issuer_name,
                'DID':            self.issuer_did,
                'issuerOrgTLA':   issuer_abbr,
                'issuerOrgURL':   issuer_url,
                'effectiveDate':  current_date(),
                'jurisdictionId': self.jurisdiction_id
            })
            self.issuer_service_id = issuer_service['id']
        return self.issuer_service_id

    async def sync_claim_types(self, http_client):
        if not self.issuer_service_id:
            raise ValueError("Cannot sync claim types: issuer_service_id not populated")
        claim_type_specs = self.config.get('claim_types')
        if not claim_type_specs:
            raise ValueError("Missing claim_types")
        issuer_url = self.config.get('url', '')

        # Register in TheOrgBook
        # Check if my schema record exists by claimType
        claim_types = await self.fetch_list(http_client, 'verifiableclaimtypes')
        for type_spec in claim_type_specs:
            schema_def = type_spec['schema']
            for claim_type in claim_types:
                if claim_type['schemaName'] == schema_def['name'] and \
                        claim_type['schemaVersion'] == schema_def['version'] and \
                        claim_type['issuerServiceId'] == self.issuer_service_id:
                    # skip creation
                    break
            await self.post_json(http_client, 'verifiableclaimtypes', {
                'claimType':        type_spec.get('description', schema_def['name']),
                'issuerServiceId':  self.issuer_service_id,
                'issuerURL':        type_spec.get('issuer_url', issuer_url),
                'effectiveDate':    current_date(),
                'schemaName':       schema_def['name'],
                'schemaVersion':    schema_def['version']
            })

    def get_api_url(self, module=None):
        url = self.api_url + '/api/v1/'
        if module:
            url = url + module
        return url

    async def fetch_list(self, client, module):
        url = self.get_api_url(module)
        # Would be better practice to use one ClientSession globally, but
        # these requests are only performed once, at startup.
        LOGGER.debug('fetch_list: %s', url)
        response = await client.get(url)
        if response.status != 200:
            raise TobClientError(
                response.status,
                'Bad response from fetch_list: ({}) {}'.format(
                    response.status,
                    await response.text()),
                response)
        return await response.json()

    async def post_json(self, client, module, data):
        url = self.get_api_url(module)
        LOGGER.debug('post_json: %s', url)
        response = await client.post(url, json=data)
        if response.status != 200 and response.status != 201:
            raise TobClientError(
                response.status,
                'Bad response from post_json: ({}) {}'.format(
                    response.status,
                    await response.text()),
                response)
        return await response.json()

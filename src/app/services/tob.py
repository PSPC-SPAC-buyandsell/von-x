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
import requests

LOGGER = logging.getLogger(__name__)


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

        self.sync_jurisdiction()
        self.sync_issuer_service()
        self.sync_claim_types()

        self.synced = True
        LOGGER.info('TOB client synced: %s', self.config['id'])

    def sync_jurisdiction(self):
        jurisdiction_spec = self.config.get('jurisdiction')
        if not jurisdiction_spec or not 'name' in jurisdiction_spec:
            raise ValueError('Missing jurisdiction.name')

        # Check if my jurisdiction exists by name
        jurisdictions = self.fetch_list('jurisdictions')
        for jurisdiction in jurisdictions:
            if jurisdiction['name'] == jurisdiction_spec['name']:
                self.jurisdiction_id = jurisdiction['id']
                break

        # If it doesn't, then create it
        if not self.jurisdiction_id:
            jurisdiction = self.create_record('jurisdictions', {
                'name':  jurisdiction_spec['name'],
                'abbrv': jurisdiction_spec.get('abbreviation'),
                'displayOrder':   0,
                'isOnCommonList': True,
                'effectiveDate':  current_date()
            })
            self.jurisdiction_id = jurisdiction['id']
        return self.jurisdiction_id

    def sync_issuer_service(self):
        if not self.jurisdiction_id:
            raise ValueError("Cannot sync issuer service: jurisdiction_id not populated")
        issuer_name = self.config.get('name', '')
        issuer_abbr = self.config.get('abbreviation', '')
        issuer_url = self.config.get('url', '')
        if not issuer_name:
            raise ValueError('Missing issuer name')

        # Check if my issuer record exists by name
        issuer_services = self.fetch_list('issuerservices')
        for issuer_service in issuer_services:
            if issuer_service['name'] == issuer_name and \
                    issuer_service['DID'] == self.issuer_did:
                self.issuer_service_id = issuer_service['id']
                break

        # If it doesn't, then create it
        if not self.issuer_service_id:
            issuer_service = self.create_record('issuerservices', {
                'name':           issuer_name,
                'DID':            self.issuer_did,
                'issuerOrgTLA':   issuer_abbr,
                'issuerOrgURL':   issuer_url,
                'effectiveDate':  current_date(),
                'jurisdictionId': self.jurisdiction_id
            })
            self.issuer_service_id = issuer_service['id']
        return self.issuer_service_id

    def sync_claim_types(self):
        if not self.issuer_service_id:
            raise ValueError("Cannot sync claim types: issuer_service_id not populated")
        claim_type_specs = self.config.get('claim_types')
        if not claim_type_specs:
            raise ValueError("Missing claim_types")
        issuer_url = self.config.get('url', '')

        # Register in TheOrgBook
        # Check if my schema record exists by claimType
        claim_types = self.fetch_list('verifiableclaimtypes')
        for type_spec in claim_type_specs:
            schema_def = type_spec['schema']
            for claim_type in claim_types:
                claim_type_exists = False
                if claim_type['schemaName'] == schema_def['name'] and \
                        claim_type['schemaVersion'] == schema_def['version'] and \
                        claim_type['issuerServiceId'] == self.issuer_service_id:
                    claim_type_exists = True
                    break
            if not claim_type_exists:
                self.create_record('verifiableclaimtypes', {
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

    def fetch_list(self, module):
        url = self.get_api_url(module)
        return requests.get(url).json()

    def create_record(self, module, data):
        url = self.get_api_url(module)
        response = requests.post(url, json=data)
        if response.status_code != 200 and response.status_code != 201:
            raise RuntimeError("Bad response ({}) from create_record: {}".format(
                response.status_code, response.text))
        return response.json()

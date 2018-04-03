#! /usr/local/bin/python3
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

#
# "requests" must be installed - pip3 install requests
#

import asyncio
import json
import os
import sys

import aiohttp

AGENT_URL = os.environ.get('AGENT_URL', 'http://localhost:5000')

if len(sys.argv) < 2:
    raise ValueError("Expected JSON file path(s)")
CLAIM_PATHS = sys.argv[1:]

async def submit_claim(http_client, claim_path):
    with open(claim_path) as claim_file:
        claim = json.load(claim_file)
    if not claim:
        raise ValueError('Claim could not be parsed')
    schema = claim.get('schema')
    if not schema:
        raise ValueError('No schema defined')
    version = claim.get('version', '')
    attrs = claim.get('attributes')
    if not attrs:
        raise ValueError('No schema attributes defined')

    print('Submitting claim {}'.format(claim_path))

    try:
        response = await http_client.post(
            '{}/submit-claim'.format(AGENT_URL),
            params={'schema': schema, 'version': version},
            json=attrs
        )
        if response.status != 200:
            raise RuntimeError(
                'Claim could not be processed: {}'.format(await response.text())
            )
        result_json = await response.json()
    except Exception as exc:
        raise Exception(
            'Could not submit claim. '
            'Are von-x and TheOrgBook running?') from exc

    print('Response from von-x:\n\n{}\n'.format(result_json))

async def submit_all(claim_paths):
    async with aiohttp.ClientSession() as http_client:
        for claim_path in claim_paths:
            await submit_claim(http_client, claim_path)

asyncio.get_event_loop().run_until_complete(submit_all(CLAIM_PATHS))

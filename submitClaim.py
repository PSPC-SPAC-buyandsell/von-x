#! /usr/local/bin/python3
#
# Copyright 2017-2018 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca
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

import json
import os
import requests
import sys

agent_url = os.environ.get('AGENT_URL', 'http://localhost:5000')

if len(sys.argv) < 2:
    raise ValueError("Expected JSON file path(s)")
claim_paths = sys.argv[1:]

def submit_claim(claim_path):
    with open(claim_path) as f:
        claim = json.load(f)
        if not claim:
            raise ValueError('Claim could not be parsed')
        schema = claim.get('schema')
        if not schema:
            raise ValueError('No schema defined')
        version = claim.get('version')
        attrs = claim.get('attributes')
        if not attrs:
            raise ValueError('No schema attributes defined')

        print('Submitting claim {}'.format(claim_path))

        try:
            response = requests.post(
                '{}/submit-claim'.format(agent_url),
                params={'schema': schema, 'version': version},
                json=attrs
            )
            if response.status_code != 200:
                raise RuntimeError('Claim could not be processed: {}'.format(response.text))
            result_json = response.json()
        except Exception as e:
            raise Exception(
                'Could not submit claim. '
                'Are von-x and TheOrgBook running?') from e

        print('Response from von-x:\n\n{}\n'.format(result_json))

for claim_path in claim_paths:
    submit_claim(claim_path)


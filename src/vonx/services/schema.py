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

from distutils.version import LooseVersion
from typing import Mapping, Sequence


class Schema:
    def __init__(self, name, version, attributes=None):
        self.name = name
        self.version = version
        self._attributes = []
        if attributes:
            self.attributes = attributes

    @property
    def attributes(self):
        return self._attributes.copy()

    @attributes.setter
    def attributes(self, value):
        self._attributes = []
        if isinstance(value, Mapping):
            for name, attr in value.items():
                self.add_attribute(attr, name)
        elif isinstance(value, Sequence):
            for attr in value:
                self.add_attribute(attr)
        else:
            raise ValueError('Unsupported type for attributes: {}'.format(value))

    @property
    def attr_names(self):
        return tuple(attr['name'] for attr in self._attributes)

    def add_attribute(self, attr, name=None):
        if isinstance(attr, Mapping):
            if name is not None:
                attr['name'] = name
            self._attributes.append(attr)
        elif isinstance(attr, str):
            attr = {'name': attr}
            self._attributes.append(attr)
        elif attr is None and name:
            self._attributes.append({'name': name})
        else:
            raise ValueError('Unsupported type for attribute: {}'.format(attr))

    def validate(self, value):
        pass

    def __repr__(self):
        return 'Schema(name={}, version={})'.format(self.name, self.version)


class SchemaManager:
    def __init__(self):
        self._schemas = []

    @property
    def schemas(self):
        return self._schemas.copy()

    def add_schema(self, schema, override=False):
        if not isinstance(schema, Schema):
            if not isinstance(schema, Mapping):
                raise ValueError('Unsupported type for schema: {}'.format(schema))
            name = schema.get('name')
            if not name:
                raise ValueError('Missing schema name')
            schema = Schema(name, schema.get('version'), schema.get('attributes'))
        found = self.find(schema.name, schema.version)
        if found:
            if override:
                self.remove_schema(found)
            else:
                raise ValueError('Duplicate schema definition: {}'.format(schema))
        self._schemas.append(schema)

    def remove_schema(self, schema, version=None):
        if isinstance(schema, str):
            schema = self.find(schema, version)
        self._schemas.remove(schema)

    def load(self, values: Sequence, override=False):
        for spec in values:
            self.add_schema(spec, override)

    def find(self, name, version=None):
        found = None
        for schema in self._schemas:
            if schema.name == name:
                if version is not None:
                    if schema.version == version:
                        found = schema
                        break
                else:
                    if found is None or LooseVersion(found.version) < LooseVersion(schema.version):
                        found = schema
        return found

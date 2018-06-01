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
    """
    A credential schema definition
    """

    def __init__(self, name, version, attributes=None, issuer_did=None):
        self.name = name
        self.version = version
        self._attributes = []
        if attributes:
            self.attributes = attributes
        self.issuer_did = issuer_did

    @property
    def attributes(self) -> list:
        """
        Accessor for the extended schema attributes list

        Returns:
            a copy of the schema attributes
        """
        return self._attributes.copy()

    @attributes.setter
    def attributes(self, value) -> None:
        """
        Setter for the schema attributes list
        """
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
    def attr_names(self) -> list:
        """
        Accessor for the schema attribute names

        Returns:
            the attribute names only
        """
        return tuple(attr['name'] for attr in self._attributes)

    def add_attribute(self, attr, name=None) -> None:
        """
        Add an attribute to the schema including optional type information

        Args:
            attr: a dict or str representing the attribute
            name: the name of the attribute
        """
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

    def copy(self) -> 'Schema':
        """
        Create a copy of this :class:`Schema` instance
        """
        return Schema(self.name, self.version, self._attributes)

    def validate(self, value) -> None:
        """
        Perform validation of a set of attribute values against the schema
        """
        pass

    def compare(self, schema: 'Schema') -> bool:
        """
        Check whether this schema instance and another are compatible.
        Note: schemas with an empty issuer DID will match schemas with a blank issuer DID,
        or the same DID
        """
        if self.name == schema.name and self.version == schema.version:
            if not self.issuer_did or not schema.issuer_did or self.issuer_did == schema.issuer_did:
                if not self.attributes or not schema.attributes \
                        or self.attributes == schema.attributes:
                    return True
        return False

    def __repr__(self) -> str:
        return 'Schema(name={}, version={})'.format(self.name, self.version)


class SchemaManager:
    """
    A manager class for handling a set of loaded credential schema definitions
    """

    def __init__(self):
        self._schemas = []

    @property
    def schemas(self) -> list:
        """
        An accessor for the list of all loaded schemas
        """
        return self._schemas.copy()

    def add_schema(self, schema, override=False) -> None:
        """
        Add a schema to the manager

        Args:
            schema: a Schema or dict instance
            override: replace an existing schema if any
        """
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

    def remove_schema(self, schema, version=None) -> None:
        """
        Remove an existing schema from the manager

        Args:
            schema: the schema name
            version: the schema version
        """
        if isinstance(schema, str):
            schema = self.find(schema, version)
        self._schemas.remove(schema)

    def load(self, values: Sequence, override=False) -> None:
        """
        Load a list of schemas and add each to the manager

        Args:
            values: the list of schema definitions
            override: replace existing defined schemas of the same name and version
        """
        for spec in values:
            self.add_schema(spec, override)

    def find(self, name, version=None) -> Schema:
        """
        Locate a defined schema

        Args:
            name: the schema name
            version: the schema version

        Returns:
            the located Schema instance, if any
        """
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

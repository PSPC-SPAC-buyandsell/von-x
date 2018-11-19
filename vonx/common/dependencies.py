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
This module provides a dependency graph data structure and related utility functions
for managing credential dependencies.
"""

from networkx import DiGraph
from networkx.readwrite import json_graph
from networkx.algorithms.cycles import find_cycle
from networkx.exception import NetworkXNoCycle


class CredentialDependencyError(Exception):
    """
    Base class for all exceptions thrown by :class:`CredentialDependency`
    """

    pass


class EdgeAlreadyExistsError(CredentialDependencyError):
    pass


class NoSelfLoopsError(CredentialDependencyError):
    pass


class CantResolveDidError(CredentialDependencyError):
    pass


class CantConnectToEndpointError(CredentialDependencyError):
    pass


class BadResponseError(CredentialDependencyError):
    pass


class CircularDependencyError(CredentialDependencyError):
    pass


class CredentialDependencyGraph(DiGraph):
    """
    A directed acyclic graph that represents the dependency relationships
    of a group of credentials. A light wrapper around the graph data structure
    library networkx
    """

    def __init__(self, graph_data=None):
        if graph_data:
            graph = self.deserialize(graph_data)
            super().__init__(graph)
        else:
            super().__init__()

    def add_edge(self, node_a, node_b, detect_cycles=True):
        """
        Overrides add_edge method to add
        extra meta data to each node
        """

        if node_a.id == node_b.id:
            raise NoSelfLoopsError()

        if (node_a.id, node_b.id) in self.edges:
            raise EdgeAlreadyExistsError()

        if detect_cycles:
            current_graph = self
            current_graph.add_edge(node_a, node_b, False)
            try:
                cycle = find_cycle(current_graph)
                cycle_strs = ["{} -> {}".format(link[0], link[1]) for link in cycle]
                raise CircularDependencyError(
                    "Circular dependency detected: {}".format(", ".join(cycle_strs))
                )
            except NetworkXNoCycle:
                pass

        self.add_node(node_a.id, **node_a.node_data)
        self.add_node(node_b.id, **node_b.node_data)
        super().add_edge(node_a.id, node_b.id)

    def annotate_edge(self, node_a, node_b, **kwargs):
        """
        Overrides add_edge method to add
        extra meta data to each node
        """

        for argname, argval in kwargs.items():
            self.edges[(node_a.id, node_b.id)][argname] = argval

    def serialize(self):
        """
        Returns a json representation of the graph
        """
        data = json_graph.node_link_data(self)
        del data["directed"]
        del data["multigraph"]
        del data["graph"]
        return data

    def deserialize(self, graph_data):
        """
        Instantiates a new graph object from json
        """
        graph_data["directed"] = True
        graph_data["multigraph"] = False
        graph_data["graph"] = {}
        graph = json_graph.node_link_graph(graph_data)
        return graph

    def clear_root(self):
        """
        Clears the 'root' node for this graph
        """
        for node in self.nodes:
            self.nodes[node]["root"] = False

    def set_root(self, node):
        """
        Sets the 'root' node for this graph.
        This value doubles as a distributed pointer
        for context as the graph propogates through the network.
        """
        self.nodes[node.id]["root"] = True

    def get_root(self):
        """
        Returns the 'root' node for this graph.
        This value doubles as a distributed pointer
        for context as the graph propogates through the network.
        """
        for node_id in self.nodes:
            node = self.nodes[node_id]
            try:
                if node["root"] is True:
                    return CredentialDependency(
                        node["schema_name"], node["schema_version"], node["origin_did"]
                    )
            except KeyError:
                pass

        raise CredentialDependencyError("This graph does not have a root!")


class CredentialDependency:
    """
    A hashable class representing a credential dependency.
    It is aware of its place in a graph of dependencies.
    """

    def __init__(self, schema_name, schema_version, origin_did, graph_data=None):
        self._schema_name = schema_name
        self._schema_version = schema_version
        self._origin_did = origin_did
        self._graph = CredentialDependencyGraph(graph_data)

        if graph_data and self.id not in self.graph:
            raise CredentialDependencyError(
                "Existing graph provided but the credential dependency represented by"
                "{}, {}, {} is not in graph.".format(
                    schema_name, schema_version, origin_did)
            )

        self.graph.add_node(self.id, **self.node_data)
        self.graph.clear_root()
        self.graph.set_root(self)

    @property
    def graph(self):
        """
        Accessor for dependency graph
        """
        return self._graph

    @property
    def schema_name(self):
        """
        Accessor for schema_name
        """
        return self._schema_name

    @property
    def schema_version(self):
        """
        Accessor for schema_version
        """
        return self._schema_version

    @property
    def origin_did(self):
        """
        Accessor for origin_did
        """
        return self._origin_did

    @property
    def id(self):
        """
        Returns a unique id for this credential
        """
        return ":".join(
            tuple(
                x for x in (self.schema_name, self.schema_version, self.origin_did) if x
            )
        )

    @property
    def node_data(self):
        """
        Get data to be stored in the graph node
        """
        return {
            "schema_name": self.schema_name,
            "schema_version": self.schema_version,
            "origin_did": self.origin_did,
        }

    def add_dependency(self, dependency):
        """
        Adds a new dependency from this credential to the provided credential
        """
        self.graph.add_edge(self, dependency)

    def __str__(self):
        return "{}({})".format(self.__class__.__name__, self.__dict__)

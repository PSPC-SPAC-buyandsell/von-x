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
Methods for loading and working with our standard YAML-based configuration files
"""

import logging
import os
import re
from typing import Callable, Mapping, TextIO

import pkg_resources
import yaml


def load_resource(path: str) -> TextIO:
    """
    Open a resource file located in a python package or the local filesystem

    Args:
        path (str): The resource path in the form of `dir/file` or `package:dir/file`
    Returns:
        A file-like object representing the resource
    """
    components = path.rsplit(':', 1)
    if len(components) == 1:
        return open(components[0])
    return pkg_resources.resource_stream(components[0], components[1])


def load_settings(env=True) -> dict:
    """
    Loads the application settings from several sources:

        - settings.yml
        - an optional application settings file defined by SETTINGS_PATH
        - custom environment settings defined by ENVIRONMENT (ie. dev, prod)
        - enviroment variable overrides

    Args:
        env: A dict of environment variables, or the value True to inherit the global
            environment
    Returns:
        A combined dictionary of setting values
    """
    if env is True:
        env = os.environ
    elif not env:
        env = {}
    env_name = os.environ.get('ENVIRONMENT', 'default')

    settings = {}

    # Load default settings
    with load_resource('vonx.config:settings.yml') as resource:
        cfg = yaml.load(resource)
        if 'default' not in cfg:
            raise ValueError('Default settings not found in settings.yml')
        settings.update(cfg['default'])
        if env_name != 'default' and env_name in cfg:
            settings.update(cfg[env_name])

    # Load application settings
    ext_path = os.environ.get('SETTINGS_PATH')
    if not ext_path:
        config_root = os.environ.get('CONFIG_ROOT', os.curdir)
        ext_path = os.path.join(config_root, 'settings.yml')
    with load_resource(ext_path) as resource:
        ext_cfg = yaml.load(resource)
        if 'default' in ext_cfg:
            settings.update(ext_cfg['default'])
        if env_name != 'default':
            if env_name not in ext_cfg:
                raise ValueError(
                    'Environment not defined by application settings: {}'.format(env_name))
            settings.update(ext_cfg[env_name])

    # Inherit environment variables
    for k, v in env.items():
        if v is not None and v != '':
            settings[k] = v

    # Expand variable references
    for k, v in settings.items():
        if isinstance(v, str):
            settings[k] = expand_string_variables(v, settings)

    return settings


def load_config(path: str, env=None):
    """
    Load a YAML config file and replace variables from the environment

    Args:
        path (str): The resource path in the form of `dir/file` or `package:dir/file`
    Returns:
        The configuration tree with variable references replaced, or `False` if the
        file is not found
    """
    try:
        with load_resource(path) as resource:
            cfg = yaml.load(resource)
    except FileNotFoundError:
        return False
    cfg = expand_tree_variables(cfg, env or os.environ)
    return cfg


def expand_string_variables(value, env: Mapping, warn: bool = True):
    """
    Expand environment variables of form `$var` and `${var}` in a string

    Args:
        value (str): The input value
        env (Mapping): The dictionary of environment variables
        warn (bool): Whether to warn on references to undefined variables
    Returns:
        The transformed string
    """
    if not isinstance(value, str):
        return value
    def _replace_var(matched):
        default = None
        var = matched.group(1)
        if matched.group(2):
            var = matched.group(2)
            default = matched.group(4)
        found = env.get(var)
        if found is None or found == '':
            found = default
        if found is None and warn:
            logging.getLogger(__name__).warning('Configuration variable not defined: %s', var)
            found = ''
        return found
    return re.sub(r'\$(?:(\w+)|\{([^}]*?)(:-([^}]*))?\})', _replace_var, value)


def map_tree(tree, map_fn: Callable):
    """
    Map one tree to another using a transformation function

    Args:
        tree: A sequence, mapping or other value
        map_fn (Callable): The function to apply to each node, returing the new value
    Returns:
        The transformed tree
    """
    if isinstance(tree, Mapping):
        return {key: map_tree(value, map_fn) for (key, value) in tree.items()}
    if isinstance(tree, (list, tuple)):
        return [map_tree(value, map_fn) for value in tree]
    return map_fn(tree)


def expand_tree_variables(tree, env: Mapping, warn: bool = True):
    """
    Expand environment variables of form `$var` and `${var}` in a configuration tree.
    This is used to allow variable insertion in issuer and route definitions

    Args:
        tree: A sequence, mapping or other value
        env (Mapping): The dictionary of environment variables
        warn (bool): Whether to warn on references to undefined variables
    Returns:
        The transformed tree
    """
    return map_tree(tree, lambda val: expand_string_variables(val, env, warn))

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
import os
import re
import yaml

import pkg_resources


def load_resource(path: str):
    """Open a resource file located in a python package or the local filesystem"""
    components = path.rsplit(':', 1)
    if len(components) == 1:
        return open(components[0])
    return pkg_resources.resource_stream(components[0], components[1])


def load_settings(env=True):
    """
    Load the application settings from several sources:
        - settings.yml
        - an optional application settings file defined by SETTINGS_PATH
        - custom environment settings defined by ENVIRONMENT (ie. dev, prod)
        - enviroment variable overrides
    """
    if env is True:
        env = os.environ
    elif not env:
        env = {}
    env_name = os.environ.get('ENVIRONMENT', 'default')

    settings = {}

    # Load default settings
    with load_resource('app.config:settings.yml') as resource:
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
    """
    try:
        with load_resource(path) as resource:
            cfg = yaml.load(resource)
    except FileNotFoundError:
        return False
    cfg = expand_tree_variables(cfg, env or os.environ)
    return cfg


def expand_string_variables(value, env, warn=True):
    """
    Expand environment variables of form $var and ${var} in a string.
    """
    if not isinstance(value, str):
        return value
    def replace_var(matched):
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
    return re.sub(r'\$(?:(\w+)|\{([^}]*?)(:-([^}]*))?\})', replace_var, value)


def map_tree(tree, map_fn):
    if isinstance(tree, dict):
        return {key: map_tree(value, map_fn) for (key, value) in tree.items()}
    if isinstance(tree, (list, tuple)):
        return [map_tree(value, map_fn) for value in tree]
    return map_fn(tree)


def expand_tree_variables(tree, env, warn=True):
    """
    Expand environment variables of form $var and ${var} in a configuration tree.
    This is used in the 'issuers' section of the config to allow variable overrides.
    """
    return map_tree(tree, lambda val: expand_string_variables(val, env, warn))

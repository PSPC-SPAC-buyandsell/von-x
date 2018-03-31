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


def load_global_config(path=None):
    """Load the application config file."""
    if not path:
        app_path = os.path.dirname(__file__)
        path = os.environ.get('CONFIG_PATH', os.path.join(app_path, '..', 'config.yaml'))
    # Load the config file
    with open(path) as config_file:
        global_config = yaml.load(config_file)
    return global_config or {}

def load_server_config(global_config, env=True):
    """
    Extract the server configuration from the app config and apply optional
    overrides from the environment.
    """
    if env is True:
        env = os.environ
    elif not env:
        env = {}
    env_name = env.get('ENVIRONMENT', 'default').lower()
    if 'server' not in global_config or env_name not in global_config['server']:
        raise ValueError("Environment not defined by application config: {}".format(env_name))
    config = global_config['server'][env_name]
    # Inherit environment variables
    for k, v in env.items():
        if v != '':
            config[k] = v
    return config

def load_logging_config(global_config, logging_env=None):
    """Initialize the application logger using dictConfig."""
    if not global_config:
        return False
    if not logging_env:
        logging_env = 'default'
    log_config = None
    if 'logging' in global_config:
        if logging_env in global_config['logging']:
            log_config = global_config['logging'][logging_env]
        else:
            print("Logger not defined: {}".format(logging_env))
    else:
        print("No loggers defined by application config")
    return log_config

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

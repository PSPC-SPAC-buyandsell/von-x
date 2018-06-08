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
from typing import Mapping

from . import config, indy, issuer, manager, prover, schema

LOGGER = logging.getLogger(__name__)


class StandardServiceManager(manager.ServiceManager):
    """
    A standard :class:`ServiceManager` which starts the Indy ledger manager and
    related services
    """

    def __init__(self, env: Mapping = None):
        self._schema_mgr = None
        self._services_cfg = None
        super(StandardServiceManager, self).__init__(env)

    def _init_services(self) -> None:
        super(StandardServiceManager, self)._init_services()

        self._load_schemas()

        # Indy ledger - handles all ledger interactions
        self.add_service('ledger', self.init_indy_ledger())

        # Issuer manager - handles credential issuing
        self.add_service('issuer', self.init_issuer_manager())

        # Prover manager - handles proof construction and verification
        self.add_service('prover', self.init_prover_manager())

    @property
    def config_root(self) -> str:
        """
        Accessor for the value of the CONFIG_ROOT setting, defaulting to the current directory
        """
        return self._env.get('CONFIG_ROOT') or os.curdir

    def load_config_path(self, settings_key, default_path, env=None) -> dict:
        """
        Load a YAML configuration file with defined variables replaced in the result

        Args:
            settings_key: the name of an environment variable defining an alternative
                configuration path
            default_path: the default path to the configuration file

        Returns:
            the parsed YAML configuration with variables replaced
        """
        path = self._env.get(settings_key)
        if not path:
            path = os.path.join(self.config_root, default_path)
        return config.load_config(path, env or self._env)

    def services_config(self, section: str) -> dict:
        """
        Load a named section from the global services.yml configuration

        Args:
            section: the configuration key
        """
        if self._services_cfg is None:
            self._services_cfg = self.load_config_path('SERVICES_CONFIG_PATH', 'services.yml')
        if self._services_cfg:
            return self._services_cfg.get(section) or {}
        return {}

    def _load_schemas(self) -> None:
        """
        Load any standard and custom schemas into our SchemaManager
        """
        self._schema_mgr = schema.SchemaManager()
        std = config.load_config('vonx.config:schemas.yml')
        if std:
            self._schema_mgr.load(std)
        ext = self.load_config_path('SCHEMAS_CONFIG_PATH', 'schemas.yml')
        if ext:
            self._schema_mgr.load(ext)

    @property
    def schema_manager(self) -> schema.SchemaManager:
        """
        Accessor for the SchemaManager defined by this ServiceManager
        """
        return self._schema_mgr

    def init_indy_ledger(self, pid: str = "indy-ledger") -> indy.IndyLedger:
        """
        Initialize the Hyperledger Indy service

        Args:
            pid: the identifier for the :class:`IndyLedger` service
        """
        genesis_path = self._env.get("INDY_GENESIS_PATH")
        if not genesis_path:
            raise ValueError(
                "Indy genesis transaction path (INDY_GENESIS_PATH) not defined"
            )
        ledger_url = self._env.get("INDY_LEDGER_URL")
        if not ledger_url:
            raise ValueError("INDY_LEDGER_URL not defined")

        spec = {
            "auto_register": self._env.get("AUTO_REGISTER_DID", 1),
            "genesis_path": genesis_path,
            "ledger_url": ledger_url,
        }
        LOGGER.info("Initializing Indy ledger service")
        return indy.IndyLedger(pid, self._exchange, self._env, spec)

    def init_issuer_manager(self, pid: str = "issuer-manager") -> issuer.IssuerManager:
        """
        Initialize a standard :class:`IssuerManager` instance

        Args:
            pid: the identifier for the :class:`IssuerManager` service
        """

        issuers = []
        issuer_ids = []
        limit_issuers = self._env.get("ISSUERS")
        limit_issuers = (
            limit_issuers.split()
            if (limit_issuers and limit_issuers != "all")
            else None
        )
        config_issuers = self.services_config("issuers")
        if not config_issuers:
            raise ValueError("No issuers defined by configuration")
        for issuer_key, issuer_cfg in config_issuers.items():
            if not "id" in issuer_cfg:
                issuer_cfg["id"] = issuer_key
            if limit_issuers is None or issuer_cfg["id"] in limit_issuers:
                issuers.append(issuer_cfg)
                issuer_ids.append(issuer_cfg["id"])
        if issuers:
            LOGGER.info(
                "Initializing processor for services: %s",
                ", ".join(issuer_ids),
            )
            mgr = issuer.IssuerManager(pid, self._exchange, self._env)
            for issuer_cfg in issuers:
                if "api_url" not in issuer_cfg:
                    issuer_cfg["api_url"] = self._env.get("TOB_API_URL")
                svc = issuer.IssuerService(issuer_cfg, self.schema_manager)
                mgr.add_issuer(svc)
            return mgr
        else:
            raise ValueError("No defined issuers referenced by ISSUERS")

    def init_prover_manager(self, pid: str = 'prover-manager') -> prover.ProverManager:
        """
        Create an instance of the :class:`ProverManager`, loading the defined configuration
        from the :class:`ServiceManager` instance

        Args:
            pid: the identifier for the :class:`ProverManager` service
        """
        config_requests = self.services_config('proof_requests')
        LOGGER.info('Initializing proof request manager')
        return prover.ProverManager(pid, self._exchange, self._env, config_requests)

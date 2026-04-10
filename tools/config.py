# pylint: disable=E1101,E0203,C0103
#
#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Config """

import json
from pylon.core.tools import log  # pylint: disable=E0401
from ..patterns import SingletonABC


class Config(metaclass=SingletonABC):  # pylint: disable=R0903
    """ Config singleton """

    def __init__(self, module):
        module_cfg = module.descriptor.config
        self.load_settings(
            module_cfg.get("settings", {}),
            (
                # Currently only used in carrier-io/ui_performance · constants.py
                ("LOCAL_DEV", "bool", False),
                # Used in carrier-io/secrets · module.py
                # If set to False - overrides secrets with default ones on startup
                ("PERSISTENT_SECRETS", "bool", True),
                # Sets runtime container tags e.g. in carrier-io/backend_performance · constants.py
                ("CURRENT_RELEASE", "str", "latest"),
                # Common mode names
                ("ADMINISTRATION_MODE", "str", "administration"),
                ("DEFAULT_MODE", "str", "default"),
                # Used in carrier-io/backend_performance e.g. in connectors/minio_connector.py
                ("MAX_DOTS_ON_CHART", "int", 100),
                # Stored in secrets, used in carrier-io/backend_performance · api/v1/retention.py
                ("BACKEND_PERFORMANCE_RESULTS_RETENTION", "int", 30),   # in days
                # Used in carrier-io/tasks · utils.py
                ("BUCKET_RETENTION_DAYS", "int", 7),
                # Used in carrier-io/secrets · module.py to set influx_ip and rabbit_host
                # TODO: specify EXTERNAL_REDIS_HOST and others explicitly
                ("APP_IP", "str", None),
                # Used to set URLs; galloper_url in carrier-io/secrets · module.py
                ("APP_HOST", "str", None),
                # Only used in carrier-io/shared · tools/loki_tools.py;
                # also use in centry_gaid cookie secure flag
                ("APP_SCHEME", "str", "http"),
                # Used in auth to set CORS headers
                ("ALLOW_CORS", "bool", False),
                # Sets arbiter eventnode type for tasks
                ("ARBITER_RUNTIME", "str", "rabbitmq"),
                # Sets eventnode processing threads for tasknode and such
                ("EVENT_NODE_WORKERS", "int", 1),
                # Used to create redis clients. E.g. in carrier-io/projects · rpc/main.py
                ("REDIS_HOST", "str", "centry-redis"),
                ("REDIS_PORT", "int", 6379),
                ("REDIS_USER", "str", ""),
                ("REDIS_PASSWORD", "str", ""),
                # Only seems to be used in old code: carrier-io/carrier-auth · auth/utils/redis_client.py  # pylint: disable=C0301
                ("REDIS_DB", "int", 2),
                # Used in carrier-io/projects · rpc/main.py and others
                ("REDIS_RABBIT_DB", "int", 4),
                ("REDIS_CHAT_CANVAS_DB", "int", 6),
                # For arbiter/eventnodes
                ("REDIS_USE_SSL", "bool", False),
                # Used in some places, other use data from secrets - which maps to APP_IP
                ("RABBIT_HOST", "str", None),
                ("RABBIT_PORT", "int", 5672),
                ("RABBIT_USER", "str", ""),
                ("RABBIT_PASSWORD", "str", ""),
                ("RABBIT_ADMIN_URL", "str", "http://carrier-rabbit:15672"),
                # Used in carrier-io/tasks · tools/TaskManager.py
                ("RABBIT_QUEUE_NAME", "str", "default"),
                ("RABBIT_USE_SSL", "bool", False),
                ("RABBIT_SSL_VERIFY", "bool", False),
                # Stored in carrier-io/secrets · module.py
                # Used in performance and carrier-io/projects · tools/influx_tools.py
                # TODO: set INFLUX_ENABLED/USE_INFLUX and others
                # FIXME: set influx_host from INFLUX_HOST, not APP_IP
                ("INFLUX_PORT", "int", 8086),
                ("INFLUX_USER", "str", ""),
                ("INFLUX_PASSWORD", "str", ""),
                # Stored in secrets used in multiple places
                ("LOKI_HOST", "str", {"APP_HOST"}),
                ("LOKI_HOST_INTERNAL", "str", "http://carrier-loki"),
                ("LOKI_PORT", "int", 3100),
                # Used in carrier-io/s3_integration · module.py and shared
                ("MINIO_URL", "str", "http://carrier-minio:9000"),
                ("MINIO_ACCESS_KEY", "str", ""),
                ("MINIO_ACCESS", "str", {"MINIO_ACCESS_KEY"}),
                ("MINIO_SECRET_KEY", "str", ""),
                ("MINIO_SECRET", "str", {"MINIO_SECRET_KEY"}),
                ("MINIO_REGION", "str", "us-east-1"),
                # Used in carrier-io/shared · tools/vault_tools.py
                ("VAULT_URL", "str", "http://carrier-vault:8200"),
                ("VAULT_DB_PK", "int", 1),
                ("VAULT_ADMINISTRATION_NAME", "str", {"ADMINISTRATION_MODE"}),
                # Used in shared and carrier-io/shared_orch · utils.py
                # TODO: remove shared_orch
                ("DATABASE_VENDOR", "str", "postgres"),
                ("POSTGRES_HOST", "str", "centry-postgres"),
                ("POSTGRES_PORT", "int", 5432),
                ("POSTGRES_USER", "str", ""),
                ("POSTGRES_PASSWORD", "str", ""),
                ("POSTGRES_DB", "str", "centry"),
                ("POSTGRES_SCHEMA", "str", "centry"),
                ("POSTGRES_TENANT_SCHEMA", "str", "tenant"),
                # Only for some tests
                ("SQLITE_DB", "str", "sqlite.db"),
                # Transitional for context.db != sqlite RAM
                ("FORCE_INJECT_DB", "bool", False),
                # Used in carrier-io/projects · tools/session_plugins.py
                ("PROJECT_CACHE_PLUGINS", "str", "PROJECT_CACHE_PLUGINS"),
                # Used in carrier-io/projects · tools/session_project.py
                ("PROJECT_CACHE_KEY", "str", "PROJECT_CACHE_KEY"),
                # Used in carrier-io/shared · tools/db.py and carrier-io/projects · module.py
                ("DATABASE_URI", "str", None),
                ("DATABASE_ENGINE_OPTIONS", "dict", None),
                # Used in tools/data_tools/files.py
                ("TASKS_UPLOAD_FOLDER", "str", "/tmp/tasks"),
                # New arbiter EventNode types
                ("SIO_URL", "str", ""),
                ("SIO_PASSWORD", "str", ""),
                ("SIO_SSL_VERIFY", "bool", False),
                # Transitional (next, new, NG+) settings
                ("CENTRY_USE_INFLUX", "bool", False),
                ("SECRETS_ENGINE", "str", "managed_vault"),
                ("SECRETS_MASTER_KEY", "str", None),
                ("SECRETS_FILESYSTEM_PATH", "str", "/tmp/secrets"),
                ("STORAGE_ENGINE", "str", "s3"),
                ("STORAGE_FILESYSTEM_PATH", "str", "/tmp/storage"),
                ("STORAGE_FILESYSTEM_ENCODER", "str", "base64"),
                ("STORAGE_LIBCLOUD_DRIVER", "str", "LOCAL"),
                ("STORAGE_LIBCLOUD_PARAMS", "any", {"kwargs": {"key": "/tmp/storage"}}),
                ("STORAGE_LIBCLOUD_ENCODER", "str", None),
                ("NO_GROUP_NAME", "str", 'no-group'),
            )
        )
        #
        # Fix redis password
        #
        if self.REDIS_PASSWORD is None:
            self.REDIS_PASSWORD = ""
        #
        # Make DB URI if not set
        #
        if self.DATABASE_ENGINE_OPTIONS is None:
            self.DATABASE_ENGINE_OPTIONS = {}
        #
        if self.DATABASE_URI is None:
            if self.DATABASE_VENDOR == "sqlite":  # Probably is not supported with tenant schemas now  # pylint: disable=C0301
                self.DATABASE_URI = f"sqlite:///{self.SQLITE_DB}"
                self.DATABASE_ENGINE_OPTIONS["isolation_level"] = "SERIALIZABLE"
            elif self.DATABASE_VENDOR == "postgres":
                self.DATABASE_URI = 'postgresql://{username}:{password}@{host}:{port}/{database}'.format(  # pylint: disable=C0301
                    host=self.POSTGRES_HOST,
                    port=self.POSTGRES_PORT,
                    username=self.POSTGRES_USER,
                    password=self.POSTGRES_PASSWORD,
                    database=self.POSTGRES_DB
                )
                if not self.DATABASE_ENGINE_OPTIONS:
                    self.DATABASE_ENGINE_OPTIONS = {
                        "isolation_level": "READ COMMITTED",
                        "echo": False,
                        "pool_size": 25,
                        "max_overflow": 25,
                        "pool_pre_ping": True
                    }
            else:
                raise RuntimeError(f"Unsupported DB vendor: {self.DATABASE_VENDOR}")
        #
        log.info('Initialized config %s', self)

    def load_settings(self, settings, schema):
        """ Load and set config vars """
        processors = {
            "str": lambda item: item if isinstance(item, str) else str(item),
            "int": lambda item: item if isinstance(item, int) else int(item),
            "bool": lambda item: item if isinstance(item, bool) else item.lower() in ["true", "yes"],  # pylint: disable=C0301
            "dict": lambda item: item if isinstance(item, dict) else json.loads(item),
        }
        #
        for item in schema:
            if len(item) == 3:
                key, kind, default = item
            elif len(item) == 2:
                key, kind = item
                default = ...
            else:
                raise RuntimeError(f"Invalid config schema: {item}")
            #
            if isinstance(default, set):
                default = getattr(self, list(default)[0])
            #
            data = ...
            for variant in [key, key.lower(), key.upper()]:
                if variant in settings:
                    data = settings[variant]
            #
            if data is ... and default is ...:
                raise RuntimeError(f"Required config value is not set: {key}")
            #
            if data is ...:
                data = default
            elif kind in processors:
                data = processors[kind](data)
            #
            setattr(self, key, data)

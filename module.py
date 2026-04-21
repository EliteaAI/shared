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

""" Module """

import logging

from pylon.core.tools import module, log  # pylint: disable=E0611,E0401


class Module(module.ModuleModel):
    """ Galloper module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        self.db = None
        self.mongo = None
        self.job_type_rpcs = set()
        #
        self.module_tables = {}
        self.original_add_table = None

    def preload(self):
        """ Preload handler """
        from pylon.core.tools.context import Context as Holder
        #
        noop_func = lambda *args, **kwargs: None
        noop_decorator = lambda *args, **kwargs: lambda func: func
        #
        dummy = Holder()
        #
        self.descriptor.register_tool('constants', dummy)
        self.descriptor.register_tool('db_migrations', dummy)
        self.descriptor.register_tool('VaultClient', dummy)
        self.descriptor.register_tool('MinioClient', dummy)
        #
        dummy_openapi_registry = Holder()
        dummy_openapi_registry.register_plugin = noop_func
        #
        self.descriptor.register_tool('openapi_registry', dummy_openapi_registry)
        #
        dummy_config = Holder()
        dummy_config.POSTGRES_SCHEMA = "dummy"
        dummy_config.POSTGRES_TENANT_SCHEMA = "dummy"
        dummy_config.FORCE_INJECT_DB = True
        dummy_config.DATABASE_URI = "duckdb:///:memory:"
        dummy_config.DATABASE_ENGINE_OPTIONS = {}
        dummy_config.DEFAULT_MODE = "dummy"
        dummy_config.VAULT_ADMINISTRATION_NAME = "dummy"
        dummy_config.SECRETS_ENGINE = "database"
        #
        self.descriptor.register_tool('config', dummy_config)
        #
        class dummy_class_a:
            def __init__(self, *args, **kwargs):
                pass
            #
            metadata = Holder()
            metadata.tables = {}
            metadata._add_table = lambda *args, **kwargs: None
            metadata._remove_table = lambda *args, **kwargs: None
            metadata.naming_convention = {}
            metadata._fk_memos = {
                ('dummy.project', 'id'): [],
                ('dummy.project_group', 'id'): [],
                ('dummy.application_versions', 'id'): [],
                ('dummy.tags', 'id'): [],
                ('dummy.prompt_versions', 'id'): [],
            }
        #
        dummy_db = Holder()
        dummy_db.Base = dummy_class_a
        #
        self.descriptor.register_tool('db', dummy_db)
        #
        class dummy_class_b:
            def __init__(self, *args, **kwargs):
                pass
            #
            __table__ = "dummy"
        #
        dummy_db_tools = Holder()
        dummy_db_tools.AbstractBaseMixin = dummy_class_b
        #
        self.descriptor.register_tool('db_tools', dummy_db_tools)
        #
        class dummy_class_c:
            def __init__(self, *args, **kwargs):
                pass
        #
        dummy_rpc_tools = Holder()
        dummy_rpc_tools.RpcMixin = dummy_class_c
        #
        self.descriptor.register_tool('rpc_tools', dummy_rpc_tools)
        #
        self.descriptor.register_tool('register_openapi', noop_decorator)
        self.descriptor.register_tool('serialize', noop_func)

    def init(self):
        """ Init module """

        log.info("Initializing module Shared")

        try:
            from pylon.core.tools.module.this import caller_module_name  # pylint: disable=E0401,E0611,C0415
            import sqlalchemy  # pylint: disable=E0401,C0415
            #
            self.context.manager.register_reload_hook(self._reload_hook)
            #
            def _wrap_metadata_add_table(original_add_table):
                _self = self
                _original_add_table = original_add_table
                #
                def _wrapped_metadata_add_table(self, name, schema, table):
                    module_name = caller_module_name(skip=2)
                    module_tables = _self.module_tables
                    #
                    if module_name not in module_tables:
                        module_tables[module_name] = []
                    #
                    if table not in module_tables[module_name]:
                        module_tables[module_name].append(table)
                    #
                    return _original_add_table(self, name, schema, table)
                #
                return _wrapped_metadata_add_table
            #
            self.original_add_table = sqlalchemy.MetaData._add_table  # pylint: disable=W0212
            sqlalchemy.MetaData._add_table = _wrap_metadata_add_table(  # pylint: disable=W0212
                sqlalchemy.MetaData._add_table  # pylint: disable=W0212
            )
        except:  # pylint: disable=W0702
            log.warning("Could not add reload hooks, skipping")

        from .tools.rpc_tools import RpcMixin, EventManagerMixin
        RpcMixin.set_rpc_manager(self.context.rpc_manager)
        EventManagerMixin.set_event_manager(self.context.event_manager)

        from .tools.config import Config
        _config = Config(self)
        from .tools.config_pydantic import TheConfig
        TheConfig.__old_config = _config
        self.descriptor.register_tool('constants', _config)
        self.descriptor.register_tool('config', _config)

        # from .tools.config import Config
        # self.descriptor.register_tool('config', Config())

        from .tools import rpc_tools, api_tools
        self.descriptor.register_tool('rpc_tools', rpc_tools)
        self.descriptor.register_tool('api_tools', api_tools)

        from .tools.loki_tools import LokiLogFetcher
        self.descriptor.register_tool('LokiLogFetcher', LokiLogFetcher)

        try:
            from .tools import db
            self.db = db
            self.descriptor.register_tool('db', db)

            from .tools import db_tools, db_migrations
            self.descriptor.register_tool('db_tools', db_tools)
            self.descriptor.register_tool('db_migrations', db_migrations)

            # self.context.app.config.from_object(self.config)
            from .init_db import init_db
            init_db()
        except Exception:  # pylint: disable=W0703
            log.warning("DB initialization skipped (database may not be configured on this pylon)")

        try:
            from .tools.minio_client import MinioClient
            self.descriptor.register_tool('MinioClient', MinioClient)
            logging.getLogger("botocore").setLevel(logging.INFO)
        except Exception:  # pylint: disable=W0703
            log.warning("MinioClient initialization skipped")

        from .tools.vault_tools import VaultClient
        self.descriptor.register_tool('VaultClient', VaultClient)
        try:
            VaultClient.init_vault()  # won't do anything if vault is not available
        except:  # pylint: disable=W0702
            log.exception("Vault failed to init, secrets WONT WORK")

        from .tools import data_tools
        self.descriptor.register_tool('data_tools', data_tools)

        from .tools.flow_tools import FlowNodes
        self.descriptor.register_tool('flow_tools', FlowNodes(self))

        self.init_filters()

        self.descriptor.register_tool('shared', self)

        from .tools.serialize import serialize
        self.descriptor.register_tool('serialize', serialize)

        from .tools.secret_field import SecretString
        self.descriptor.register_tool('SecretString', SecretString)

        from .tools.secret_field import store_secrets
        self.descriptor.register_tool('store_secrets', store_secrets)

        from .tools.secret_field import store_secrets_replaced
        self.descriptor.register_tool('store_secrets_replaced', store_secrets_replaced)

        from .tools.log_tools import prettify
        self.descriptor.register_tool('prettify', prettify)

        # OpenAPI tools
        from .tools.openapi_tools import register_openapi, openapi_registry
        self.descriptor.register_tool('register_openapi', register_openapi)
        self.descriptor.register_tool('openapi_registry', openapi_registry)

        # self.descriptor.init_api()
        self.descriptor.init_rpcs()
        self.descriptor.init_blueprint()

    def ready(self):
        """ Ready callback """
        if self.db is None:
            log.info("Shared ready: DB not initialized, skipping metadata apply")
            return
        #
        from .tools import db  # pylint: disable=C0415
        #
        try:
            if self.descriptor.config.get("apply_shared_metadata", True):
                log.info("Getting shared metadata")
                shared_metadata = db.get_shared_metadata()
                #
                log.info("Applying shared metadata")
                with db.get_session(None) as shared_db:
                    shared_metadata.create_all(bind=shared_db.connection())
                    shared_db.commit()
            #
            if self.descriptor.config.get("apply_project_metadata", True):
                log.info("Getting project metadata")
                tenant_metadata = db.get_tenant_specific_metadata()
                #
                log.info("Getting project list")
                project_list = self.context.rpc_manager.timeout(120).project_list(
                    filter_={"create_success": True},
                )
                #
                for project in project_list:
                    log.info("Applying project metadata: %s", project)
                    with db.get_session(project["id"]) as tenant_db:
                        tenant_metadata.create_all(bind=tenant_db.connection())
                        tenant_db.commit()
        except Exception:  # pylint: disable=W0703
            log.warning("Shared ready: failed to apply DB metadata (database may not be available)")

        try:
            from tools import config as c
            if c.STORAGE_ENGINE != "s3":
                self.context.rpc_manager.timeout(5).scheduling_create_if_not_exists({
                    'rpc_func': 'shared_storage_cleanup',
                    'name': 'Storage Retention Cleanup',
                    'cron': '0 0 * * *',
                    'active': True
                })
            else:
                log.debug(f"Storage engine is '{c.STORAGE_ENGINE}', skipping retention cleanup task registration")
        except:
            log.warning('Scheduling plugin not available, storage retention cleanup will not run automatically')


    def deinit(self):
        """ De-init module """
        log.info("De-initializing module Shared")
        #
        try:
            import sqlalchemy  # pylint: disable=E0401,C0415
            #
            if self.original_add_table is not None:
                sqlalchemy.MetaData._add_table = self.original_add_table  # pylint: disable=W0212
            #
            self.context.manager.unregister_reload_hook(self._reload_hook)
        except:  # pylint: disable=W0702
            pass

        self.descriptor.deinit_blueprint()

    def init_filters(self):
        # Register custom Jinja filters
        from .filters import tag_format, extract_tags, list_pd_to_json, \
            map_method_call, pretty_json, humanize_timestamp, format_datetime
        self.context.app.template_filter()(tag_format)
        self.context.app.template_filter()(extract_tags)
        self.context.app.template_filter()(list_pd_to_json)
        self.context.app.template_filter()(map_method_call)
        self.context.app.template_filter()(pretty_json)
        self.context.app.template_filter()(humanize_timestamp)
        self.context.app.template_filter()(format_datetime)

    def _reload_hook(self, name):
        import pydantic  # pylint: disable=E0401,C0415
        from .tools import db  # pylint: disable=C0415
        #
        name_prefix = f"plugins.{name}."
        #
        # Collect DB tables and dispose DeclarativeMeta
        #
        base_tables = []
        #
        for key, ref in list(db.Base.registry._class_registry.data.items()):  # pylint: disable=W0212
            obj = ref()
            #
            if obj is None:
                continue
            #
            if obj.__class__.__name__ != "DeclarativeMeta":
                continue
            #
            mod_name = obj.__module__
            #
            if mod_name.startswith(name_prefix):
                log.info("Removing DB base: %s: %s", key, mod_name)
                #
                base_tables.append(obj.__table__)
                db.Base.registry._dispose_cls(obj)  # pylint: disable=W0212
        #
        for table in self.module_tables.get(name, []):
            if table not in base_tables:
                base_tables.append(table)
        #
        # Remove DB relationships
        #
        for key, ref in list(db.Base.registry._class_registry.data.items()):  # pylint: disable=W0212
            obj = ref()
            #
            if obj is None:
                continue
            #
            if obj.__class__.__name__ != "DeclarativeMeta":
                continue
            #
            obj_mapper = obj.__mapper__
            mappers = set(obj_mapper.iterate_to_root()).union(obj_mapper.self_and_descendants)
            #
            for mapper in mappers:
                for prop_key, prop_val in list(mapper._props.items()):  # pylint: disable=W0212
                    if prop_val.__class__.__name__ != "RelationshipProperty":
                        continue
                    #
                    tables = [prop_val.target, prop_val.secondary, prop_val.backref]
                    #
                    for table in tables:
                        if table in base_tables:
                            log.info("Removing DB relation: %s - %s", mapper, prop_key)
                            #
                            mapper._props.pop(prop_key)  # pylint: disable=W0212
                            type.__delattr__(mapper.class_, prop_key)
                            break
        #
        # Remove DB tables
        #
        for table in list(reversed(db.Base.metadata.sorted_tables)):
            if table in base_tables:
                log.info("Removing DB table: %s", table)
                db.Base.metadata.remove(table)
        #
        # Remove PD validators
        #
        try:
            class_validators = pydantic.v1.class_validators
        except:  # pylint: disable=W0702
            class_validators = pydantic.class_validators
        #
        for ref in list(class_validators._FUNCS):  # pylint: disable=W0212
            if ref.startswith(name_prefix):
                log.info("Removing PD validator: %s", ref)
                class_validators._FUNCS.discard(ref)  # pylint: disable=W0212

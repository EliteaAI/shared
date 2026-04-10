import traceback
from contextlib import closing

from flask_sqlalchemy import BaseQuery

from pylon.core.tools import log
from sqlalchemy import MetaData
from sqlalchemy.orm import declarative_base
from sqlalchemy.schema import CreateSchema



try:
    from tools import context
except ImportError:
    class _FallbackContext:
        def __init__(self):
            self.__dict__['_data'] = {}
        def __getattr__(self, name):
            if name not in self._data:
                self._data[name] = _FallbackContext()
            return self._data[name]
        def __setattr__(self, name, value):
            self._data[name] = value
        def __repr__(self):
            def expand(obj):
                if isinstance(obj, _FallbackContext):
                    return {k: expand(v) for k, v in obj._data.items()}
                return obj
            return repr(expand(self))
        def __str__(self):
            return repr(self)
    context = _FallbackContext()



try:
    from tools import config as c
except ImportError:
    from config_pydantic import TheConfig
    c = TheConfig()


# DB: local
def schema_mapper(schema):
    if schema in [..., None, c.POSTGRES_SCHEMA]:
        return ...
    #
    try:
        from tools import project_constants as pc  # pylint: disable=E0401,C0415
    except ImportError:
        pc = {
            'INFLUX_DATABASES': {
                'jmeter_db': 'jmeter_{}',
                'gatling_db': 'gatling_{}',
                'comparison_db': 'comparison_{}',
                'telegraf_db': 'telegraf_{}'
            },
            'PROJECT_USER_NAME_PREFIX': ':system:project:',

            'PROJECT_USER_EMAIL_TEMPLATE': 'system_user_{}@centry.user',
            'PROJECT_SCHEMA_TEMPLATE': 'p_{}',
            'PROJECT_RABBIT_USER_TEMPLATE': 'rabbit_user_{}',
            'PROJECT_RABBIT_VHOST_TEMPLATE': 'project_{}_vhost',
            'PROJECT_PERSONAL_NAME_TEMPLATE': 'project_user_{user_id}',
        }
        pc['PROJECT_USER_NAME_TEMPLATE'] = '{}{{}}:'.format(pc['PROJECT_USER_NAME_PREFIX'])
    return pc["PROJECT_SCHEMA_TEMPLATE"].format(schema)


# DB: local
context.db.schema_mapper = schema_mapper

# DB: transitional config injector
if c.FORCE_INJECT_DB or context.db.url == "sqlite://":
    from pylon.core.tools import db_support
    log.info("Injecting DB config")
    #
    db_support.close_local_session()
    context.db.engine.dispose()
    #
    context.db.config = {
        "engine_url": c.DATABASE_URI,
        "engine_kwargs": c.DATABASE_ENGINE_OPTIONS.copy(),
        # "default_schema": c.POSTGRES_SCHEMA,
        "default_source_schema": c.POSTGRES_TENANT_SCHEMA,
    }
    #
    context.db.url = db_support.get_db_url(context.db)
    context.db.engine = db_support.make_engine(context.db)
    context.db.make_session = db_support.make_session_fn(context.db)
    #
    db_support.create_local_session()

# DB: proxy
engine = context.db.engine

# DB: transitional for 'public' schemas on present deployments
try:
    with engine.connect() as connection:
        connection.execute(CreateSchema(c.POSTGRES_SCHEMA, if_not_exists=True))
        connection.commit()
except Exception:  # pylint: disable=W0703
    log.warning("Could not ensure DB schema exists (DB may not be configured on this pylon)")


# DB: local
# def get_schema_translate_map(project_id: int | None) -> dict | None:
#     if project_id:
#         from tools import project_constants as pc
#         template = pc['PROJECT_SCHEMA_TEMPLATE']
#         return {
#             c.POSTGRES_TENANT_SCHEMA: template.format(project_id),
#             # c.POSTGRES_SCHEMA: c.POSTGRES_SCHEMA
#         }
#     return None


# DB: local
# def get_project_schema_sessionmaker(project_id: int | None):
#     schema_translate_map = get_schema_translate_map(project_id)
#     connectable = engine.execution_options(schema_translate_map=schema_translate_map)
#     return sessionmaker(
#         bind=connectable,
#         expire_on_commit=False,
#     )


# DB: used
def get_project_schema_session(project_id: int | None):
    return context.db.make_session(project_id)


# DB: obsolete
# class SessionMeta(DeclarativeMeta):
#     def __init__(cls, name, bases, attrs):
#         super().__init__(name, bases, attrs)
#         cls.session = get_project_schema_session(None)
#         cls.query = cls.session.query_property(query_cls=BaseQuery)


# DB: proxy
class SessionProxyMeta(type):
    """ Proxy meta class """

    def __getattr__(cls, name):
        log.info("SessionProxy.cls.__getattr__(%s)", name)


# DB: proxy
class SessionProxy(metaclass=SessionProxyMeta):  # pylint: disable=R0902,R0903
    """ Proxy class """

    def __getattr__(self, name):
        from pylon.core.tools import db_support
        db_support.check_local_entities()
        #
        if context.local.db_session is None:
            log.warning("Creating new local session")
            #
            log.debug("Local session stack:")
            for stack_line in traceback.format_stack():
                log.debug("%s", stack_line.strip())
            #
            db_support.create_local_session()
        #
        return getattr(context.local.db_session, name)


# DB: proxy
session = SessionProxy()


# DB: proxy
class QueryProxyMeta(type):
    """ Proxy meta class """

    def __getattr__(cls, name):
        log.info("QueryProxy.cls.__getattr__(%s)", name)


# DB: proxy
class QueryProxy(metaclass=QueryProxyMeta):  # pylint: disable=R0902
    """ Proxy base """

    def __get__(self, instance, owner):
        return BaseQuery(owner, session=session)


# DB: legacy
Base = declarative_base()
Base.query = QueryProxy()


# DB: used
def get_all_metadata():
    meta = MetaData()
    for table in Base.metadata.tables.values():
        table.tometadata(meta)
    return meta


# DB: used
def get_shared_metadata():
    meta = MetaData()
    for table in Base.metadata.tables.values():
        if table.schema != c.POSTGRES_TENANT_SCHEMA:
            table.tometadata(meta)
    return meta


# DB: used (by flows)
def get_tenant_specific_metadata():
    meta = MetaData(schema=c.POSTGRES_TENANT_SCHEMA)
    for table in Base.metadata.tables.values():
        if table.schema == c.POSTGRES_TENANT_SCHEMA:
            table.tometadata(meta)
    return meta


# DB: used
def get_session(project_id: int | None = None):
    return closing(get_project_schema_session(project_id))


# DB: used
with_project_schema_session = get_session

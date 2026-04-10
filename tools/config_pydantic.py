from typing import Optional, Any, Dict

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TheConfig(BaseSettings):
    LOCAL_DEV: bool = False
    PERSISTENT_SECRETS: bool = True
    CURRENT_RELEASE: str = "latest"
    ADMINISTRATION_MODE: str = "administration"
    DEFAULT_MODE: str = "default"
    MAX_DOTS_ON_CHART: int = 100
    BACKEND_PERFORMANCE_RESULTS_RETENTION: int = 30
    BUCKET_RETENTION_DAYS: int = 7
    PROJECT_USER_NAME_PREFIX: Optional[str] = None
    APP_IP: Optional[str] = None
    APP_HOST: Optional[str] = None
    APP_SCHEME: str = "http"
    ALLOW_CORS: bool = False
    ARBITER_RUNTIME: str = "rabbitmq"
    EVENT_NODE_WORKERS: int = 1
    REDIS_HOST: str = "centry-redis"
    REDIS_PORT: int = 6379
    REDIS_USER: str = ""
    REDIS_PASSWORD: str = ""
    REDIS_DB: int = 2
    REDIS_RABBIT_DB: int = 4
    REDIS_CHAT_CANVAS_DB: int = 6
    REDIS_USE_SSL: bool = False
    RABBIT_HOST: Optional[str] = None
    RABBIT_PORT: int = 5672
    RABBIT_USER: str = ""
    RABBIT_PASSWORD: str = ""
    RABBIT_ADMIN_URL: str = "http://carrier-rabbit:15672"
    RABBIT_QUEUE_NAME: str = "default"
    RABBIT_USE_SSL: bool = False
    RABBIT_SSL_VERIFY: bool = False
    INFLUX_PORT: int = 8086
    INFLUX_USER: str = ""
    INFLUX_PASSWORD: str = ""
    LOKI_HOST: Optional[str] = None
    LOKI_HOST_INTERNAL: str = "http://carrier-loki"
    LOKI_PORT: int = 3100
    MINIO_URL: str = "http://carrier-minio:9000"
    MINIO_ACCESS_KEY: str = ""
    MINIO_ACCESS: Optional[str] = None
    MINIO_SECRET_KEY: str = ""
    MINIO_SECRET: Optional[str] = None
    MINIO_REGION: str = "us-east-1"
    VAULT_URL: str = "http://carrier-vault:8200"
    VAULT_DB_PK: int = 1
    VAULT_ADMINISTRATION_NAME: Optional[str] = None
    DATABASE_VENDOR: str = "postgres"
    POSTGRES_HOST: str = "centry-postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = ""
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "centry"
    POSTGRES_SCHEMA: str = "centry"
    POSTGRES_TENANT_SCHEMA: str = "tenant"
    SQLITE_DB: str = "sqlite.db"
    FORCE_INJECT_DB: bool = False
    PROJECT_CACHE_PLUGINS: str = "PROJECT_CACHE_PLUGINS"
    PROJECT_CACHE_KEY: str = "PROJECT_CACHE_KEY"
    DATABASE_URI: Optional[str] = None
    DATABASE_ENGINE_OPTIONS: Optional[Dict[str, Any]] = Field(default_factory=dict)
    TASKS_UPLOAD_FOLDER: str = "/tmp/tasks"
    SIO_URL: str = ""
    SIO_PASSWORD: str = ""
    SIO_SSL_VERIFY: bool = False
    CENTRY_USE_INFLUX: bool = False
    SECRETS_ENGINE: str = "managed_vault"
    SECRETS_MASTER_KEY: Optional[str] = None
    SECRETS_FILESYSTEM_PATH: str = "/tmp/secrets"
    STORAGE_ENGINE: str = "s3"
    STORAGE_FILESYSTEM_PATH: str = "/tmp/storage"
    STORAGE_FILESYSTEM_ENCODER: str = "base64"
    STORAGE_LIBCLOUD_DRIVER: str = "LOCAL"
    STORAGE_LIBCLOUD_PARAMS: Any = Field(default_factory=lambda: {"kwargs": {"key": "/tmp/storage"}})
    STORAGE_LIBCLOUD_ENCODER: Optional[str] = None
    NO_GROUP_NAME: str = 'no-group'
    __old_config = None

    model_config = SettingsConfigDict(env_file=None, env_file_encoding='utf-8')

    def __init__(self, *args, env_files: list[str] = None, **kwargs):
        if env_files is not None:
            self.model_config['env_files'] = env_files
            from dotenv import load_dotenv
            for i in env_files:
                load_dotenv(i, encoding=self.model_config['env_file_encoding'], override=True)
        super().__init__(*args, **kwargs)

    def __new__(cls, *args, **kwargs):
        if cls.__old_config is not None:
            old = cls.__old_config
            cls.__old_config = None  # Reset before instantiation to prevent recursion
            instance = cls.from_old_config(old)
            return instance
        return super().__new__(cls)

    @classmethod
    def from_old_config(cls, old_config) -> "TheConfig":
        """
        Initialize from an old config object (with attributes).
        """
        values = {}
        for field in cls.model_fields:
            if hasattr(old_config, field):
                values[field] = getattr(old_config, field)
        return cls(**values)

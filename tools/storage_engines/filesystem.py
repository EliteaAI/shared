# pylint: disable=C0116
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

""" Storage engine impl """

import os
import sys
import json
import queue
import shutil
import datetime

from pylon.core.tools import log  # pylint: disable=E0401,E0611

from tools import context, this  # pylint: disable=E0401
from tools import config as c  # pylint: disable=E0401

from ..minio_tools import space_monitor, throughput_monitor  # pylint: disable=E0401
from . import fs_encode_name, fs_decode_name


class EngineMeta(type):
    """ Engine meta class """

    def __getattr__(cls, name):
        log.info("StorageEngine.cls.__getattr__(%s)", name)


class EngineBase(metaclass=EngineMeta):  # pylint: disable=R0902
    """ Engine base class """

    def purify_bucket_name(self, name: str) -> str:
        return name[len(self.bucket_prefix):] if name.startswith(self.bucket_prefix) else name

    def __getattr__(self, name):
        log.info("StorageEngine.base.__getattr__(%s)", name)

    TASKS_BUCKET = "tasks"

    def __init__(
            self,
            *args,
            storage_filesystem_path=None,
            storage_filesystem_encoder=None,
            **kwargs,
    ):
        _ = args, kwargs
        #
        self.event_manager = context.event_manager
        self.rpc_manager = context.rpc_manager
        #
        self.storage_filesystem_path = storage_filesystem_path \
            if storage_filesystem_path is not None else \
            c.STORAGE_FILESYSTEM_PATH
        #
        self.storage_filesystem_encoder = storage_filesystem_encoder \
            if storage_filesystem_encoder is not None else \
            c.STORAGE_FILESYSTEM_ENCODER
        #
        self.bucket_path = os.path.join(self.storage_filesystem_path, "bucket")
        self.meta_path = os.path.join(self.storage_filesystem_path, "meta")
        #
        os.makedirs(self.bucket_path, exist_ok=True)
        os.makedirs(self.meta_path, exist_ok=True)

    def extract_access_data(self, configuration_title=None, is_local=True):
        if this.descriptor.config.get("always_use_shared_storage", True):
            return {}
        #
        try:
            rpc_call = self.rpc_manager.timeout(5)
            #
            if self.project:
                conf = rpc_call.configurations_get_filtered_project(
                    project_id=self.project['id'],
                    include_shared=True,
                    filter_fields={'elitea_title': configuration_title}
                )[0]
            else:
                conf = rpc_call.configurations_get_filtered_public(
                    filter_fields={'elitea_title': configuration_title}
                )[0]
        #
        except (queue.Empty, IndexError):
            conf = None
        #
        if conf:
            return dict(conf)
        #
        return {}

    @property
    def bucket_prefix(self):
        raise NotImplementedError

    def format_bucket_name(self, bucket):
        if bucket.startswith(self.bucket_prefix):
            return bucket
        #
        return f"{self.bucket_prefix}{bucket}"

    def _save_meta(self, bucket, meta):
        bucket_name = self.format_bucket_name(bucket)
        path = os.path.join(
            self.meta_path,
            fs_encode_name(
                name=bucket_name,
                kind="meta",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        with open(path, "w", encoding="utf-8") as file:
            json.dump(meta, file)

    def _load_meta(self, bucket):
        bucket_name = self.format_bucket_name(bucket)
        path = os.path.join(
            self.meta_path,
            fs_encode_name(
                name=bucket_name,
                kind="meta",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        if os.path.exists(path):
            with open(path, "rb") as file:
                return json.load(file)
        #
        return {}

    def list_bucket(self):
        result = []
        #
        for item in os.listdir(path=self.bucket_path):
            try:
                name = fs_decode_name(
                    name=item,
                    kind="bucket",
                    encoder=self.storage_filesystem_encoder,
                )
            except:  # pylint: disable=W0702
                continue
            #
            if name.startswith(self.bucket_prefix):
                result.append(name.replace(self.bucket_prefix, "", 1))
        #
        return result

    def create_bucket(self, bucket, bucket_type=None, retention_days=None) -> dict:
        bucket_name = self.format_bucket_name(bucket)
        path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        os.makedirs(path, exist_ok=True)
        #
        if bucket_type and bucket_type in ("system", "autogenerated", "local"):
            self.set_bucket_tags(bucket=bucket, tags={"type": bucket_type})
        #
        if retention_days:
            self.configure_bucket_lifecycle(bucket_name, retention_days)
        #
        return {
            "Location": f"/{bucket_name}"
        }

    def list_files(self, bucket, next_continuation_token=None):
        _ = next_continuation_token
        #
        bucket_name = self.format_bucket_name(bucket)
        bucket_path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        files = []
        #
        # Recursively walk the bucket directory to support "/" in file names
        for root, dirs, filenames in os.walk(bucket_path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                stat = os.stat(file_path)
                #
                # Get relative path from bucket root and decode each component
                rel_path = os.path.relpath(file_path, bucket_path)
                #
                # Decode each path component if encoder is set
                if self.storage_filesystem_encoder:
                    parts = rel_path.split(os.sep)
                    decoded_parts = [
                        fs_decode_name(
                            name=part,
                            kind="file",
                            encoder=self.storage_filesystem_encoder,
                        )
                        for part in parts
                    ]
                    decoded_name = "/".join(decoded_parts)
                else:
                    # No encoding, use the relative path directly (convert os.sep to /)
                    decoded_name = rel_path.replace(os.sep, "/")
                #
                files.append({
                    "name": decoded_name,
                    "size": stat.st_size,
                    "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
        #
        return files

    @space_monitor
    def upload_file(self, bucket, file_obj, file_name):
        bucket_name = self.format_bucket_name(bucket)
        path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
            fs_encode_name(
                name=file_name,
                kind="file",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        # Create parent directories if file_name contains "/" (S3-style paths)
        parent_dir = os.path.dirname(path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        #
        with open(path, "wb") as file:
            if isinstance(file_obj, bytes):
                data = file_obj
            elif isinstance(file_obj, str):
                data = file_obj.encode()
            else:
                data = file_obj.read()
            #
            file.write(data)
        #
        throughput_monitor(client=self, file_size=sys.getsizeof(file_obj))
        #
        # NB: No return response data emulated

    def download_file(self, bucket, file_name, project_id=None):
        bucket_name = self.format_bucket_name(bucket)
        path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
            fs_encode_name(
                name=file_name,
                kind="file",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        file_size = self.get_file_size(bucket, file_name)
        throughput_monitor(client=self, file_size=file_size, project_id=project_id)
        #
        with open(path, "rb") as file:
            return file.read()

    @space_monitor
    def remove_file(self, bucket, file_name):
        bucket_name = self.format_bucket_name(bucket)
        bucket_path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        path = os.path.join(
            bucket_path,
            fs_encode_name(
                name=file_name,
                kind="file",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        if os.path.exists(path):
            os.remove(path)
            #
            # Clean up empty parent directories (but not the bucket directory itself)
            parent = os.path.dirname(path)
            while parent and parent != bucket_path:
                try:
                    os.rmdir(parent)  # Only removes if empty
                    parent = os.path.dirname(parent)
                except OSError:
                    break  # Directory not empty or other error

    def remove_bucket(self, bucket):
        bucket_name = self.format_bucket_name(bucket)
        path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        meta_path = os.path.join(
            self.meta_path,
            fs_encode_name(
                name=bucket_name,
                kind="meta",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        # Use shutil.rmtree to remove bucket with all nested directories (S3-style paths)
        if os.path.exists(path):
            shutil.rmtree(path)
        #
        if os.path.exists(meta_path):
            os.remove(meta_path)

    def configure_bucket_lifecycle(self, bucket, days):
        meta = self._load_meta(bucket)
        #
        meta["lifecycle"] = days
        #
        self._save_meta(bucket, meta)

    def get_bucket_lifecycle(self, bucket):
        meta = self._load_meta(bucket)
        #
        if not meta or "lifecycle" not in meta:
            return {}
        #
        return {
            "Rules": [{
                "Expiration": {
                    "Days": meta["lifecycle"],
                },
            }],
        }

    def get_bucket_size(self, bucket):
        bucket_name = self.format_bucket_name(bucket)
        bucket_path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        total_size = 0
        #
        # Recursively calculate size including nested directories (S3-style paths)
        for root, dirs, filenames in os.walk(bucket_path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                total_size += os.path.getsize(file_path)
        #
        return total_size

    def get_file_size(self, bucket, filename):
        bucket_name = self.format_bucket_name(bucket)
        path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
            fs_encode_name(
                name=filename,
                kind="file",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        try:
            stat = os.stat(path)
            return stat.st_size
        except:  # pylint: disable=W0702
            return 0

    def get_bucket_tags(self, bucket):
        meta = self._load_meta(bucket)
        #
        if not meta or "tags" not in meta:
            return {}
        #
        result = {
            "TagSet": [],
        }
        #
        for key, value in meta["tags"].items():
            result["TagSet"].append({
                "Key": key,
                "Value": value,
            })
        #
        return result

    def set_bucket_tags(self, bucket, tags):
        meta = self._load_meta(bucket)
        #
        if "tags" not in meta:
            meta["tags"] = {}
        #
        meta["tags"].update(tags)
        #
        self._save_meta(bucket, meta)

    def select_object_content(self, bucket, file_name, expression_addon=""):
        # TODO: implement using py-partiql-parser or similiar
        log.info("select_object_content(%s, %s, %s)", bucket, file_name, expression_addon)
        return []

    def is_file_exist(self, bucket, file_name):
        bucket_name = self.format_bucket_name(bucket)
        path = os.path.join(
            self.bucket_path,
            fs_encode_name(
                name=bucket_name,
                kind="bucket",
                encoder=self.storage_filesystem_encoder,
            ),
            fs_encode_name(
                name=file_name,
                kind="file",
                encoder=self.storage_filesystem_encoder,
            ),
        )
        #
        return os.path.exists(path)


class Engine(EngineBase):
    """ Engine class """

    def __init__(self, project: dict, configuration_title=None, is_local=True, **kwargs):
        _ = kwargs
        #
        if isinstance(project, dict):
            self.project = project
        else:
            self.project = project.to_json()
        #
        self.configuration_title = configuration_title
        self.is_local = is_local
        #
        self.rpc_manager = context.rpc_manager
        #
        conf = self.extract_access_data(configuration_title, is_local)
        #
        if conf:
            if conf["id"] != 1:
                raise RuntimeError("Non-default filesystem integrations are not currently supported")
        else:
            super().__init__()

    @property
    def bucket_prefix(self):
        return f"p--{self.project['id']}."

    @classmethod
    def from_project_id(
            cls, project_id: int,
            configuration_title=None, is_local=True, rpc_manager=None,
            **kwargs
    ):
        _ = kwargs
        #
        if not rpc_manager:
            rpc_manager = context.rpc_manager
        #
        project = rpc_manager.call.project_get_by_id(project_id=project_id)
        return cls(project, configuration_title, is_local)


# TODO: engine init() and retention watcher thread

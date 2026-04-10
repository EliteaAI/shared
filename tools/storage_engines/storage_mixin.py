import time
import datetime

from pylon.core.tools import log  # pylint: disable=E0401,E0611


class ManualCleanupMixin:
    """
    Mixin for storage engines that require manual lifecycle cleanup.

    S3/MinIO handles lifecycle natively at the server level.
    Libcloud/filesystem engines store lifecycle as metadata and need manual cleanup.

    Usage in storage_cleanup RPC:
        if isinstance(engine, ManualCleanupMixin):
            engine.cleanup_all_buckets()
    """

    def cleanup_expired_files(self, bucket):
        bucket_name = self.format_bucket_name(bucket)
        try:
            lifecycle = self.get_bucket_lifecycle(bucket)
            if not lifecycle or "Rules" not in lifecycle:
                return 0
            expiration_days = lifecycle["Rules"][0]["Expiration"]["Days"]
            cutoff_time = time.time() - (expiration_days * 24 * 60 * 60)
            cutoff_datetime = datetime.datetime.fromtimestamp(cutoff_time)
            files = self.list_files(bucket)
            deleted_count = 0
            for file_obj in files:
                file_modified = datetime.datetime.fromisoformat(file_obj["modified"])
                if file_modified < cutoff_datetime:
                    try:
                        self.remove_file(bucket, file_obj["name"])
                        deleted_count += 1
                    except Exception as e:
                        log.error(f"Failed to delete file {file_obj['name']}: {e}")
            return deleted_count
        except Exception as e:
            log.error(f"Failed to cleanup expired files for bucket={bucket_name}: {e}", exc_info=True)
            return 0

    def cleanup_all_buckets(self):
        results = {}
        try:
            buckets = self.list_bucket()
            for bucket in buckets:
                try:
                    deleted = self.cleanup_expired_files(bucket)
                    if deleted > 0:
                        results[bucket] = deleted
                except Exception as e:
                    log.error(f"Failed to cleanup bucket {bucket}: {e}")
            return results
        except Exception as e:
            log.error(f"Failed to cleanup all buckets: {e}", exc_info=True)
            return results


import time
import datetime

from pylon.core.tools import log  # pylint: disable=E0401,E0611

CLEANUP_FILE_BATCH_SIZE = 1000
MAX_RETENTION_DAYS = 36500  # ~100 years, sanity limit


class ManualCleanupMixin:
    """
    Mixin for storage engines that require manual lifecycle cleanup.

    S3/MinIO handles lifecycle natively at the server level.
    Libcloud/filesystem engines store lifecycle as metadata and need manual cleanup.

    Usage in storage_cleanup RPC:
        if isinstance(engine, ManualCleanupMixin):
            engine.cleanup_all_buckets()
    """

    def _remove_files_bulk(self, bucket, file_names):
        """
        Remove multiple files from a bucket.
        Subclasses can override for native bulk delete support.
        """
        removed = 0
        for file_name in file_names:
            try:
                self.remove_file(bucket, file_name)
                removed += 1
            except Exception as e:
                log.error(f"Failed to delete file {file_name}: {e}")
        return removed

    def cleanup_expired_files(self, bucket):
        """
        Clean up expired files from a bucket using pagination and bulk delete.
        """
        bucket_name = self.format_bucket_name(bucket)
        try:
            lifecycle = self.get_bucket_lifecycle(bucket)
            if not lifecycle or "Rules" not in lifecycle:
                return 0

            expiration_days = lifecycle["Rules"][0]["Expiration"]["Days"]

            if not isinstance(expiration_days, (int, float)) or expiration_days <= 0:
                log.warning(f"Invalid expiration_days={expiration_days} for bucket={bucket_name}, skipping")
                return 0
            if expiration_days > MAX_RETENTION_DAYS:
                log.warning(f"expiration_days={expiration_days} exceeds max ({MAX_RETENTION_DAYS}) for bucket={bucket_name}, skipping")
                return 0

            cutoff_time = time.time() - (expiration_days * 24 * 60 * 60)
            cutoff_datetime = datetime.datetime.fromtimestamp(cutoff_time)

            deleted_count = 0
            files_to_delete = []
            continuation_token = None

            while True:
                files = self.list_files(bucket, next_continuation_token=continuation_token)

                if isinstance(files, dict):
                    file_list = files.get("files", [])
                    continuation_token = files.get("next_continuation_token")
                else:
                    file_list = files
                    continuation_token = None

                for file_obj in file_list:
                    try:
                        file_modified = datetime.datetime.fromisoformat(file_obj["modified"])
                        if file_modified < cutoff_datetime:
                            files_to_delete.append(file_obj["name"])

                            if len(files_to_delete) >= CLEANUP_FILE_BATCH_SIZE:
                                deleted_count += self._remove_files_bulk(bucket, files_to_delete)
                                files_to_delete = []
                    except Exception as e:
                        log.error(f"Failed to process file {file_obj.get('name', 'unknown')}: {e}")

                if not continuation_token:
                    break

            if files_to_delete:
                deleted_count += self._remove_files_bulk(bucket, files_to_delete)

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


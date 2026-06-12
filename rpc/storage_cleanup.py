""" Storage retention policy cleanup RPC """

from concurrent.futures import ThreadPoolExecutor, as_completed

from pylon.core.tools import log, web

from ..tools.minio_client import MinioClient
from ..tools.storage_engines.libcloud import ManualCleanupMixin

CLEANUP_BATCH_SIZE = 1000


def _batch_list(items, batch_size):
    """Yield successive batches from items list."""
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]


def _process_project(project):
    """
    Process cleanup for a single project.
    Designed to run in a thread pool worker.
    """
    project_id = project["id"]
    project_name = project.get("name", f"project_{project_id}")
    try:
        engine = MinioClient(project)
        bucket_results = engine.cleanup_all_buckets()
        if bucket_results:
            files_deleted = sum(bucket_results.values())
            return {
                "project_id": project_id,
                "name": project_name,
                "buckets_cleaned": len(bucket_results),
                "files_deleted": files_deleted,
                "buckets": bucket_results
            }
        return None
    except Exception as e:
        return {
            "project_id": project_id,
            "name": project_name,
            "error": str(e)
        }


class RPC:
    @web.rpc("shared_storage_cleanup")
    def storage_cleanup(self):
        """
        Run retention policy cleanup on all projects' storage buckets.

        This RPC is designed to be called by the scheduling plugin to enforce
        retention policies on all buckets across all projects.

        Projects are processed in parallel using ThreadPoolExecutor with batching
        to prevent resource exhaustion.

        Only runs cleanup for storage engines that implement ManualCleanupMixin.
        S3/MinIO handles lifecycle natively at server level.

        Returns:
            dict: Cleanup results with statistics per project
        """
        try:
            try:
                self.context.rpc_manager.timeout(60).artifacts_check_bucket_expiration_notifications()
            except Exception as e:
                log.warning('Failed to run bucket expiration notifications: %s', e)

            if not issubclass(MinioClient, ManualCleanupMixin):
                return {
                    "skipped": True,
                    "reason": "Storage engine handles lifecycle natively"
                }

            project_list = self.context.rpc_manager.timeout(30).project_list(
                filter_={"create_success": True}
            )

            all_results = {}
            total_files_deleted = 0
            total_buckets_cleaned = 0

            total_batches = (len(project_list) + CLEANUP_BATCH_SIZE - 1) // CLEANUP_BATCH_SIZE
            batch_num = 0

            for batch in _batch_list(project_list, CLEANUP_BATCH_SIZE):
                batch_num += 1
                log.info(
                    f"Storage_cleanup: Processing batch {batch_num}/{total_batches} "
                    f"({len(batch)} projects)"
                )

                with ThreadPoolExecutor() as executor:
                    futures = {executor.submit(_process_project, p): p for p in batch}

                    for future in as_completed(futures):
                        result = future.result()
                        if result is None:
                            continue

                        project_id = result["project_id"]

                        if "error" in result:
                            all_results[f"project_{project_id}"] = {
                                "error": result["error"],
                                "name": result["name"]
                            }
                        else:
                            total_files_deleted += result["files_deleted"]
                            total_buckets_cleaned += result["buckets_cleaned"]
                            all_results[f"project_{project_id}"] = {
                                "name": result["name"],
                                "buckets_cleaned": result["buckets_cleaned"],
                                "files_deleted": result["files_deleted"],
                                "buckets": result["buckets"]
                            }

                log.info(
                    f"Storage_cleanup: Batch {batch_num}/{total_batches} complete. "
                    f"Running totals: {total_buckets_cleaned} buckets, {total_files_deleted} files"
                )

            log.info(
                f"Storage_cleanup: Complete. "
                f"Processed {len(project_list)} projects, "
                f"cleaned {total_buckets_cleaned} buckets, "
                f"deleted {total_files_deleted} files"
            )

            return {
                "success": True,
                "skipped": False,
                "projects_processed": len(project_list),
                "projects_with_cleanups": len([r for r in all_results.values() if "error" not in r]),
                "total_buckets_cleaned": total_buckets_cleaned,
                "total_files_deleted": total_files_deleted,
                "results": all_results
            }

        except Exception:
            return {
                "success": False,
            }

""" Storage retention policy cleanup RPC """

from concurrent.futures import ThreadPoolExecutor, as_completed

from pylon.core.tools import log, web

from tools import this

from ..tools.minio_client import MinioClient
from ..tools.storage_engines.libcloud import ManualCleanupMixin

CLEANUP_BATCH_SIZE = 1000
NOTIFY_BATCH_SIZE = 200


def _batch_list(items, batch_size):
    """Yield successive batches from items list."""
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]


def _shared_storage_confirmed():
    """One global walk only covers every project when they all share one storage backend.
    With per-project storage configs the walk would silently miss projects on other backends."""
    try:
        return bool(this.descriptor.config.get("always_use_shared_storage", True))
    except Exception as e:  # pylint: disable=W0703
        log.warning('Could not resolve always_use_shared_storage, skipping batch walk: %s', e)
        return False


def _process_project(project, buckets=None):
    """
    Process cleanup for a single project.
    Designed to run in a thread pool worker.
    `buckets`, if given, comes from a single precomputed global walk instead of a per-project one.
    """
    project_id = project["id"]
    project_name = project.get("name", f"project_{project_id}")
    try:
        engine = MinioClient(project)
        metas = engine.load_metas(buckets) if buckets is not None and hasattr(engine, "load_metas") else None
        bucket_results = engine.cleanup_all_buckets(buckets=buckets, metas=metas)
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


def _notify_bucket_expiration(rpc_manager, buckets_by_project, project_list):
    """Send the precomputed listing in project-sized chunks: a whole-deployment bucket map
    in one RPC argument would just move the latency into serialization/transport."""
    if buckets_by_project is None or not project_list:
        try:
            rpc_manager.timeout(60).artifacts_check_bucket_expiration_notifications(
                buckets_by_project=buckets_by_project
            )
        except Exception as e:  # pylint: disable=W0703
            log.warning('Failed to run bucket expiration notifications: %s', e)
        return
    #
    for batch in _batch_list(project_list, NOTIFY_BATCH_SIZE):
        project_ids = [str(p["id"]) for p in batch]
        chunk = {pid: buckets_by_project.get(pid, []) for pid in project_ids}
        try:
            rpc_manager.timeout(60).artifacts_check_bucket_expiration_notifications(
                buckets_by_project=chunk, project_ids=project_ids
            )
        except Exception as e:  # pylint: disable=W0703
            log.warning('Failed to run bucket expiration notifications: %s', e)


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
            # Walk once and share the listing with both the notifier and the deleter below,
            # instead of each re-walking storage per project. Only engines that support the
            # batch path (currently libcloud) get this; others keep their own per-call walk.
            buckets_by_project = None
            project_list = None
            if hasattr(MinioClient, "list_all_buckets_by_project") and _shared_storage_confirmed():
                try:
                    project_list = self.context.rpc_manager.timeout(30).project_list(
                        filter_={"create_success": True}
                    )
                    if project_list:
                        buckets_by_project = MinioClient(project_list[0]).list_all_buckets_by_project()
                except Exception as e:
                    log.warning('Failed to precompute global bucket listing: %s', e)
                    buckets_by_project = None

            _notify_bucket_expiration(
                self.context.rpc_manager, buckets_by_project, project_list
            )

            if not issubclass(MinioClient, ManualCleanupMixin):
                return {
                    "skipped": True,
                    "reason": "Storage engine handles lifecycle natively"
                }

            if project_list is None:
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
                    futures = {
                        executor.submit(
                            _process_project, p,
                            buckets_by_project.get(str(p["id"]), []) if buckets_by_project is not None else None
                        ): p
                        for p in batch
                    }

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

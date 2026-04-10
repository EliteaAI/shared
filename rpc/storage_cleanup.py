""" Storage retention policy cleanup RPC """

from pylon.core.tools import log, web

from ..tools.minio_client import MinioClient
from ..tools.storage_engines.libcloud import ManualCleanupMixin


class RPC:
    @web.rpc("shared_storage_cleanup")
    def storage_cleanup(self):
        """
        Run retention policy cleanup on all projects' storage buckets.

        This RPC is designed to be called by the scheduling plugin to enforce
        retention policies on all buckets across all projects.

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

            for project in project_list:
                try:
                    project_id = project["id"]
                    project_name = project.get("name", f"project_{project_id}")
                    engine = MinioClient(project)
                    bucket_results = engine.cleanup_all_buckets()

                    if bucket_results:
                        files_deleted = sum(bucket_results.values())
                        total_files_deleted += files_deleted
                        total_buckets_cleaned += len(bucket_results)

                        all_results[f"project_{project_id}"] = {
                            "name": project_name,
                            "buckets_cleaned": len(bucket_results),
                            "files_deleted": files_deleted,
                            "buckets": bucket_results
                        }

                except Exception as e:
                    all_results[f"project_{project.get('id', 'unknown')}"] = {
                        "error": str(e),
                        "name": project.get("name", "unknown")
                    }

            log.debug(
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

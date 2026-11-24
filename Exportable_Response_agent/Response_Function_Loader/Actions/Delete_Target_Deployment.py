
"""Tier-3 response action: delete a malicious Kubernetes Deployment.

The action is independent of the previous response tiers.
It records the Deployment UID and configuration for potential rollback.
"""

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..Kubernetes_API_calls.Kube_API_calls import (
    read_namespaced_deployment,
    read_namespaced_deployment_scale,
    delete_namespaced_deployment
)


def delete_target_deployment(issue, Time, parameters, API):
    """
    Delete a Kubernetes Deployment.

    Expected issue keys:
        Issue_ID, Namespace, Resource_name

    Optional parameters:
        {
            "require_scaled_to_zero": True
        }

    API["apps"] must be a configured AppsV1Api instance.

    Returns:
        (result, error)
        error is None on success.
    """

    namespace = issue["Namespace"]
    deployment_name = issue["Resource_name"]

    result = {
        "deployment": deployment_name,
        "namespace": namespace,
        "deployment_uid": None,
        "replicas_at_deletion": None,
        "deployment_backup": None,
        "deletion_requested": False,
        "status": "Pending"
    }

    try:
        # 1. Validate parameters
        if parameters is None:
            parameters = {}

        if not isinstance(parameters, dict):
            result["status"] = "Failed"
            return result, "parameters must be a dictionary"

        require_zero = parameters.get("require_scaled_to_zero", True)

        if type(require_zero) is not bool:
            result["status"] = "Failed"
            return result, "require_scaled_to_zero must be a boolean"

        apps_api = API["apps"]

        # 2. Retrieve Deployment
        deployment, error = read_namespaced_deployment(
            vi=apps_api,
            name=deployment_name,
            namespace=namespace
        )

        if error:
            result["status"] = "Failed"
            return result, error

        uid = deployment.metadata.uid

        if not uid:
            result["status"] = "Failed"
            return result, "Deployment UID is missing"

        result["deployment_uid"] = uid

        # 3. Retrieve current Deployment scale
        scale, error = read_namespaced_deployment_scale(
            vi=apps_api,
            name=deployment_name,
            namespace=namespace
        )

        if error:
            result["status"] = "Failed"
            return result, error

        if scale.metadata.uid != uid:
            result["status"] = "Failed"
            return result, "Deployment changed during inspection"

        current_replicas = scale.spec.replicas

        if current_replicas is None:
            result["status"] = "Failed"
            return result, "Could not determine current replica count"

        result["replicas_at_deletion"] = current_replicas

        # 4. Optionally require the Deployment to be scaled to zero
        if require_zero and current_replicas != 0:
            result["status"] = "Failed"
            return result, (
                f"Deployment has {current_replicas} desired replicas. "
                "Scale to zero before deletion."
            )

        # 5. Save Deployment configuration for rollback
        metadata = deployment.metadata

        backup_metadata = {
            "name": deployment_name,
            "namespace": namespace
        }

        if metadata.labels:
            backup_metadata["labels"] = dict(metadata.labels)

        if metadata.annotations:
            backup_metadata["annotations"] = dict(metadata.annotations)

        result["deployment_backup"] = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": backup_metadata,
            "spec": apps_api.api_client.sanitize_for_serialization(
                deployment.spec
            )
        }

        # 6. Configure deletion
        # UID precondition prevents deleting a replacement Deployment.
        # Foreground deletion also removes dependent ReplicaSets and Pods.
        delete_options = client.V1DeleteOptions(
            propagation_policy="Foreground",
            preconditions=client.V1Preconditions(
                uid=uid
            )
        )

        # 7. Delete Deployment
        delete_result, error = delete_namespaced_deployment(
            vi=apps_api,
            name=deployment_name,
            namespace=namespace,
            body=delete_options
        )

        if error:
            result["status"] = "Failed"
            return result, error

        result["deletion_requested"] = True

        # 8. Mark action completed
        # Completion indicates deletion was accepted by Kubernetes,
        # not necessarily that all dependent resources are gone.
        result["status"] = "Completed"
        issue["Execution_Status"] = "Completed"

        return result, None

    except ApiException as error:
        result["status"] = "Failed"
        return result, (
            f"Kubernetes API error ({error.status}): {error.reason}"
        )

    except Exception as error:
        result["status"] = "Failed"
        return result, str(error)

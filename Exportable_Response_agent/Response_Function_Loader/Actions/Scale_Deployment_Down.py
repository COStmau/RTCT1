
"""Tier-2 response action: reduce a Kubernetes Deployment's desired replicas.

The action is independent of the Tier-1 isolation action.
It records the original replica count and Deployment UID for later rollback.
"""

from kubernetes.client.rest import ApiException

from ..Kubernetes_API_calls.Kube_API_calls import (
    patch_namespaced_deployment_scale,
    read_namespaced_deployment,
    read_namespaced_deployment_scale
)


def scale_down_deployment(issue, Time, parameters, API):
    """
    Scale a Deployment down (to 0 by default).

    Expected issue keys:
        Issue_ID, Namespace, Resource_name

    Optional parameters:
        {"target_replicas": nonnegative_integer}

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
        "original_replicas": None,
        "target_replicas": None,
        "observed_replicas": None,
        "scale_updated": False,
        "status": "Pending",
    }

    try:
        # 1. Validate parameters
        if parameters is None:
            parameters = {}

        if not isinstance(parameters, dict):
            result["status"] = "Failed"
            return result, "parameters must be a dictionary"

        target = parameters.get("target_replicas", 0)

        if type(target) is not int or target < 0:
            result["status"] = "Failed"
            return result, "target_replicas must be a nonnegative integer"

        result["target_replicas"] = target

        apps_api = API["apps"]

        # 2. Retrieve Deployment and record UID
        deployment, error = read_namespaced_deployment(
            vi=apps_api,
            name=deployment_name,
            namespace=namespace
        )

        if error:
            result["status"] = "Failed"
            return result, error

        uid = deployment.metadata.uid
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

        # Ensure Deployment has not changed
        if scale.metadata.uid != uid:
            result["status"] = "Failed"
            return result, "Deployment changed while reading its scale"

        original = scale.spec.replicas

        if original is None:
            original = deployment.spec.replicas

        if original is None:
            result["status"] = "Failed"
            return result, "Could not read the Deployment's current replica count"

        result["original_replicas"] = original
        result["observed_replicas"] = (
            scale.status.replicas
            if scale.status is not None else None
        )

        # 4. Prevent accidental scaling up
        if target > original:
            result["status"] = "Failed"
            return result, (
                f"Refusing to scale up from {original} to {target}; "
                "this action only scales down"
            )

        # No changes needed
        if target == original:
            result["status"] = "Completed"
            issue["Execution_Status"] = "Completed"
            return result, None

        # 5. Scale Deployment
        patch_result, error = patch_namespaced_deployment_scale(
            vi=apps_api,
            name=deployment_name,
            namespace=namespace,
            body={
                "metadata": {
                    "resourceVersion": scale.metadata.resource_version
                },
                "spec": {
                    "replicas": target
                }
            }
        )

        if error:
            result["status"] = "Failed"
            return result, error

        result["scale_updated"] = True

        # 6. Verify updated Deployment scale
        updated, error = read_namespaced_deployment_scale(
            vi=apps_api,
            name=deployment_name,
            namespace=namespace
        )

        if error:
            result["status"] = "Verification Failed"
            return result, error

        # Verify Deployment UID has not changed
        if updated.metadata.uid != uid:
            result["status"] = "Verification Failed"
            return result, "Deployment UID changed during scaling"

        result["observed_replicas"] = (
            updated.status.replicas
            if updated.status is not None else None
        )

        # Verify requested replica count
        verified_replicas = updated.spec.replicas

        if verified_replicas is None:
            verified_replicas = 0

        if verified_replicas != target:
            result["status"] = "Verification Failed"
            return result, (
                f"Requested {target} replicas, but the Deployment "
                f"currently specifies {verified_replicas}"
            )
        
        # 7. Mark action completed
        result["status"] = "Completed"
        issue["Execution_Status"] = "Completed"

        return result, None

    except ApiException as error:
        result["status"] = (
            "Partial Failure" if result["scale_updated"] else "Failed"
        )
        return result, (
            f"Kubernetes API error ({error.status}): {error.reason}"
        )

    except Exception as error:
        result["status"] = (
            "Partial Failure" if result["scale_updated"] else "Failed"
        )
        return result, str(error)

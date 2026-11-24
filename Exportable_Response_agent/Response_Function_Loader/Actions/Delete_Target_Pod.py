from kubernetes import client
from ..Kubernetes_API_calls.Kube_API_calls import (
    read_namespaced_pod,
    delete_namespaced_pod,
)


def delete_target_pod(issue, Time, parameters, API):
    """Request pod deletion, checking the pod UID to avoid deleting replacements.

    An owning Deployment/ReplicaSet may create another pod automatically.
    Returns (result, error).
    """
    namespace = issue["Namespace"]
    pod_name = issue["Resource_name"]

    result = {
        "pod": pod_name,
        "namespace": namespace,
        "status": "Pending",
    }

    pod, error = read_namespaced_pod(API["core"], pod_name, namespace)
    if error:
        return result, error

    # Refuse to delete a different pod that happens to reuse this name.
    expected_uid = (issue.get("Execution_Result") or {}).get("pod_uid")
    if expected_uid and pod.metadata.uid != expected_uid:
        return result, "Pod UID differs from the previously recorded target"

    result["pod_uid"] = pod.metadata.uid


    body = client.V1DeleteOptions(
        preconditions=client.V1Preconditions(uid=pod.metadata.uid)
    )
    _, error = delete_namespaced_pod(
        vi=API["core"],
        name=pod_name,
        namespace=namespace,
        body=body,
    )
    if error:
        result["status"] = "Failed"
        return result, error

    result["status"] = "Deletion Requested"
    return result, None

from ..Kubernetes_API_calls.Kube_API_calls import list_namespace_pods

def validate_pod_uid_deleted(issue, Time, parameters, API):
    """
    Validates whether the pod with the specified UID has been deleted.

    Returns:
        (True, None)  - Pod has been deleted
        (False, None) - Pod still exists
        (None, error) - API or configuration error
    """

    try:
        # Retrieve information from execution result
        execution_result = issue["Execution_Result"][str(issue["Current_Step"])]
        

        namespace = execution_result["namespace"]
        pod_uid = execution_result["pod_uid"]

        # List all pods in the namespace and check for the UID
        pods, error = list_namespace_pods(API["core"], namespace)
        if error:
            return None, error

        for pod in pods.items:
            if pod.metadata.uid == pod_uid:
                return False, None  # Pod still exists

        return True, None  # Pod has been deleted

    except Exception as e:
        return None, str(e)

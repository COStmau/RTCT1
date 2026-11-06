
from kubernetes.client.exceptions import ApiException


def validate_baseline_policy(issue, Time, parameters, API):
    """
    Verifies that the baseline NetworkPolicy exists.

    Retrieves policy name and namespace from Execution_Result.

    Returns:
        (True, None)  - Policy exists
        (False, None) - Policy does not exist
        (None, error) - API or configuration error
    """

    try:
        # Retrieve information from execution result
        execution_result = issue["Execution_Result"]

        namespace = execution_result["namespace"]
        policy_name = execution_result["baseline_policy"]

        # Check whether policy exists
        try:
            policy = API["networking"].read_namespaced_network_policy(
                name=policy_name,
                namespace=namespace
            )

            return True, None

        except ApiException as e:
            # 404 means policy does not exist
            if e.status == 404:
                return False, None

            return None, str(e)

    except Exception as e:
        return None, str(e)
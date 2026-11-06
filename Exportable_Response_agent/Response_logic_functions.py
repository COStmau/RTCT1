


from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

def initialize_kubernetes():
    """
    Initialize Kubernetes API interfaces.
    Returns a dictionary of reusable clients.
    """

    try:
        # When the agent runs as a Kubernetes pod
        config.load_incluster_config()
        print("Loaded in-cluster configuration")

    except ConfigException:
        # When developing locally with Minikube
        config.load_kube_config()
        print("Loaded local kubeconfig")

    # One shared underlying API client
    api_client = client.ApiClient()

    apis = {
        "core": client.CoreV1Api(api_client),
        "networking": client.NetworkingV1Api(api_client),
        "apps": client.AppsV1Api(api_client)
    }

    return api_client, apis


#Should be in a completed state as tests passed:
def execute_tier(issue, Time, Actions):
    """
    Inputs:
        issue: Dictionary containing issue information
        Time: Current time
        Actions: Dictionary mapping action names to functions

    Outputs:
        result: Result returned by the action, or None on failure
        error: None if successful, error description otherwise
    """

    action_name = issue.get("Action")

    # Check if action exists
    if action_name not in Actions:
        return None, f"Unknown action: {action_name}"

    try:
        # Execute selected action
        result, error = Actions[action_name](issue, Time)

        if error is not None:
            return result, error

        return result, None

    except Exception as e:
        return None, str(e)

#Needs work and testing:
def validate_tier(issue, Time, Validations):
    """
    Returns:
        issue, error | issue will be updated and error will be in case error occurs.
    """

    try:
        validation_name = issue["Validation"]

        if validation_name not in Validations:
            return issue, f"Unknown validation: {validation_name}"

        result,error = Validations[validation_name](issue, Time)

        return result, error

    except Exception as e:
        return issue, str(e)

#Needs work and testing:
def escalate_tier_or_descalate(issue, Time, DandELists):
    """
    Inputs:
        issue: Dictionary containing issue information
        Time: Current time
        DandELists: Dictionary mapping escalation or descalation names to functions

    Returns:
        issue: Updated issue dictionary
        error: None if successful, error description otherwise
    """

    try:
        escalation_name = issue["Escalation"]

        if escalation_name not in DandELists:
            return issue, f"Unknown escalation: {escalation_name}"

        # Execute escalation function
        issue, error = DandELists[escalation_name](issue, Time)

        return issue, error

    except Exception as e:
        return issue, str(e)



    
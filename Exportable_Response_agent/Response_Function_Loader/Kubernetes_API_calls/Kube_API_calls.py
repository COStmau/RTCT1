from kubernetes import client, config
from .Error_Handling import safe_api_call

def list_namespace_pods(vi,namespace="default"): #List pods in a specific namespace

    return safe_api_call(vi.list_namespaced_pod, namespace=namespace, watch=False) #Retrieves a list of all pods in the specified namespace and returns the result of the listing operation

def get_pod_names(vi,namespace="default"): #Get the names of all pods in a specific namespace
    ret = safe_api_call(vi.list_namespaced_pod, namespace=namespace, watch=False) #Retrieves a list of all pods in the specified namespace
    if ret[0] is None: #Checks if the API call was successful
        return ret #Returns an empty list if the API call failed
    pod_names = [pod.metadata.name for pod in ret[0].items] #Extracts the names of the pods from the list of pod objects
    return pod_names, None #Returns a list of pod names in the specified namespace

def read_namespace_pod(vi,name, namespace="default"): #inspects a specific pod

    return safe_api_call(vi.read_namespaced_pod, name=name, namespace=namespace) #Retrieves the details of a specific pod in the specified namespace and returns the result of the inspection operation

def patch_namespace_pod(vi, name, body, namespace="default"): # Modifies an existing pod

    return safe_api_call(vi.patch_namespaced_pod, name=name, namespace=namespace, body=body)

def read_namespaced_pod_status(vi,name, namespace="default"): #Reads the status of a specific pod.
    
    ret = safe_api_call(vi.read_namespaced_pod_status, name=name, namespace=namespace) #Retrieves the status of a specific pod in the specified namespace
    return ret #Returns the pod status object for the specified pod


#Requires further testing: (Currently having issues reading pod logs for Response Agent.)
def read_pod_log(vi,name, namespace="default"): #Reads the log of a specific pod.
    ret = vi.read_namespaced_pod_log(name=name, namespace=namespace) #Retrieves the log of a specific pod in the specified namespace
    return ret #Returns the log of the specified pod


def delete_namespaced_pod(vi, name, namespace="default"): #Deletes a specific pod.

    return safe_api_call(vi.delete_namespaced_pod, name=name, namespace=namespace) #Deletes a specific pod in the specified namespace and returns the result of the deletion operation

def list_deployments(vi,namespace="default"): #List deployments in a specific namespace

    return safe_api_call(vi.list_namespaced_deployment, namespace=namespace, watch=False) #Retrieves a list of all deployments in the specified namespace and returns the result of the listing operation

def read_namespaced_deployment(vi,name, namespace="default"): #inspects a specific deployment

    return safe_api_call(vi.read_namespaced_deployment, name=name, namespace=namespace) #Retrieves the details of a specific deployment in the specified namespace and returns the result of the inspection operation

def patch_namespaced_deployment_scale(vi, name, namespace="default", body=None): #Patches the scale of a specific deployment

    return safe_api_call(vi.patch_namespaced_deployment_scale, name=name, namespace=namespace, body=body) #Patches the scale of a specific deployment in the specified namespace and returns the result of the patch operation

def create_network_policy(vi, namespace="default", body=None): #Creates a new network policy
    
    return safe_api_call(vi.create_namespaced_network_policy, namespace=namespace, body=body) #Creates a new network policy in the specified namespace and returns the result of the creation operation

def delete_network_policy(vi, name, namespace="default"): #Deletes a specific network policy
    
    return safe_api_call(vi.delete_namespaced_network_policy, name=name, namespace=namespace) #Deletes a specific network policy in the specified namespace and returns the result of the deletion operation

def list_network_policies(vi, namespace="default"): #List network policies in a specific namespace
    
    return safe_api_call(vi.list_namespaced_network_policy, namespace=namespace, watch=False) #Retrieves a list of all network policies in the specified namespace and returns the result of the listing operation

def read_network_policy(vi, name, namespace="default"): #Reads a specific network policy
    
    return safe_api_call(vi.read_namespaced_network_policy, name=name, namespace=namespace) #Retrieves the details of a specific network policy in the specified namespace and returns the result of the inspection operation

def patch_network_policy(vi, name, body, namespace="default"):  # Modifies an existing NetworkPolicy

    return safe_api_call(
        vi.patch_namespaced_network_policy,
        name=name,
        namespace=namespace,
        body=body
    )  # Updates the specified NetworkPolicy using the provided patch body

def list_events(vi, namespace="default"): #List events in a specific namespace
    
    return safe_api_call(vi.list_namespaced_event, namespace=namespace, watch=False) #Retrieves a list of all events in the specified namespace and returns the result of the listing operation

def list_all_pods_all_namespaces(vi): #List all pods across all namespaces
    
    ret = safe_api_call(vi.list_pod_for_all_namespaces, watch=False) #Retrieves a list of all pods across all namespaces and returns the result of the listing operation
    if ret[0] is None: #Checks if the API call was successful
        return ret
    return (ret[0].items, ret[1]) #Returns a list of all pods across all namespaces

def list_of_all_pods_all_namespaces(vi): #Returns a list of all pods across all namespaces

    pods = safe_api_call(vi.list_pod_for_all_namespaces, watch=False) #Retrieves a list of all pods across all namespaces
    if( pods[0] is None): #Checks if the API call was successful
        return pods #Returns an empty list if the API call failed
    pod_list = [
    [pod.metadata.name, pod.metadata.namespace]
    for pod in pods[0]
    ]
    return pod_list, None

def create_namespaced_pod(vi, namespace="default", body=None): #Creates a new pod in a specific namespace
    
    return safe_api_call(vi.create_namespaced_pod, namespace=namespace, body=body) #Creates a new pod in the specified namespace and returns the result of the creation operation

def get_pod_labels(vi, pod_name, namespace="default"): #Retrieves the labels of a specific pod in a specific namespace
    pod = safe_api_call(vi.read_namespaced_pod, name=pod_name, namespace=namespace) #Reads the specified pod in the specified namespace
    if pod[0] is None: #Checks if the API call was successful
        return pod #Returns an empty dictionary if the API call failed
    return pod[0].metadata.labels, None #Returns the labels of the specified pod

def add_pod_label(vi, pod_name, namespace, label_key, label_value): #Adds a label to a specific pod in a specific namespace

    """
    Add a label to a specific pod.

    :param pod_name: Name of the pod
    :param namespace: Namespace of the pod
    :param label_key: Key of the label to add
    :param label_value: Value of the label to add
    :return: Updated pod object
    """
    # Read the current pod object
    pod = read_namespace_pod(vi, pod_name, namespace="default")
    if( pod[0] is None):
        print("Error occurred while reading the pod:", pod[1])
        return pod  # Return the error if reading the pod failed
    # Add or update the label
    pod = pod[0]
    if not pod.metadata.labels:
        pod.metadata.labels = {}
    
    pod.metadata.labels[label_key] = label_value

    # Patch the pod with the updated labels
    body = {
        "metadata": {
            "labels": pod.metadata.labels
        }
    }
    updated_pod = safe_api_call(vi.patch_namespaced_pod, name=pod_name, namespace=namespace, body=body)
    
    return updated_pod


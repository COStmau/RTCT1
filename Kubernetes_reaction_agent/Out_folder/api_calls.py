from kubernetes import client, config


def list_namespace_pods(vi,namespace="default"): #List pods in a specific namespace
    ret = vi.list_namespaced_pod(namespace=namespace, watch=False) #Retrieves a list of all pods in the specified namespace
    return ret.items #Returns a list of pod objects in the specified namespace

def get_pod_names(vi,namespace="default"): #Get the names of all pods in a specific namespace
    ret = vi.list_namespaced_pod(namespace=namespace, watch=False) #Retrieves a list of all pods in the specified namespace
    pod_names = [pod.metadata.name for pod in ret.items] #Extracts the names of the pods from the list of pod objects
    return pod_names #Returns a list of pod names in the specified namespace

def read_namespace_pod(vi,name, namespace="default"): #inspects a specific pod
    ret = vi.read_namespaced_pod(name=name, namespace=namespace) #Retrieves the details of a specific pod in the specified namespace
    return ret #Returns the pod object for the specified pod

def read_namespaced_pod_status(vi,name, namespace="default"): #Reads the status of a specific pod.
    ret = vi.read_namespaced_pod_status(name=name, namespace=namespace) #Retrieves the status of a specific pod in the specified namespace
    return ret #Returns the pod status object for the specified pod

def read_pod_log(vi,name, namespace="default"): #Reads the log of a specific pod.
    ret = vi.read_namespaced_pod_log(name=name, namespace=namespace) #Retrieves the log of a specific pod in the specified namespace
    return ret #Returns the log of the specified pod

def delete_namespaced_pod(vi, name, namespace="default"): #Deletes a specific pod.
    ret = vi.delete_namespaced_pod(name=name, namespace=namespace) #Deletes a specific pod in the specified namespace
    return ret #Returns the result of the deletion operation

def list_deployments(vi,namespace="default"): #List deployments in a specific namespace
    ret = vi.list_namespaced_deployment(namespace=namespace, watch=False) #Retrieves a list of all deployments in the specified namespace
    return ret.items #Returns a list of deployment objects in the specified namespace

def read_namespaced_deployment(vi,name, namespace="default"): #inspects a specific deployment
    ret = vi.read_namespaced_deployment(name=name, namespace=namespace) #Retrieves the details of a specific deployment in the specified namespace
    return ret #Returns the deployment object for the specified deployment

def patch_namespaced_deployment_scale(vi, name, namespace="default", body=None): #Patches the scale of a specific deployment
    ret = vi.patch_namespaced_deployment_scale(name=name, namespace=namespace, body=body)
    return ret #Returns the result of the scale patch operation

def create_network_policy(vi, namespace="default", body=None): #Creates a new network policy
    ret = vi.create_namespaced_network_policy(namespace=namespace, body=body)
    return ret #Returns the result of the network policy creation operation

def delete_network_policy(vi, name, namespace="default"): #Deletes a specific network policy
    ret = vi.delete_namespaced_network_policy(name=name, namespace=namespace)
    return ret #Returns the result of the network policy deletion operation

def list_network_policies(vi, namespace="default"): #List network policies in a specific namespace
    ret = vi.list_namespaced_network_policy(namespace=namespace, watch=False) #Retrieves a list of all network policies in the specified namespace
    return ret.items #Returns a list of network policy objects in the specified namespace

def read_network_policy(vi, name, namespace="default"): #Reads a specific network policy
    ret = vi.read_namespaced_network_policy(name=name, namespace=namespace) #Retrieves the details of a specific network policy in the specified namespace
    return ret #Returns the network policy object for the specified network policy

def list_events(vi, namespace="default"): #List events in a specific namespace
    ret = vi.list_namespaced_event(namespace=namespace, watch=False) #Retrieves a list of all events in the specified namespace
    return ret.items #Returns a list of event objects in the specified namespace

def list_all_pods_all_namespaces(vi): #List all pods across all namespaces
    ret = vi.list_pod_for_all_namespaces(watch=False) #Retrieves a list of all pods across all namespaces
    return ret.items #Returns a list of pod objects across all namespaces

def list_of_all_pods_all_namespaces(vi): #Returns a list of all pods across all namespaces
    pods = list_all_pods_all_namespaces(vi) #Retrieves a list of all pods across all namespaces
    pod_list = [
    [pod.metadata.name, pod.metadata.namespace]
    for pod in pods
    ]
    return pod_list
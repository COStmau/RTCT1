from Response_scripts.api_calls import *



def define_network_policy(name, namespace, pod_labels, policy_types, ingress_rules=None, egress_rules=None):
    """
    Define a Kubernetes NetworkPolicy object.

    :param name: Name of the NetworkPolicy
    :param namespace: Namespace in which to create the NetworkPolicy
    :param pod_labels: Dictionary specifying the pod labels (e.g., {"app": "my-app"})
    :param policy_types: List of policy types (e.g., ["Ingress", "Egress"])
    :param ingress_rules: List of ingress rules (optional)
    :param egress_rules: List of egress rules (optional)
    :return: V1NetworkPolicy object
    """
    body = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": { #Name of the NetworkPolicy and the namespace in which it will be created
            "name": name,
            "namespace": namespace
        },
        "spec": {
            "podSelector": { #Labels to select the pods to which this policy applies
                "matchLabels": {
                    "app": pod_labels
                }
            },
            "policyTypes": policy_types,
            "ingress": ingress_rules if ingress_rules is not None else [],
            "egress": egress_rules if egress_rules is not None else []
        }
    }   
    return body

def apply_bandwidth_limit(vi, pod_name, namespace, bandwidth_limit):
    """
    Apply a bandwidth limit to a specific pod.

    :param pod_name: Name of the pod
    :param namespace: Namespace of the pod
    :param bandwidth_limit: Bandwidth limit in Mbps (e.g., 10 for 10 Mbps)
    :return: Updated pod object
    """
    # Read the current pod object
    pod = read_namespace_pod(vi, pod_name, namespace)
    if pod[0] is None:
        print("Error occurred while reading the pod:", pod[1])
        return pod  # Return the error if reading the pod failed
    pod = pod[0]
    # Add or update the bandwidth limit annotation
    if not pod.metadata.annotations:
        pod.metadata.annotations = {}
    
    pod.metadata.annotations["kubernetes.io/ingress-bandwidth"] = f"{bandwidth_limit}M"
    pod.metadata.annotations["kubernetes.io/egress-bandwidth"] = f"{bandwidth_limit}M"

    # Patch the pod with the updated annotations
    body = {
        "metadata": {
            "annotations": pod.metadata.annotations
        }
    }
    updated_pod = safe_api_call(vi.patch_namespaced_pod, name=pod_name, namespace=namespace, body=body)
    
    
    return updated_pod
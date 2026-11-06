from ..Kubernetes_API_calls.Kube_API_calls import (
    read_namespace_pod,
    list_network_policies,
    create_network_policy,
    patch_network_policy,
    patch_namespace_pod
)

from datetime import datetime
import time
import hashlib
import re
import ipaddress
from kubernetes import client
from kubernetes.client.rest import ApiException


def restrict_ingress_egress_baseline(issue, Time, parameters,API):
    #creates a ingress rule for the current pod restricting ingress to baseline communicaiton.

    #Names and labels used throughout execution policy:
    namespace = issue["Namespace"]
    pod_name = issue["Resource_name"]

    exclusion_label = generate_exclusion_label(issue)
    suffix = exclusion_label.rsplit("-", 1)[-1]
    policy_name = f"baseline-{suffix}"

    #Will be added to issue for postarity.
    result = {
        "pod": pod_name,
        "namespace": namespace,
        "exclusion_label": exclusion_label,
        "baseline_policy": policy_name,
        "modified_policies": [],
        "status": "Pending"
    }

    #Gets the current restrictions on a specific pod:
    pod_info, error = check_pod_restrictions(issue, Time, parameters, API)

    if error:
        return result, error

    matching_policies = pod_info["matching_policies"]
    pod_labels = pod_info["pod_labels"]

    # Prevent duplicate application of policy per pod
    if exclusion_label in pod_labels:
        return result, "Pod already has the exclusion label"

    # Check whether baseline policy already exists
    policies, error = list_network_policies(API["networking"], namespace)

    if error:
        return result, error

    #Check for if policy is in list of policies before applicaiton.
    policy_lookup = {
        p.metadata.name: p for p in policies.items
    }
    #Errors out if it is
    if policy_name in policy_lookup:
        return result, "Baseline policy already exists"

    #List of normal traffic. Will need to be subbed for normal traffic later.
    normal_traffic, error = get_normal_traffic(
    pod_name,
    namespace
)

    if error:
        return result, error

    baseline_labels = {
        exclusion_label: "true"
    }

    #Updates pod to remove from prexsisting policies.
    for policy_info in matching_policies:

        name = policy_info["name"]
        policy = policy_lookup[name]

        matches, error = selector_matches_pod(
            selector=policy.spec.pod_selector,
            pod_labels=pod_labels,
            issue=issue,
            policy=policy,
            networking_api=API["networking"],
            namespace=namespace,
            apply=True
        )

        if error:
            result["status"] = "Partial Failure"
            return result, error

        if matches:
            result["modified_policies"].append(name)

    baseline, error = create_baseline_network_policy(
        namespace=namespace,
        policy_name=policy_name,
        pod_labels=baseline_labels,
        normal_traffic=normal_traffic,
        apply=True,
        networking_api=API["networking"]
    )

    if error:
        result["status"] = "Partial Failure"
        return result, error

    label_result, error = apply_exclusion_label(
        issue, API
    )

    if error:
        result["status"] = "Partial Failure"
        return result, error

    pod, error = read_namespace_pod(
        API["core"], pod_name, namespace
    )

    if error:
        result["status"] = "Verification Failed"
        return result, error

    if pod.metadata.uid != pod_info["pod_uid"]:
        result["status"] = "Verification Failed"
        return result, "Pod UID changed during operation"

    if (pod.metadata.labels or {}).get(exclusion_label) != "true":
        result["status"] = "Verification Failed"
        return result, "Exclusion label not found on pod"

    result["status"] = "Completed"
    issue["Execution_Status"] = "Completed"
    return result, None


def generate_exclusion_label(issue):
    issue_id = str(issue["Issue_ID"])
    pod_name = str(issue["Resource_name"])

    raw_name = f"{issue_id}-{pod_name}-temp-restriction"
    safe_name = re.sub(
        r"[^a-z0-9-]", "-", raw_name.lower()
    ).strip("-")

    # Short hash prevents collisions when truncating
    suffix = hashlib.sha256(
        raw_name.encode()
    ).hexdigest()[:10]

    label_name = f"{safe_name[:52].rstrip('-')}-{suffix}"

    return f"response-agent.example.com/{label_name}"


def check_pod_restrictions(issue, Time, parameters,API):
    namespace = issue["Namespace"]
    pod_name = issue["Resource_name"]

    pod, error = read_namespace_pod(
        API["core"], pod_name, namespace
    )

    if error:
        return None, error

    pod_labels = pod.metadata.labels or {}

    # Retrieve all policies in the namespace
    policies, error = list_network_policies(
        API["networking"], namespace
    )

    if error:
        return None, error

    matching_policies = []

    # Examine every NetworkPolicy
    for policy in policies.items:

        selector = policy.spec.pod_selector
        matches, error = selector_matches_pod(selector, pod_labels)

        if error:
            return None, error

        if matches:

            matching_policies.append({
                "name": policy.metadata.name,
                "namespace": namespace,
                "resource_version":
                    policy.metadata.resource_version,
                "policy_types":
                    policy.spec.policy_types,
                "pod_selector": {
                    "matchLabels":
                        selector.match_labels or {},
                    "matchExpressions": [
                        {
                            "key": expr.key,
                            "operator": expr.operator,
                            "values": expr.values or []
                        }
                        for expr in (
                            selector.match_expressions or []
                        )
                    ]
                }
            })

    result = {
        "pod_name": pod_name,
        "pod_uid": pod.metadata.uid,
        "namespace": namespace,
        "pod_labels": pod_labels,
        "matching_policies": matching_policies,
        "timestamp": Time.isoformat()
    }

    return result, None


def apply_exclusion_label(issue, API):
    """
    Generates an issue-specific exclusion label and
    applies it to the target Kubernetes pod.

    Inputs:
        issue: Dictionary containing Issue_ID,
               Resource_name, and Namespace
        API: Dictionary containing Kubernetes API clients

    Returns:
        (result, error)
    """

    try:
        namespace = issue["Namespace"]
        pod_name = issue["Resource_name"]

        # Generate exclusion label
        exclusion_label = generate_exclusion_label(issue)

        # Retrieve target pod
        pod, error = read_namespace_pod(
            API["core"],
            pod_name,
            namespace
        )

        if error:
            return None, error

        # Check whether label already exists
        current_labels = pod.metadata.labels or {}

        if current_labels.get(exclusion_label) == "true":
            return {
                "pod_name": pod_name,
                "namespace": namespace,
                "exclusion_label": exclusion_label,
                "status": "Already Applied"
            }, None

        # Add label to pod metadata
        body = {
            "metadata": {
                "labels": {
                    exclusion_label: "true"
                }
            }
        }

        # Patch pod
        result, error = patch_namespace_pod(
            vi=API["core"],
            name=pod_name,
            body=body,
            namespace=namespace
        )

        if error:
            return None, error

        return {
            "pod_name": result.metadata.name,
            "namespace": namespace,
            "exclusion_label": exclusion_label,
            "status": "Applied"
        }, None

    except Exception as error:
        return None, str(error)



def selector_matches_pod(
    selector,
    pod_labels,
    issue=None,
    policy=None,
    networking_api=None,
    namespace=None,
    apply=False
):
    """
    Checks whether a NetworkPolicy selects a pod.

    If matching, optionally generates an issue-specific
    exclusion label and adds a DoesNotExist expression
    to the NetworkPolicy's podSelector.

    Returns:
        (matches, error)
    """

    pod_labels = pod_labels or {}

    if selector is None:
        return False, None

    # -------------------------------
    # 1. Check matchLabels
    # -------------------------------
    for key, value in (selector.match_labels or {}).items():
        if pod_labels.get(key) != value:
            return False, None

    # -------------------------------
    # 2. Check matchExpressions
    # -------------------------------
    for expression in (selector.match_expressions or []):
        key = expression.key
        operator = expression.operator
        values = expression.values or []

        if operator == "In":
            if key not in pod_labels or pod_labels[key] not in values:
                return False, None

        elif operator == "NotIn":
            if key in pod_labels and pod_labels[key] in values:
                return False, None

        elif operator == "Exists":
            if key not in pod_labels:
                return False, None

        elif operator == "DoesNotExist":
            if key in pod_labels:
                return False, None

        else:
            return False, (
                f"Unsupported selector operator: {operator}"
            )

    # Pod matches the original policy selector
    matches = True

    # Only check matching, no modification
    if not apply:
        return matches, None

    # -------------------------------
    # 3. Validate modification inputs
    # -------------------------------
    if (
        issue is None
        or policy is None
        or networking_api is None
        or not namespace
    ):
        return matches, "Missing policy update parameters"

    try:
        # Generate issue-specific exclusion label
        exclusion_label = generate_exclusion_label(issue)

        # Preserve existing expressions
        expressions = [
            {
                "key": expr.key,
                "operator": expr.operator,
                "values": expr.values or []
            }
            for expr in (selector.match_expressions or [])
        ]

        # Check for conflicting use of exclusion key
        if exclusion_label in (selector.match_labels or {}):
            return matches, (
                f"Policy {policy.metadata.name} already "
                f"uses exclusion label in matchLabels"
            )

        # Prevent duplicate exclusions
        existing = [
            expr for expr in expressions
            if expr["key"] == exclusion_label
        ]

        if existing:
            if any(
                expr["operator"] != "DoesNotExist"
                for expr in existing
            ):
                return matches, (
                    "Conflicting exclusion expression"
                )

            return matches, None

        # -------------------------------
        # 4. Add exclusion expression
        # -------------------------------
        expressions.append({
            "key": exclusion_label,
            "operator": "DoesNotExist"
        })

        updated_selector = {
            "matchLabels": selector.match_labels or {},
            "matchExpressions": expressions
        }

        # -------------------------------
        # 5. Patch NetworkPolicy
        # -------------------------------
        body = {
            "metadata": {
                "resourceVersion":
                    policy.metadata.resource_version
            },
            "spec": {
                "podSelector": updated_selector
            }
        }

        result, error = patch_network_policy(
            vi=networking_api,
            name=policy.metadata.name,
            body=body,
            namespace=namespace
        )

        if error:
            return matches, error

        return matches, None

    except Exception as error:
        return matches, str(error)



def get_normal_traffic(pod_name, namespace):
    """
    Retrieves normal ingress and egress traffic IPs
    for a specified pod.

    Inputs:
        pod_name: Name of target pod
        namespace: Kubernetes namespace

    Returns:
        (normal_traffic, error)
    """

    try:
        # Placeholder for detection agent data
        normal_traffic = {
            "ingress": [
                "192.168.1.100",
                "192.168.1.101"
            ],
            "egress": [
                "192.168.1.200",
                "10.0.0.50"
            ]
        }

        return normal_traffic, None

    except Exception as error:
        return None, str(error)


def create_baseline_network_policy(
    namespace,
    policy_name,
    pod_labels,
    normal_traffic,
    apply=False,
    networking_api=None
):
    """
    Create a NetworkPolicy from predefined normal traffic.

    Inputs:
        namespace: Kubernetes namespace
        policy_name: Name for the new NetworkPolicy
        pod_labels: Labels identifying target pods
        normal_traffic: Dictionary containing ingress/egress IPs
        apply: False = generate only, True = create in cluster
        networking_api: Existing NetworkingV1Api instance (optional)

    Returns:
        (result, error)
    """

    try:
        if not pod_labels:
            return None, "Target pod labels cannot be empty"

        # Convert IP addresses to CIDR notation
        def create_ip_blocks(addresses):
            blocks = []

            for address in addresses:
                network = ipaddress.ip_network(
                    address, strict=False
                )

                blocks.append({
                    "ipBlock": {
                        "cidr": str(network)
                    }
                })

            return blocks

        ingress_ips = normal_traffic["ingress"]
        egress_ips = normal_traffic["egress"]

        ingress_blocks = create_ip_blocks(ingress_ips)
        egress_blocks = create_ip_blocks(egress_ips)

        # Empty lists mean deny all in that direction.
        ingress_rules = (
            [{"from": ingress_blocks}]
            if ingress_blocks else []
        )

        egress_rules = (
            [{"to": egress_blocks}]
            if egress_blocks else []
        )

        # Construct NetworkPolicy
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": policy_name,
                "namespace": namespace
            },
            "spec": {
                "podSelector": {
                    "matchLabels": pod_labels
                },
                "policyTypes": [
                    "Ingress",
                    "Egress"
                ],
                "ingress": ingress_rules,
                "egress": egress_rules
            }
        }

        # Preview without modifying the cluster
        if not apply:
            return policy, None

        # Create policy in Kubernetes
        api = networking_api or client.NetworkingV1Api()

        result, error = create_network_policy(
            api,
            namespace=namespace,
            body=policy
        )

        if error:
            return None, error
        return result.to_dict(), None

    except (ValueError, KeyError, TypeError) as error:
        return None, f"Invalid baseline: {error}"

    except ApiException as error:
        return None, f"Kubernetes API error: {error}"

    except Exception as error:
        return None, str(error)

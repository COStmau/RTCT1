# Place this in the same module as generate_exclusion_label and selector_matches_pod,
# or import those helpers from your existing Pod isolation action.
# Assumes imports: create_network_policy, list_network_policies,
# patch_namespace_pod, kubernetes.client.rest.ApiException.


import hashlib

from datetime import datetime
import time
import hashlib
import re
import ipaddress
from kubernetes import client
from kubernetes.client.rest import ApiException

from ..Kubernetes_API_calls.Kube_API_calls import (
    read_namespaced_pod,
    list_network_policies,
    create_network_policy,
    patch_network_policy,
    patch_namespace_pod
)

def get_deployment_pods(deployment, API, namespace):
    """Get Pods owned by any ReplicaSet controlled by this Deployment."""
    replicasets = API["apps"].list_namespaced_replica_set(namespace=namespace).items
    rs_uids = {
        rs.metadata.uid
        for rs in replicasets
        if any(
            ref.kind == "Deployment" and ref.uid == deployment.metadata.uid
            and ref.controller
            for ref in (rs.metadata.owner_references or [])
        )
    }

    pods = API["core"].list_namespaced_pod(namespace=namespace).items
    return [
        pod for pod in pods
        if any(
            ref.kind == "ReplicaSet" and ref.uid in rs_uids
            and ref.controller
            for ref in (pod.metadata.owner_references or [])
        )
    ]


def isolate_deployment(issue, Time, parameters, API):
    namespace = issue["Namespace"]
    deployment_name = issue["Resource_name"]
    exclusion_label = generate_exclusion_label(issue)
    policy_name = f"isolate-{exclusion_label.rsplit('-', 1)[-1]}"

    result = {
        "deployment": deployment_name,
        "namespace": namespace,
        "deployment_uid": None,
        "exclusion_label": exclusion_label,
        "isolation_policy": policy_name,
        "isolation_policy_created": False,
        "modified_policies": [],
        "pods_labeled": [],
        "deployment_template_patched": False,
        "status": "Pending",
    }

    try:
        deployment = API["apps"].read_namespaced_deployment(
            name=deployment_name, namespace=namespace
        )
        result["deployment_uid"] = deployment.metadata.uid
        template_labels = deployment.spec.template.metadata.labels or {}

        if exclusion_label in template_labels:
            return result, "Deployment is already labeled for this issue"

        pods = get_deployment_pods(deployment, API, namespace)
        policies, error = list_network_policies(API["networking"], namespace)
        if error:
            return result, error
        if any(p.metadata.name == policy_name for p in policies.items):
            return result, "Isolation policy already exists"

        # Check both live Pod labels and the template (handles zero replicas).
        labels_to_check = [template_labels] + [p.metadata.labels or {} for p in pods]
        matching_policies = []
        for policy in policies.items:
            for labels in labels_to_check:
                matches, error = selector_matches_pod(policy.spec.pod_selector, labels)
                if error:
                    return result, error
                if matches:
                    matching_policies.append((policy, labels))
                    break

        deny_all_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": policy_name, "namespace": namespace},
            "spec": {
                "podSelector": {"matchLabels": {exclusion_label: "true"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }

        _, error = create_network_policy(
            API["networking"], namespace=namespace, body=deny_all_policy
        )
        if error:
            return result, error
        result["isolation_policy_created"] = True

        # Reuse your existing helper; no Pod has the exclusion label yet.
        for policy, labels in matching_policies:
            _, error = selector_matches_pod(
                selector=policy.spec.pod_selector,
                pod_labels=labels,
                issue=issue,
                policy=policy,
                networking_api=API["networking"],
                namespace=namespace,
                apply=True,
            )
            if error:
                result["status"] = "Partial Failure"
                return result, error
            result["modified_policies"].append(policy.metadata.name)

        def label_pod(pod):
            if (pod.metadata.labels or {}).get(exclusion_label) == "true":
                return None
            _, err = patch_namespace_pod(
                vi=API["core"],
                name=pod.metadata.name,
                namespace=namespace,
                body={"metadata": {"labels": {exclusion_label: "true"}}},
            )
            if not err:
                result["pods_labeled"].append({
                    "name": pod.metadata.name, "uid": pod.metadata.uid
                })
            return err

        # First label existing Pods.
        for pod in pods:
            error = label_pod(pod)
            if error:
                result["status"] = "Partial Failure"
                return result, error

        # Also label new Pods created by the Deployment.
        # This changes spec.template and triggers a rolling update.
        API["apps"].patch_namespaced_deployment(
            name=deployment_name,
            namespace=namespace,
            body={"spec": {"template": {"metadata": {
                "labels": {exclusion_label: "true"}
            }}}},
        )
        result["deployment_template_patched"] = True

        # Catch Pods created during the operation from older ReplicaSets.
        for pod in get_deployment_pods(deployment, API, namespace):
            error = label_pod(pod)
            if error:
                result["status"] = "Partial Failure"
                return result, error

        # Verify that the template carries the persistent isolation label.
        updated = API["apps"].read_namespaced_deployment(
            name=deployment_name, namespace=namespace
        )
        if (updated.spec.template.metadata.labels or {}).get(exclusion_label) != "true":
            result["status"] = "Verification Failed"
            return result, "Deployment Pod template lacks isolation label"

        # Configuration-level check. Full network validation requires an
        # actual traffic test, and continuous reconciliation may be needed.
        current_pods = get_deployment_pods(updated, API, namespace)
        current_policies, error = list_network_policies(API["networking"], namespace)
        if error:
            result["status"] = "Verification Failed"
            return result, error
        if policy_name not in {p.metadata.name for p in current_policies.items}:
            result["status"] = "Verification Failed"
            return result, "Isolation policy is missing"

        for pod in current_pods:
            labels = pod.metadata.labels or {}
            if labels.get(exclusion_label) != "true":
                result["status"] = "Verification Failed"
                return result, f"Pod {pod.metadata.name} lacks isolation label"
            for policy in current_policies.items:
                if policy.metadata.name == policy_name:
                    continue
                # Deny-only policies do not grant traffic.
                if not (policy.spec.ingress or policy.spec.egress):
                    continue
                matches, error = selector_matches_pod(policy.spec.pod_selector, labels)
                if error:
                    result["status"] = "Verification Failed"
                    return result, error
                if matches:
                    result["status"] = "Verification Failed"
                    return result, (
                        f"Allowing policy {policy.metadata.name} still selects "
                        f"Pod {pod.metadata.name}"
                    )

        result["status"] = "Completed"
        issue["Execution_Status"] = "Completed"
        return result, None

    except Exception as error:
        result["status"] = "Partial Failure" if (
            result["isolation_policy_created"]
            or result["modified_policies"]
            or result["pods_labeled"]
            or result["deployment_template_patched"]
        ) else "Failed"
        return result, str(error)


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

#Checks if a network policy selector matches a pod's labels and optionally applies an exclusion label to the policy.
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

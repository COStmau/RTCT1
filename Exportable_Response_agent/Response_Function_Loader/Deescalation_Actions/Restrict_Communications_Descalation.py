
from ..Kubernetes_API_calls.Kube_API_calls import (
    read_namespaced_pod,
    list_network_policies,
    delete_network_policy,
    patch_network_policy,
    patch_namespace_pod
)

from kubernetes.client.rest import ApiException


# ============================================================
# HELPER: CHECK FOR KUBERNETES 404 ERRORS
# ============================================================

def is_not_found_error(error):
    """
    Determines whether an API error represents HTTP 404.

    Supports:
        - Kubernetes ApiException
        - Errors returned by safe_api_call()

    Returns:
        True if the resource was not found.
        False otherwise.
    """

    if isinstance(error, ApiException):
        return error.status == 404

    # Handle errors returned by safe_api_call()
    # Example: (NotFoundException(), "read_namespaced_pod",
    #           404, "Not Found")
    if isinstance(error, (tuple, list)):

        if len(error) >= 3 and str(error[2]) == "404":
            return True

        for item in error:
            if isinstance(item, ApiException):
                if item.status == 404:
                    return True

    return str(getattr(error, "status", "")) == "404"


# ============================================================
# MAIN DEESCALATION FUNCTION
# ============================================================

def undo_restrict_ingress_egress_baseline(
    issue, step_result, Time, parameters, API
):
    """
    Reverses network restrictions created by a response action.

    Steps:
        1. Restore the original NetworkPolicy selectors.
        2. Remove the exclusion label from the Pod if it exists.
        3. Delete the response-created NetworkPolicy.

    If the Pod was deleted:
        - Skip removing its exclusion label.
        - Continue cleaning up NetworkPolicies.
        - Do not recreate the Pod.

    Returns:
        (result, error)
    """

    result = {
        "policy_cleanup": None,
        "label_cleanup": None,
        "baseline_cleanup": None,
        "status": "Pending"
    }

    # --------------------------------------------------------
    # 1. Restore original NetworkPolicies
    # --------------------------------------------------------

    policy_result, error = remove_exclusion_expressions(
        step_result, API
    )

    result["policy_cleanup"] = policy_result

    if error:
        result["status"] = "Partial Failure"
        return result, error

    # --------------------------------------------------------
    # 2. Remove exclusion label from Pod
    # --------------------------------------------------------

    label_result, error = remove_exclusion_label(
        step_result, API
    )

    result["label_cleanup"] = label_result

    if error:
        result["status"] = "Partial Failure"
        return result, error

    # If the Pod has been deleted, remove_exclusion_label()
    # returns status "Pod Deleted - Skipped" with no error.
    # NetworkPolicy cleanup continues normally.

    # --------------------------------------------------------
    # 3. Delete response-created NetworkPolicy
    # --------------------------------------------------------

    baseline_result, error = delete_baseline_network_policy(
        step_result, API
    )

    result["baseline_cleanup"] = baseline_result

    if error:
        result["status"] = "Partial Failure"
        return result, error

    # --------------------------------------------------------
    # 4. Mark rollback completed
    # --------------------------------------------------------

    result["status"] = "Completed"

    return result, None


# ============================================================
# RESTORE ORIGINAL NETWORK POLICY SELECTORS
# ============================================================

def remove_exclusion_expressions(step_result, API):
    """
    Removes this action's exclusion expression from each
    NetworkPolicy modified during execution.

    Preserves all other selector expressions, including
    exclusions created by other response tiers.

    Missing policies are skipped.

    Returns:
        (result, error)
    """

    namespace = step_result["namespace"]
    exclusion_label = step_result["exclusion_label"]
    modified_policies = step_result["modified_policies"]

    result = {
        "restored_policies": [],
        "already_clean": [],
        "missing_policies": [],
        "failed_policies": [],
        "status": "Pending"
    }

    # --------------------------------------------------------
    # 1. Retrieve NetworkPolicies
    # --------------------------------------------------------

    policies, error = list_network_policies(
        API["networking"], namespace
    )

    if error:
        result["status"] = "Failed"
        return result, error

    policy_lookup = {
        policy.metadata.name: policy
        for policy in policies.items
    }

    # --------------------------------------------------------
    # 2. Process policies modified by this action
    # --------------------------------------------------------

    for policy_name in dict.fromkeys(modified_policies):

        # Policy may have already been deleted
        if policy_name not in policy_lookup:
            result["missing_policies"].append(policy_name)
            continue

        policy = policy_lookup[policy_name]
        selector = policy.spec.pod_selector

        # Preserve existing expressions
        expressions = [
            {
                "key": expr.key,
                "operator": expr.operator,
                "values": expr.values or []
            }
            for expr in (selector.match_expressions or [])
        ]

        # ----------------------------------------------------
        # 3. Remove only this action's exclusion expression
        # ----------------------------------------------------

        updated_expressions = [
            expr for expr in expressions
            if not (
                expr["key"] == exclusion_label
                and expr["operator"] == "DoesNotExist"
            )
        ]

        # Nothing needs to be removed
        if len(updated_expressions) == len(expressions):
            result["already_clean"].append(policy_name)
            continue

        updated_selector = {
            "matchLabels": selector.match_labels or {},
            "matchExpressions": updated_expressions
        }

        body = {
            "metadata": {
                "resourceVersion": policy.metadata.resource_version
            },
            "spec": {
                "podSelector": updated_selector
            }
        }

        # ----------------------------------------------------
        # 4. Apply updated NetworkPolicy selector
        # ----------------------------------------------------

        _, error = patch_network_policy(
            vi=API["networking"],
            name=policy_name,
            body=body,
            namespace=namespace
        )

        if error:
            result["failed_policies"].append({
                "name": policy_name,
                "error": str(error)
            })
            continue

        result["restored_policies"].append(policy_name)

    # --------------------------------------------------------
    # 5. Check for failures
    # --------------------------------------------------------

    if result["failed_policies"]:
        result["status"] = "Partial Failure"
        return result, (
            "Failed to restore one or more NetworkPolicies"
        )

    result["status"] = "Completed"

    return result, None


# ============================================================
# REMOVE EXCLUSION LABEL FROM POD
# ============================================================

def remove_exclusion_label(step_result, API):
    """
    Removes the action-specific exclusion label from a Pod.

    If the Pod no longer exists (404):
        - Skip label removal.
        - Return success.
        - Allow NetworkPolicy cleanup to continue.

    If the Pod exists:
        - Verify its UID.
        - Remove only the action-specific label.
        - Verify the label was removed.

    Other API errors are returned normally.

    Returns:
        (result, error)
    """

    namespace = step_result["namespace"]
    pod_name = step_result["pod"]
    exclusion_label = step_result["exclusion_label"]

    result = {
        "pod": pod_name,
        "namespace": namespace,
        "exclusion_label": exclusion_label,
        "status": "Pending"
    }

    # --------------------------------------------------------
    # 1. Retrieve target Pod
    # --------------------------------------------------------

    pod, error = read_namespaced_pod(
        API["core"],
        pod_name,
        namespace
    )

    if error:

        # Pod was deleted during an earlier response tier.
        # There is no label left to remove.
        if is_not_found_error(error):
            result["status"] = "Pod Deleted - Skipped"
            return result, None

        # Other API errors must not be ignored.
        result["status"] = "Failed"
        return result, error

    # --------------------------------------------------------
    # 2. Verify Pod UID
    # --------------------------------------------------------

    original_uid = step_result.get("pod_uid")

    if original_uid and pod.metadata.uid != original_uid:
        result["status"] = "Verification Failed"
        return result, (
            "Pod UID changed since original execution"
        )

    # --------------------------------------------------------
    # 3. Check existing labels
    # --------------------------------------------------------

    current_labels = pod.metadata.labels or {}

    if exclusion_label not in current_labels:
        result["status"] = "Already Removed"
        return result, None

    # --------------------------------------------------------
    # 4. Remove only the exclusion label
    # --------------------------------------------------------

    body = {
        "metadata": {
            "resourceVersion": pod.metadata.resource_version,
            "labels": {
                exclusion_label: None
            }
        }
    }

    patched_pod, error = patch_namespace_pod(
        vi=API["core"],
        name=pod_name,
        body=body,
        namespace=namespace
    )

    if error:

        # Pod might have been deleted between reading
        # its metadata and attempting to patch it.
        if is_not_found_error(error):
            result["status"] = "Pod Deleted - Skipped"
            return result, None

        result["status"] = "Failed"
        return result, error

    # --------------------------------------------------------
    # 5. Verify label removal
    # --------------------------------------------------------

    updated_labels = patched_pod.metadata.labels or {}

    if exclusion_label in updated_labels:
        result["status"] = "Verification Failed"
        return result, (
            "Exclusion label still exists on Pod"
        )

    result["status"] = "Completed"

    return result, None


# ============================================================
# DELETE RESPONSE-CREATED NETWORK POLICY
# ============================================================

def delete_baseline_network_policy(step_result, API):
    """
    Deletes the response-created NetworkPolicy.

    This supports both:
        - Baseline restriction policies
        - Pod isolation policies

    Verifies the action-specific exclusion label before
    deleting the policy.

    If the policy was already deleted, returns success.

    Returns:
        (result, error)
    """

    namespace = step_result["namespace"]
    policy_name = step_result["baseline_policy"]
    exclusion_label = step_result["exclusion_label"]

    result = {
        "namespace": namespace,
        "baseline_policy": policy_name,
        "status": "Pending"
    }

    # --------------------------------------------------------
    # 1. Retrieve NetworkPolicies
    # --------------------------------------------------------

    policies, error = list_network_policies(
        API["networking"], namespace
    )

    if error:
        result["status"] = "Failed"
        return result, error

    policy_lookup = {
        policy.metadata.name: policy
        for policy in policies.items
    }

    # --------------------------------------------------------
    # 2. Check whether policy exists
    # --------------------------------------------------------

    if policy_name not in policy_lookup:
        result["status"] = "Already Deleted"
        return result, None

    policy = policy_lookup[policy_name]

    # --------------------------------------------------------
    # 3. Verify policy identity
    # --------------------------------------------------------

    selector = policy.spec.pod_selector
    labels = selector.match_labels or {}

    if labels.get(exclusion_label) != "true":
        result["status"] = "Verification Failed"
        return result, (
            "Response policy selector does not match "
            "the expected exclusion label"
        )

    # --------------------------------------------------------
    # 4. Delete response-created NetworkPolicy
    # --------------------------------------------------------

    _, error = delete_network_policy(
        vi=API["networking"],
        name=policy_name,
        namespace=namespace
    )

    if error:
        # Treat an already-deleted policy as successful cleanup.
        # This can occur if another operation removed it.
        if is_not_found_error(error):
            result["status"] = "Already Deleted"
            return result, None

        result["status"] = "Failed"
        return result, error

    result["status"] = "Completed"

    return result, None

from .reaction_api import (
    new_issues,
    manual_requests_list,
    list_lock
)


def get_pending_requests():
    """
    Retrieve all pending API requests and clear the queues.

    Returns:
        incoming_issues: List of newly received issues
        manual_requests: List of manual escalation/deescalation requests
    """

    with list_lock:

        incoming_issues = list(new_issues)
        manual_requests = list(manual_requests_list)

        new_issues.clear()
        manual_requests_list.clear()

    return incoming_issues, manual_requests



def main():

    # Simulate an incoming issue
    test_issue = {
        "Issue_ID": "001",
        "Issue_type": "traffic_flood",
        "Resource_type": "pod",
        "Resource_name": "pod-b",
        "Namespace": "network-test",
        "Current_Severity": "high",
        "Information": {}
    }

    # Simulate a manual request
    test_manual = {
        "Issue_ID": "001",
        "Action": "escalate"
    }

    # Add requests to the shared lists
    with list_lock:
        new_issues.append(test_issue)
        manual_requests_list.append(test_manual)

    # TEST 1: Retrieve requests
    incoming_issues, manual_requests = get_pending_requests()

    print("TEST 1: Retrieved requests")
    print("Incoming issues:", incoming_issues)
    print("Manual requests:", manual_requests)

    assert incoming_issues == [test_issue]
    assert manual_requests == [test_manual]

    # TEST 2: Confirm queues were cleared
    incoming_issues, manual_requests = get_pending_requests()

    print("\nTEST 2: Queues cleared")
    print("Incoming issues:", incoming_issues)
    print("Manual requests:", manual_requests)

    assert incoming_issues == []
    assert manual_requests == []

    print("\nAll tests passed!")


if __name__ == "__main__":
    main()

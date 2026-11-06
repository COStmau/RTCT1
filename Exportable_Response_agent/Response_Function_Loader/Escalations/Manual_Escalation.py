
def manual_escalation(issue, Time, parameters, API):
    """
    Checks whether a manual escalation has been requested
    after the current tier was executed.

    Returns:
        (True, None) if escalation is requested
        (False, None) otherwise
        (None, error) if an error occurs
    """

    try:
        manual_request = issue.get("Manual_Request")
        request_time = issue.get("Manual_Request_Time")
        execution_time = issue.get("Execution_Time")

        # Check if manual escalation was requested
        if manual_request != "escalate":
            return False, None

        # Ensure timestamps exist
        if request_time is None or execution_time is None:
            return False, None

        # Check if request occurred after execution
        if request_time > execution_time:
            return True, None

        return False, None

    except Exception as e:
        return None, str(e)

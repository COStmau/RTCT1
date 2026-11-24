
def manual_deescalation(issue, Time, parameters, API):
    """
    Checks whether a manual deescalation has been requested
    after the current tier was executed.

    Returns:
        ((True, # steps, Retire?), None) if deescalation is requested
        ((False, None, None), None) otherwise
        (None, error) if an error occurs
    """

    try:
        manual_request = issue.get("Manual_Request")
        request_time = issue.get("Manual_Request_Time")
        execution_time = issue.get("Execution_Time")
        rollback_steps = issue.get("Number_of_tiers_to_deescalate")
        retire_issue = issue.get("Retire_Issue")

        # Check if manual deescalation was requested
        if manual_request != "deescalate":
            return (False, None, None), None

        # Ensure timestamps exist
        if request_time is None or execution_time is None:
            return (False, None, None), None

        # Check if request occurred after execution
        if request_time > execution_time:
            return (True, rollback_steps, retire_issue), None

        return (False, None, None), None

    except Exception as e:
        return None, str(e)

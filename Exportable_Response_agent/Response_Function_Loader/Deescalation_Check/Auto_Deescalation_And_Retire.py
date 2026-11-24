
def auto_deescalation_and_retire(issue, Time, parameters, API):
    """
    Automatically deescalates and retires an issue after
    the final response action is executed and validated.

    Returns:
        ((True, rollback_steps, True), None)
            if automatic deescalation is needed.

        ((False, None, None), None)
            if conditions have not been met.

        (None, error)
            if an error occurs.
    """

    try:
        if parameters is None:
            parameters = {}

        # Check parameter validity
        if not isinstance(parameters, dict):
            return None, "Parameters must be a dictionary"

        terminal_tier = parameters.get("terminal_tier", 4)

        if type(terminal_tier) is not int or terminal_tier < 1:
            return None, "terminal_tier must be a positive integer"

        # Do not trigger for already retired issues
        if issue.get("Retired") is True:
            return (False, None, None), None

        current_step = issue.get("Current_Step")

        # Only trigger on the terminal tier
        if current_step != terminal_tier:
            return (False, None, None), None

        # Check execution status
        if issue.get("Execution_Status") != "Completed":
            return (False, None, None), None

        # Check validation status
        if issue.get("Validation_Status") != "Completed":
            return (False, None, None), None

        # Verify successful deletion was recorded
        execution_results = issue.get("Execution_Result") or {}

        deletion_result = execution_results.get(str(terminal_tier))

        if not isinstance(deletion_result, dict):
            return None, "Missing deletion execution result"

        if deletion_result.get("status") != "Deletion Requested":
            return (False, None, None), None

        if not deletion_result.get("pod_uid"):
            return None, "Missing deleted Pod UID"

        # Roll back all tiers and retire
        rollback_steps = current_step
        retire_issue = True

        return (True, rollback_steps, retire_issue), None

    except Exception as e:
        return None, str(e)

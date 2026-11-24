def severity_increase(issue, Time, parameters, API):
    """
    Checks whether a manual escalation has been requested
    after the current tier was executed.

    Returns:
        (True, None) if escalation is requested
        (False, None) otherwise
        (None, error) if an error occurs
    """
    severity = issue.get("Current_Severity")
    past_severity = issue.get("Past_Severity")

    severity_levels = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
    }

    if severity not in severity_levels:
        return False, f"Unknown current severity: {severity}"

    if past_severity not in severity_levels:
        return False, f"Unknown past severity: {past_severity}"

    return (
        severity_levels[severity] > severity_levels[past_severity],
        None
    )


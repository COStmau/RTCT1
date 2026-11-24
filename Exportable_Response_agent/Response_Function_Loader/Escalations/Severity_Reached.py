def severity_reached(issue, Time, parameters, API):

    severity_levels = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }

    current = str(issue.get("Current_Severity", "")).lower()
    threshold = str(parameters.get("Threshold_Severity", "")).lower()

    if current not in severity_levels:
        return False, f"Unknown current severity: {current}"

    if threshold not in severity_levels:
        return False, f"Unknown threshold severity: {threshold}"

    return (
        severity_levels[current] >= severity_levels[threshold],
        None
    )
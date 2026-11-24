def time_elapsed(issue, Time, parameters, API):
    """
    Checks whether a specified amount of time has elapsed since the issue was created.

    Returns:
        (True, None) if the time has elapsed
        (False, None) otherwise
        (None, error) if an error occurs
    """
    try:
        time_threshold = parameters.get("Time_Threshold")
        creation_time = issue.get("Creation_Time")

        if time_threshold is None or creation_time is None:
            return False, None

        if Time - creation_time >= time_threshold:
            return True, None

        return False, None

    except Exception as e:
        return None, str(e)
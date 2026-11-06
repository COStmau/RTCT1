
#issues = process_manual_requests(manual_requests, issues, current_time)

def process_manual_requests(manual_requests, issues, current_time):

    for request in manual_requests:
        issue_id = request["Issue_ID"]
        action = request["Action"]

        if action in ("escalate", "deescalate") and issue_id in issues:
            issues[issue_id]["Manual_Request"] = action
            issues[issue_id]["Manual_Request_Time"] = current_time

    return issues

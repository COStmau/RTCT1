
#issues = process_manual_requests(manual_requests, issues, current_time)

def process_manual_requests(manual_requests, issues, current_time):
    #Update the issues dictionary with manual requests
    #For each manual request, check if the issue ID exists in the issues dictionary
    #If it does, update the issue's "Manual_Request" field with the action specified
    for request in manual_requests:
        issue_id = request["Issue_ID"]
        action = request["Action"]
        number_of_tiers_to_deescalate = request.get("Number_of_tiers_to_deescalate", 0)
        retire_issue = request.get("Retire_Issue", False)

        if action in ("escalate", "deescalate") and issue_id in issues:
            issues[issue_id]["Manual_Request"] = action
            issues[issue_id]["Manual_Request_Time"] = current_time
            issues[issue_id]["Number_of_tiers_to_deescalate"] = number_of_tiers_to_deescalate
            issues[issue_id]["Retire_Issue"] = retire_issue

    return issues

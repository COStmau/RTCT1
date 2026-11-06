def Create_Entry_In_Manual_response_call(manual_rc,issue, Rule):
    issue_id = issue["Issue_ID"]
    manual_rc[issue_id] = {
        "Description": {
            "Attack_Name": issue["Issue_type"],
            "Resource_Type": issue["Resource_type"],
            "Resource_Name": issue["Resource_name"],
            "Namespace": issue["Namespace"],
            "Severity": issue["Past_Severity"],
            "Response_ID": issue["Rule_ID"],
            "Step": int(issue["Current_Step"]),
            "Rule_Step": Rule["tiers"][str(issue["Current_Step"])],
            "Next_Rule_Step": Rule["tiers"].get(str(int(issue["Current_Step"]) + 1))
        },
        "Escalate": False,
        "Deescalate": False,
        "Error": None
    }
    return manual_rc


def Update_Entry_In_Manual_response_call(
    manual_rc,
    issue,
    Rule,
    reset_flags=False
):
    issue_id = str(issue["Issue_ID"])
    current_step = int(issue["Current_Step"])

    entry = manual_rc[issue_id]

    entry["Description"].update({
        "Severity": issue["Past_Severity"],
        "Step": current_step,
        "Rule_Step": Rule["tiers"][str(current_step)],
        "Next_Rule_Step": Rule["tiers"].get(str(current_step + 1))
    })

    if reset_flags:
        entry["Escalate"] = False
        entry["Deescalate"] = False

    return manual_rc
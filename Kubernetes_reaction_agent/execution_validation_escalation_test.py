

def execute_tier(issue, Time, Actions,rules):
    """
    Inputs:
        issue: Dictionary containing issue information
        Time: Current time
        Actions: Dictionary mapping action names to functions

    Outputs:
        result: Result returned by the action, or None on failure
        error: None if successful, error description otherwise
    """

    try:
        # Retrieve current tier
        current_step = str(issue["Current_Step"])
        rule_id = str(issue["Rule_ID"])
        tier = rules[rule_id]["tiers"][current_step] 

        # Retrieve action and parameters for action from rule
        action_name = tier["action"]
        parameters = tier.get("parameters", {})

        # Check if action exists
        if action_name not in Actions:
            return None, f"Unknown action: {action_name}"

        # Execute action
        result, error = Actions[action_name](issue, Time, parameters)

        #Checks if error occured
        if error is not None:
            return result, error

        return result, None

    #Catch for malformed calls
    except KeyError as e:
        return None, f"Missing issue or rule field: {e}"

    #All other errors
    except Exception as e:
        return None, str(e)

def test_action(issue, Time, parameters):
    print("Test action executed successfully!")
    print(f"Issue ID: {issue['Issue_ID']}")
    print(f"Time: {Time}")
    print(f"Parameters: {parameters}")

    return True, None

def main():
    issue = {'001': {'Issue_ID': '001', 'Issue_type': 'traffic_flood', 'Resource_type': 'pod', 'Resource_name': 'pod-b', 'Namespace': 'network-test', 'Current_Severity': 'high', 'Information': {}, 'response_executed': False, 'Number_of_Detections': 1, 'Last_Detection_Timestamp': (2026, 11, 1, 14, 12, 15, 507855), 'First_Detection_Timestamp': (2026, 11, 1, 14, 12, 15, 507855), 'Rule_ID': 'R001', 'Current_Step': 1, 'Rule': 'R001', 'Execution_Status': 'Pending', 'Validation_Status': 'Pending', 'Execution_Time': None, 'Validation_Time': None}}

    rules = {'R001': {'rule_id': 'R001', 'name': 'Pod Traffic Flood', 'description': 'Mitigates excessive incoming traffic to a pod', 'enabled': True, 'priority': 50, 'conditions': {'issue_type': 'traffic_flood', 'location_type': 'pod', 'minimum_severity': 'low'}, 'required_Actions': ['limit_ingress', 'block_source_ip'], 'required_Validations': [], 'tiers': {'1': {'name': 'test_action', 'action': 'test_action', 'parameters': {'limit': 'baseline'}, 'validation': None, 'verification_delay_seconds': 0, 'escalation': {'logic': 'OR', 'criteria': [{'type': 'detection_agent_increase'}]}, 'deescalation': {'logic': 'OR', 'criteria': [{'type': 'detection_agent_decrease'}]}}, '2': {'name': 'Restrict Ingress', 'action': 'limit_ingress', 'parameters': {'limit': 'restrictive'}, 'validation': None, 'verification_delay_seconds': 0, 'escalation': {'logic': 'OR', 'criteria': [{'type': 'detection_agent_increase'}]}, 'deescalation': {'logic': 'OR', 'criteria': [{'type': 'detection_agent_decrease'}]}}, '3': {'name': 'Block Source IP', 'action': 'block_source_ip', 'parameters': {}, 'validation': None, 'verification_delay_seconds': 0, 'escalation': {'logic': 'OR', 'criteria': []}, 'deescalation': {'logic': 'OR', 'criteria': [{'type': 'detection_agent_decrease'}]}}}, 'on_execution_failure': 'manual_review', 'on_resolution': 'begin_recovery', 'on_max_escalation': 'manual_review'}}

    actions = {
        "test_action": test_action
    }

    result, error = execute_tier(issue["001"], 0, actions, rules)

    print(result)
    print(error)

main()
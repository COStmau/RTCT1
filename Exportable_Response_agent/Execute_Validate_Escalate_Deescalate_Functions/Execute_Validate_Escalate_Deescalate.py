
#result, error, updated_issue = execute_validate_escalate_descalate(issue, Actions, Validations, Escalations, Descalations)

def execute_validate_escalate_descalate(
    issue, Actions, Validations, Escalations,
    Deescalations, active_rules, current_time, API
):

    step = active_rules[issue["Rule_ID"]]["tiers"][str(issue["Current_Step"])]

    result = None
    error = None

    if issue["Execution_Status"] not in ("Completed", "Failed"):
        result, error = execute_tier(issue, current_time, Actions, step, API)

        if error is not None:
            return result, error, issue

        issue["Execution_Result"] = result

    if (issue["Validation_Status"] not in ("Completed", "Failed")
            and issue["Execution_Status"] == "Completed"):
        
        result, error = validate_tier(issue, current_time, Validations, step, API)

        if error is not None:
            return result, error, issue
        
    if (issue["Execution_Status"] == "Completed"
            and issue["Validation_Status"] == "Completed"):

        next_step = str(issue["Current_Step"] + 1)

        if next_step in active_rules[issue["Rule_ID"]]["tiers"]:
            result, error = escalate_tier(
                issue, current_time, Escalations, step, API
            )

    return result, error, issue


def execute_tier(issue, Time, Actions,tier, API):

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
        

        # Retrieve action and parameters for action from rule
        action_name = tier["action"]
        print("Executing action:",action_name)
        parameters = tier.get("parameters", {})

        # Check if action exists
        if action_name not in Actions:
            return None, f"Unknown action: {action_name}"

        # Execute action
        result, error = Actions[action_name](issue, Time, parameters, API)

        #Checks if error occured
        if error is not None:
            return result, error



        if result is False or result is None:
            return result, None

        issue["Execution_Status"] = "Completed"
        issue["Execution_Time"] = Time

        return result, None

    #Catch for malformed calls
    except KeyError as e:
        return None, f"Missing issue or rule field: {e}"

    #All other errors
    except Exception as e:
        return None, str(e)

def validate_tier(issue, Time, Validations, tier, API):
    """
    Executes the validation function specified by the tier.

    Only marks validation as Completed if the function returns True.

    Returns:
        result: True, False, or None
        error: None if no error occurred, otherwise error description
    """

    try:
        # Retrieve validation function and parameters
        validation_name = tier["validation"]
        parameters = tier.get("validation_parameters", {})
        print("Validating with ", validation_name)
        # Check if validation exists
        if validation_name not in Validations:
            return None, f"Unknown validation: {validation_name}"

        # Execute validation function
        result, error = Validations[validation_name](
            issue, Time, parameters, API
        )

        # Check if an error occurred
        if error is not None:
            return result, error

        # Only update issue if validation succeeds
        if result is True:
            issue["Validation_Status"] = "Completed"
            issue["Validation_Time"] = Time

        return result, None

    # Catch missing fields
    except KeyError as e:
        return None, f"Missing issue or rule field: {e}"

    # Catch all other errors
    except Exception as e:
        return None, str(e)


def escalate_tier(issue, Time, Escalations, tier, API):
    """
    Executes the escalation function specified by the tier.

    If escalation returns True:
        - Increments Current_Step
        - Resets execution and validation statuses
        - Updates escalation time

    Returns:
        result: True, False, or None
        error: None if no error occurred, otherwise error description
    """

    try:
        # Retrieve escalation function and parameters
        escalation_name = tier["escalation"]
        parameters = tier.get("escalation_parameters", {})

        # Check if escalation exists
        if escalation_name not in Escalations:
            return None, f"Unknown escalation: {escalation_name}"

        # Execute escalation function
        result, error = Escalations[escalation_name](
            issue, Time, parameters, API
        )

        # Check if an error occurred
        if error is not None:
            return result, error

        # Only update issue if escalation succeeds
        if result is True:
            issue["Current_Step"] += 1
            issue["Execution_Status"] = "Unexecuted"
            issue["Validation_Status"] = "Unexecuted"
            issue["Execution_Time"] = None
            issue["Validation_Time"] = None
            issue["Execution_Result"] = None
            issue["Escalation_Time"] = Time

        return result, None

    # Catch missing fields
    except KeyError as e:
        return None, f"Missing issue or rule field: {e}"

    # Catch all other errors
    except Exception as e:
        return None, str(e)



from datetime import datetime
from copy import deepcopy


def main():

    # -------------------------------
    # Mock functions
    # -------------------------------

    def test_action(issue, Time, parameters,API):
        print("ACTION EXECUTED")
        return True, None

    def test_validation(issue, Time, parameters,API):
        print("VALIDATION EXECUTED")
        return True, None

    def test_escalation(issue, Time, parameters,API):
        print("ESCALATION CHECK EXECUTED")
        return True, None

    # -------------------------------
    # Function registries
    # -------------------------------

    Actions = {
        "test_action": test_action
    }

    Validations = {
        "test_validation": test_validation
    }

    Escalations = {
        "test_escalation": test_escalation
    }

    Deescalations = {}

    # -------------------------------
    # Mock active rules
    # -------------------------------

    active_rules = {
        "R001": {
            "1": {
                "action": "test_action",
                "parameters": {},
                "validation": "test_validation",
                "validation_parameters": {},
                "escalation": "test_escalation",
                "escalation_parameters": {}
            },
            "2": {
                "action": "test_action",
                "parameters": {},
                "validation": "test_validation",
                "validation_parameters": {},
                "escalation": "test_escalation",
                "escalation_parameters": {}
            }
        }
    }

    # -------------------------------
    # Initial issue
    # -------------------------------

    issue = {
        "Issue_ID": "001",
        "Rule_ID": "R001",
        "Current_Step": 1,
        "Execution_Status": "Unexecuted",
        "Validation_Status": "Unexecuted",
        "Execution_Time": None,
        "Validation_Time": None,
        "Escalation_Time": None
    }

    # -------------------------------
    # Run test
    # -------------------------------

    for iteration in range(1, 4):

        print(f"\n--- ITERATION {iteration} ---")

        result, error, issue = execute_validate_escalate_descalate(
            issue,
            Actions,
            Validations,
            Escalations,
            Deescalations,
            active_rules,
            datetime.now(),
            API
        )

        print("Result:", result)
        print("Error:", error)
        print("Current Step:", issue["Current_Step"])
        print("Execution Status:", issue["Execution_Status"])
        print("Validation Status:", issue["Validation_Status"])


if __name__ == "__main__":
    main()


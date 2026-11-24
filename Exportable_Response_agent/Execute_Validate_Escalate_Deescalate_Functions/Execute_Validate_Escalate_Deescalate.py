
#result, error, updated_issue = execute_validate_escalate_descalate(issue, Actions, Validations, Escalations, Descalations)
import traceback

def execute_validate_escalate_descalate(
    issue, Actions, Validations, Escalations, Deescalation_Actions, Deescalation_Checks,
    active_rules, current_time, API
):
    rule = active_rules.get(issue["Rule_ID"])
    step = rule["tiers"][str(issue["Current_Step"])]

    result = None
    error = None

    #Execute the current tier if it has not been executed yet
    if issue["Execution_Status"] not in ("Completed", "Failed"):
        result, error = execute_tier(issue, current_time, Actions, step, API)

        if error is not None:
            return result, error, issue

        issue["Execution_Result"][str(issue["Current_Step"])] = result

    #Validate the current tier if it has not been validated yet
    if (issue["Validation_Status"] not in ("Completed", "Failed")
            and issue["Execution_Status"] == "Completed"):
        
        result, error = validate_tier(issue, current_time, Validations, step, API)

        if error is not None:
            return result, error, issue

    #deescalate if the current tier has been executed and validated
    if (issue["Execution_Status"] == "Completed" and issue["Validation_Status"] == "Completed"):
        output, error = deescalate_check(issue, current_time, Deescalation_Checks, step, rule, API)
        if error is None:
            (result, rollback_steps, retire_status) = output
            if(result):
                result, error = deescalate_tier(issue, current_time, Deescalation_Actions, rule, rollback_steps, retire_status, API)

                return result, error, issue
            

    
    if (issue["Execution_Status"] == "Completed"
            and issue["Validation_Status"] == "Completed"):

        next_step = str(issue["Current_Step"] + 1)

        if next_step in rule["tiers"]:
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
        traceback.print_exc()
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
            issue["Escalation_Time"] = Time

        return result, None

    # Catch missing fields
    except KeyError as e:
        return None, f"Missing issue or rule field: {e}"

    # Catch all other errors
    except Exception as e:
        return None, str(e)

def deescalate_check(issue, Time, Deescalation_Checks, tier, rule, API):
    """
    Executes the deescalation check specified by the tier.

    Returns:
        result:
            True  - Deescalation conditions are satisfied
            False - Deescalation conditions are not satisfied
            None  - Check could not be completed

        error:
            None if no error occurred, otherwise error description
    """

    try:
        # Retrieve deescalation check and parameters
        check_name = tier.get("deescalation_check")
        parameters = tier.get("deescalation_check_parameters", {})

        # No check configured means no automatic deescalation
        if check_name is None:
            return (False,None,None), None

        # Check if deescalation check exists
        if check_name not in Deescalation_Checks:
            return None, f"Unknown deescalation check: {check_name}"

        # Execute deescalation check
        result, error = Deescalation_Checks[check_name](
            issue, Time, parameters, API
        )

        if error is not None:
            return None, error

        if (
            not isinstance(result, tuple)
            or len(result) != 3
            or type(result[0]) is not bool
        ):
            return None, f"Invalid deescalation check result: {result}"

        return result, None

    # Catch missing fields
    except KeyError as e:
        return None, f"Missing issue or rule field: {e}"

    # Catch all other errors
    except Exception as e:
        return None, str(e)


    


def deescalate_tier(issue, Time, Deescalation_Actions, rule,
                    rollback_steps, retire_status, API):
    """
    Executes deescalation actions in reverse tier order.

    For each rollback step:
        - Executes the current tier's undo action, if present
        - Removes that tier's execution result
        - Moves to the previous tier

    Tier 1 is the lowest tier. Its action can be undone,
    but Current_Step will never decrease below 1.

    If retire_status is True, marks the issue as retired
    after successful deescalation.

    Returns:
        True  - All rollback actions succeeded
        False - A deescalation action failed
        None  - An error occurred

        error: None or error description
    """

    try:
        current_step = int(issue["Current_Step"])
        tiers = rule["tiers"]

        # Validate rollback count
        if type(rollback_steps) is not int or rollback_steps < 0:
            return None, "rollback_steps must be a nonnegative integer"

        if current_step < 1:
            return None, "Current_Step cannot be below 1"

        # Cap the number of actions that can be undone
        steps_to_undo = min(rollback_steps, current_step)

        # Retrieve saved execution results
        history = issue["Execution_Result"]

        if not isinstance(history, dict):
            return None, "Execution_Result must be a dictionary"

        # Determine where the issue should end
        target_step = max(1, current_step - rollback_steps)

        # If the destination tier is not being undone,
        # its execution result must exist
        if rollback_steps > 0 and rollback_steps < current_step:
            if str(target_step) not in history:
                return None, f"Missing execution result for tier {target_step}"

        # Execute each rollback in reverse order
        for step in range(current_step,
                          current_step - steps_to_undo, -1):

            # Retrieve current tier
            tier = tiers[str(step)]

            action_name = tier.get("deescalation_action")
            parameters = tier.get(
                "deescalation_action_parameters", {}
            )

            # Execute deescalation action if specified
            if action_name is not None:

                if action_name not in Deescalation_Actions:
                    return None, f"Unknown deescalation action: {action_name}"

                # Retrieve original execution result
                if str(step) not in history:
                    return None, f"Missing execution result for tier {step}"

                step_result = history[str(step)]

                # Execute undo function
                result, error = Deescalation_Actions[action_name](
                    issue, step_result, Time, parameters, API
                )

                if error is not None:
                    return None, f"Tier {step}: {error}"

                # Determine whether undo succeeded
                if isinstance(result, dict):
                    success = result.get("status") == "Completed"
                else:
                    success = result is True

                if not success:
                    return False, None

            # Remove the undone tier's execution result
            history.pop(str(step), None)

            # Move to previous tier, but never below tier 1
            issue["Current_Step"] = max(1, step - 1)

            # Determine whether the destination tier
            # still has an active execution result
            if str(issue["Current_Step"]) in history:

                issue["Execution_Status"] = "Completed"
                issue["Validation_Status"] = "Completed"
                issue["Execution_Time"] = Time
                issue["Validation_Time"] = Time

            else:
                # No active action remains at this tier
                issue["Execution_Status"] = "Unexecuted"
                issue["Validation_Status"] = "Unexecuted"
                issue["Execution_Time"] = None
                issue["Validation_Time"] = None

            issue["Deescalation_Time"] = Time

        # Clear completed manual request
        issue["Manual_Request"] = None
        issue["Manual_Request_Time"] = None
        issue["Number_of_tiers_to_deescalate"] = 0
        issue["Retire_Issue"] = False

        # Mark issue for retirement if requested
        if retire_status is True:
            issue["Retired"] = True

        return True, None

    except KeyError as e:
        return None, f"Missing issue or rule field: {e}"

    except Exception as e:
        return None, str(e)

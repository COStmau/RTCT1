
import time
import logging


class StepExecutor:

    def __init__(self):
        self.actions = {}
        self.validations = {}

        self.logger = logging.getLogger("StepExecutor")

    def register_action(self, name, function): #Adds Action to the actions dictionary
        """Register a function that performs an action."""
        self.actions[name] = function

    def register_validation(self, name, function): #Adds Validation to the validations dictionary
        """Register a function that checks an action's result."""
        self.validations[name] = function

    def execute_step( #Execute step from rule
        self,
        action,
        validation,
        target,
        parameters=None,
        verification_delay_seconds=0,
        validation_timeout_seconds=10,
        validation_interval_seconds=1
    ):
        """
        Execute an action, then validate its effect.

        Action functions receive (target, parameters).
        Validation functions receive (target, parameters)
        and must return True or False.
        """

        parameters = parameters or {}

        result = {
            "action": action,
            "validation": validation,
            "target": target,
            "action_success": False,
            "validation_success": False,
            "status": "FAILED",
            "error": None
        }

        # Check that actions are registered in dictionary
        if action not in self.actions:
            result["error"] = f"Unknown action: {action}"
            return result

        # Check that validations are registered in dictionary
        if validation not in self.validations:
            result["error"] = f"Unknown validation: {validation}"
            return result

        if (
            verification_delay_seconds < 0
            or validation_timeout_seconds < 0
            or validation_interval_seconds <= 0
        ): 
            result["error"] = "Invalid timing parameters"
            return result

        # STEP 1: Execute action
        try:
            self.logger.info("Executing action: %s", action)

            action_result = self.actions[action](
                target, parameters
            ) #Executes the action function with the target and parameters

            if action_result is False:
                result["error"] = "Action reported failure"
                return result

            result["action_success"] = True

        except Exception as e:
            self.logger.exception("Action failed")
            result["error"] = str(e)
            return result

        # STEP 2: Wait for action to take effect
        if verification_delay_seconds > 0:
            time.sleep(verification_delay_seconds)

        # STEP 3: Validate
        deadline = time.monotonic() + validation_timeout_seconds

        while True:
            try:
                valid = self.validations[validation](
                    target, parameters
                )

                if valid:
                    result["validation_success"] = True
                    result["status"] = "SUCCESS"
                    return result

            except Exception as e:
                self.logger.exception("Validation failed")
                result["error"] = str(e)
                return result

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                break

            time.sleep(min(validation_interval_seconds, remaining))

        result["error"] = "Validation timed out"
        return result

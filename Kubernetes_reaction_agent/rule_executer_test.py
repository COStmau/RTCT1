
from step_executor import StepExecutor


# Simulated system state
system_state = {
    "pod_1": {
        "ingress_limit": "unrestricted",
        "blocked": False
    }
}


# ---------------- ACTIONS ----------------

def limit_ingress(target, parameters):
    limit = parameters["limit"]

    system_state[target]["ingress_limit"] = limit

    print(f"Applied ingress limit: {limit} to {target}")
    return True


def block_source(target, parameters):
    system_state[target]["blocked"] = True

    print(f"Blocked traffic for {target}")
    return True


# ---------------- VALIDATIONS ----------------

def validate_ingress_limit(target, parameters):
    expected = parameters["limit"]
    actual = system_state[target]["ingress_limit"]

    print(f"Checking ingress limit: {actual}")
    return actual == expected


def validate_block(target, parameters):
    return system_state[target]["blocked"] is True


# ---------------- TEST ----------------

executor = StepExecutor()

# Register available actions
executor.register_action("limit_ingress", limit_ingress)
executor.register_action("block_source_ip", block_source)

# Register validations
executor.register_validation("validate_ingress_limit",validate_ingress_limit)
executor.register_validation("validate_source_block",validate_block)

# Execute and validate
result = executor.execute_step(
    action="limit_ingress",
    validation="validate_ingress_limit",
    target="pod_1",
    parameters={"limit": "baseline"},
    verification_delay_seconds=0
)

print("\nExecution Result:")
print(result)

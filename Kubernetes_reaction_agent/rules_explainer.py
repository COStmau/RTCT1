
import json
from pathlib import Path


class RuleExplainer:

    def __init__(self):
        self.condition_descriptions = {
            "manual_intervention": "an operator manually requests it",
            "deviation_from_baseline": "the diagnosis agent reports a deviation from baseline",
            "return_to_baseline": "the diagnosis agent reports a return to baseline"
        }

        self.action_descriptions = {
            "limit_ingress": "Limit incoming traffic",
            "block_source_ip": "Block the offending source IP",
            "delete_pod": "Delete the affected pod",
            "restart_pod": "Restart the affected pod"
        }

    def explain_criterion(self, criterion):
        """Convert a criterion into readable English."""

        criterion_type = criterion["type"]
        parameters = criterion.get("parameters", {})

        if criterion_type == "time_elapsed":
            seconds = parameters.get("seconds", 0)
            return f"{seconds} seconds have elapsed"

        return self.condition_descriptions.get(
            criterion_type,
            criterion_type.replace("_", " ")
        )

    def explain_criteria(self, criteria_config):
        """Explain a group of escalation/de-escalation criteria."""

        criteria = criteria_config.get("criteria", [])
        logic = criteria_config.get("logic", "OR").upper()

        if not criteria:
            return "No conditions defined."

        descriptions = [
            self.explain_criterion(c) for c in criteria
        ]

        return f" {logic} ".join(descriptions) + "."

    def explain_action(self, step):
        """Explain the response action and its parameters."""

        action = step.get("action", "unknown")
        parameters = step.get("parameters", {})

        description = self.action_descriptions.get(
            action,
            action.replace("_", " ").capitalize()
        )

        if not parameters:
            return description + "."

        parameter_text = ", ".join(
            f"{key}={value}"
            for key, value in parameters.items()
        )

        return f"{description} ({parameter_text})."

    def explain_rule(self, rule):
        """Print a readable explanation of an entire rule."""

        print("=" * 65)
        print(f"RULE: {rule.get('name', 'Unnamed Rule')}")
        print(f"ID: {rule.get('rule_id', 'Unknown')}")
        print("=" * 65)

        print(f"\nDescription: {rule.get('description', 'None')}")
        print(f"Enabled: {rule.get('enabled', False)}")
        print(f"Priority: {rule.get('priority', 0)}")

        conditions = rule.get("conditions", {})

        print("\nWHEN THIS RULE APPLIES:")
        print(f"  Issue: {conditions.get('issue_type', 'Any')}")
        print(f"  Location: {conditions.get('location_type', 'Any')}")
        print(f"  Minimum Severity: {conditions.get('minimum_severity', 'low')}")

        steps = rule.get("response_steps", [])

        for index, step in enumerate(steps):

            print(f"\n{'-' * 65}")
            print(f"STEP {step.get('step', index + 1)}: {step.get('name', 'Unnamed')}")
            print(f"{'-' * 65}")

            print("\nAction:")
            print(f"  {self.explain_action(step)}")

            print("\nEscalate to the next step if:")
            print(f"  {self.explain_criteria(step.get('escalation', {}))}")

            print("\nDe-escalate to the previous step if:")
            print(f"  {self.explain_criteria(step.get('deescalation', {}))}")

        print("\n" + "=" * 65)

    def explain_file(self, file_path):
        """Load and explain a JSON rule file."""

        with open(file_path, "r", encoding="utf-8") as f:
            rule = json.load(f)

        self.explain_rule(rule)


if __name__ == "__main__":

    explainer = RuleExplainer()

    rule_directory = Path("response_rules")

    for rule_file in sorted(rule_directory.glob("*.json")):
        explainer.explain_file(rule_file)

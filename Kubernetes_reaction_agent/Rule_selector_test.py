
from pathlib import Path
from tempfile import TemporaryDirectory
import json

from Rule_selector import RuleSelector


def create_rule(directory, rule_id, priority, issue_type,
                location_type, minimum_severity, enabled=True):
    """Create a sample JSON rule for testing."""

    rule = {
        "rule_id": rule_id,
        "name": f"Test Rule {rule_id}",
        "description": "Test rule",
        "enabled": enabled,
        "priority": priority,
        "conditions": {
            "issue_type": issue_type,
            "location_type": location_type,
            "minimum_severity": minimum_severity
        },
        "action": {
            "type": "test_action"
        },
        "validation": {
            "type": "test_validation"
        }
    }

    file_path = Path(directory) / f"{rule_id}.json"

    with open(file_path, "w") as f:
        json.dump(rule, f, indent=4)


def run_test(name, actual, expected):
    """Compare actual and expected results."""

    if actual == expected:
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name}")
        print(f"       Expected: {expected}")
        print(f"       Actual:   {actual}")


def main():

    # Temporary directory prevents modifying real response rules
    with TemporaryDirectory() as rule_directory:

        # Create sample rules
        create_rule(
            rule_directory, "R001", 50,
            "traffic_flood", "pod", "low"
        )

        create_rule(
            rule_directory, "R002", 100,
            "traffic_flood", "pod", "high"
        )

        create_rule(
            rule_directory, "R003", 75,
            "reconnaissance", "pod", "medium"
        )

        create_rule(
            rule_directory, "R004", 90,
            "traffic_flood", "node", "low"
        )

        create_rule(
            rule_directory, "R005", 200,
            "traffic_flood", "pod", "low",
            enabled=False
        )

        # Initialize selector
        selector = RuleSelector(rule_directory)

        print("\n===== RULE LOADING TESTS =====")

        run_test(
            "Only enabled rules loaded",
            len(selector.rules),
            4
        )

        run_test(
            "Highest priority loaded first",
            selector.rules[0]["rule_id"],
            "R002"
        )

        print("\n===== RULE SELECTION TESTS =====")

        test_cases = [
            # Name, Input:  (issue_type, location_type, severity,), Output:expected rule
            ("Low severity flood",
             "traffic_flood", "pod", "low", "R001"),

            ("Medium severity flood",
             "traffic_flood", "pod", "medium", "R001"),

            ("High severity flood",
             "traffic_flood", "pod", "high", "R002"),

            ("Medium reconnaissance",
             "reconnaissance", "pod", "medium", "R003"),

            ("Low reconnaissance should not match",
             "reconnaissance", "pod", "low", None),

            ("Flood targeting node",
             "traffic_flood", "node", "high", "R004"),

            ("Unknown issue type",
             "unknown_issue", "pod", "high", None),

            ("Unknown location type",
             "traffic_flood", "container", "high", None)
        ]

        for name, issue, location, severity, expected in test_cases:

            result = selector.select_rule(
                issue_type=issue,
                location_type=location,
                severity=severity
            )

            actual = result["rule_id"] if result else None

            run_test(name, actual, expected)

        print("\n===== RULE RELOADING TEST =====")

        create_rule(
            rule_directory, "R006", 150,
            "traffic_flood", "pod", "low"
        )

        selector.load_rules()

        run_test(
            "New rule loaded after reload",
            len(selector.rules),
            5
        )

        result = selector.select_rule(
            "traffic_flood", "pod", "low"
        )

        run_test(
            "New highest-priority rule selected",
            result["rule_id"] if result else None,
            "R006"
        )

    print("\n===== TESTING COMPLETE =====")


if __name__ == "__main__":
    main()

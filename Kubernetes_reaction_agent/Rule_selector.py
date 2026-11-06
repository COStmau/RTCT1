
import json
from pathlib import Path


class RuleSelector:

    def __init__(self, rule_directory="response_rules"): #Loads rules in path.
        self.rules = []
        self.rule_directory = Path(rule_directory)

        self.severity_levels = {
            "low": 1,
            "medium": 2,
            "high": 3
        }

        self.load_rules()

    def load_rules(self):
        """Load all enabled JSON rules into memory."""

        self.rules = []

        for file in sorted(self.rule_directory.glob("*.json")): #loads all JSON files in the rule directory 
            with open(file, "r") as f:
                rule = json.load(f)

            if rule.get("enabled", False):
                self.rules.append(rule)

        # Higher priority rules are checked first
        self.rules.sort(
            key=lambda rule: rule["priority"],
            reverse=True
        )

    def rule_matches(self, rule, issue_type,
                     location_type, severity): #Check if the rule matches the diagnosis
        
        """Check whether a rule matches the diagnosis."""

        conditions = rule["conditions"]

        # Issue must match exactly
        if conditions["issue_type"] != issue_type: 
            return False

        # Location type must match exactly
        if conditions["location_type"] != location_type:
            return False

        # Severity must meet the minimum requirement
        minimum = self.severity_levels[
            conditions["minimum_severity"]
        ]

        actual = self.severity_levels[severity]

        if actual < minimum:
            return False

        return True

    def select_rule(self, issue_type,
                    location_type, severity): #Selects the highest-priority matching rule based on the diagnosis.
        """Return the highest-priority matching rule."""

        for rule in self.rules:
            if self.rule_matches(
                rule, issue_type, location_type, severity
            ):
                return rule

        return None

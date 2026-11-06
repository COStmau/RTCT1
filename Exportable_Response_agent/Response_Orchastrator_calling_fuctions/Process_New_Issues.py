
#issues, Active_rules = process_new_issues(incoming_issues, issues, Active_rules, Rule_selector, current_time)

def process_new_issues(incoming_issues, issues, Active_rules, Rule_selector, current_time):
    """
    Processes incoming issues by either creating new issues
    or updating existing ones.

    Returns:
        issues: Updated dictionary of tracked issues
        Active_rules: Rules associated with tracked issues
    """

    for new_issue in incoming_issues:

        ID = new_issue["Issue_ID"]
        print("New Issue ID: ", ID)
        if ID not in issues:
            # Create a new issue and select its response rule
            new_entry, Active_rules = create_issue(
                new_issue,
                Rule_selector,
                Active_rules,
                current_time
            )

            if new_entry is not None:
                issues[ID] = new_entry

        else:
            # Update an existing issue
            issues[ID] = update_issue(
                issues[ID],
                new_issue,
                current_time
            )

    return issues, Active_rules



#Helper Functions:

def create_issue(issue, Rule_selector,rules, timestamp=None):
    #Issue_Dict Template:
    # {
    #     "Issue_ID": "001",                     | Used to identify the issue from others
    #     "Issue_type": "resource_flood",        | Type of issue, used to match with rules
    #     "Resource_type": "pod",                | Type of resource affected by the issue
    #     "Resource_name": "pod-b",              | Name of the resource affected by the issue
    #     "Namespace": "network-test",           | Namespace of the resource affected by the issue
    #     "Current_Severity": "high",            | Current severity of the issue, used to match with rules
    #     "Past_Severity": ["high", "critical"]  | All Severity with lower index indicating older severity
    #     "Information": {}                      | Additional information about the issue such as pod IP addresses, node names, etc.
    #     "response_executed": False             | Flag to indicate whether a response has been executed for this issue
    #     "Response_ID": None                    | ID of the response executed for this issue, if any
    #     "Current_Step": None                   | Current step of the response being executed, if any
    #     "Number_of_Detections": 1,             | Number of times this issue has been detected
    #     "Last_Detection_Timestamp": timestamp, | Timestamp of the last detection of this issue
    #     "First_Detection_Timestamp": timestamp,| Timestamp of the first detection of this issue
    #     "Rule_ID": None                        | ID of the rule that matched this issue, if any
    #     "Execution_Status": None               | Status of the response execution ex. "Pending", "In Progress", "Completed", "Failed"
    #     "Validation_Status": None              | Status of the response validation ex. "Pending", "In Progress", "Completed", "Failed"
    #     "Execution_Time": None                 | Time since Execution
    #     "Validation_Time": None                | Time since Validation

    # Create a new issue in the system
    rule = Rule_selector.select_rule(
        issue["Issue_type"],
        issue["Resource_type"],
        issue["Current_Severity"]
    )


    if rule is not None:
        rules[rule["rule_id"]] = rule
    else:
        return None, rules

    new_issue = {
        "Issue_ID": issue["Issue_ID"],
        "Issue_type": issue["Issue_type"],
        "Resource_type": issue["Resource_type"],
        "Resource_name": issue["Resource_name"],
        "Namespace": issue["Namespace"],
        "Current_Severity": issue["Current_Severity"],
        "Past_Severity": [issue["Current_Severity"]],
        "Information": issue["Information"],
        "response_executed": False,
        "Number_of_Detections": 1,
        "Last_Detection_Timestamp": timestamp,
        "First_Detection_Timestamp": timestamp,
        "Rule_ID": rule["rule_id"] if rule else None,
        "Current_Step": 1 if rule else None,
        "Execution_Status": "Pending",
        "Validation_Status": "Pending",
        "Execution_Time": None,
        "Validation_Time": None,
        "Manual_Request": None,
        "Manual_Request_Time": None,
        "Execution_Result": None
    }

    return new_issue, rules

def update_issue(existing_issue, new_issue, timestamp=None):

    # Only record severity if it has changed
    if new_issue["Current_Severity"] != existing_issue["Current_Severity"]:
        existing_issue["Past_Severity"].append(
            new_issue["Current_Severity"]
        )

    # Update current issue information
    existing_issue["Current_Severity"] = new_issue["Current_Severity"]

    existing_issue["Information"].update(new_issue["Information"])

    existing_issue["Number_of_Detections"] += 1
    existing_issue["Last_Detection_Timestamp"] = timestamp

    return existing_issue


import json
from pathlib import Path

#Rules Selector:
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

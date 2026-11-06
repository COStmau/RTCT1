
# Response_Orchastrator_Beta.py

from datetime import datetime
import time
import threading
import uvicorn

from pathlib import Path

# Response logic
from Exportable_Response_agent.Response_logic_functions import *

# FastAPI application
from Exportable_Response_agent.Response_Orchastrator_calling_fuctions.reaction_api import (
    app
)

# Retrieve pending API requests
from Exportable_Response_agent.Response_Orchastrator_calling_fuctions.Get_Pending_Requests import (
    get_pending_requests
)

# Process incoming issues
from Exportable_Response_agent.Response_Orchastrator_calling_fuctions.Process_New_Issues import (
    process_new_issues,
    RuleSelector
)

from Exportable_Response_agent.Response_Orchastrator_calling_fuctions.Process_Manual_Requests import process_manual_requests

from Exportable_Response_agent.Response_Function_Loader.Function_Loader import load_functions

from Exportable_Response_agent.Execute_Validate_Escalate_Deescalate_Functions.Execute_Validate_Escalate_Deescalate import execute_validate_escalate_descalate

def start_api():
    api_thread = threading.Thread(
        target=uvicorn.run,
        kwargs={
            "app": app,
            "host": "0.0.0.0",
            "port": 8000
        },
        daemon=True
    )

    api_thread.start()


def main():

    # Initialize Kubernetes
    api_client, apis = initialize_kubernetes()

    # Load response functions (currently disabled)
    
    Actions = load_functions("Actions","Actions_List.json")

    Validations = load_functions("Validations","Validations_List.json")

    Escalations = load_functions("Escalations","Escalations_List.json")

    Deescalations = {}
    #Deescalations = load_functions("Deescalations","Deescalations_List.json")

    # Initialize rule selector


    base_path = Path(__file__).resolve().parent

    Rule_selector = RuleSelector(
        base_path / "Rules"
    )


    issues = {}
    Active_rules = {}

    # Start FastAPI
    start_api()

    print("Orchestrator running...")

    while True:

        current_time = datetime.now()

        # 1. Collect API requests
        incoming_issues, manual_requests = get_pending_requests()

        # 2. Update issue dictionary
        issues, Active_rules = process_new_issues(
            incoming_issues,
            issues,
            Active_rules,
            Rule_selector,
            current_time
        )

        # Display newly processed issues

    
        # 3. Process manual requests
        issues = process_manual_requests(manual_requests, issues, current_time)

        # 4. Execute and validate active responses
        for ID, issue in list(issues.items()):
                        
            result, error, updated_issue = execute_validate_escalate_descalate(
                issue,
                Actions,
                Validations,
                Escalations,
                Deescalations,
                Active_rules,
                current_time,
                apis
            )

            if error is not None:
                print(f"Issue {ID} error: {error}", flush=True)

            issues[ID] = updated_issue


        time.sleep(1)


if __name__ == "__main__":
    main()

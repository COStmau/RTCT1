#Assumed Format:

# {"Issue_ID": "001", "Issue_type": "traffic_flood", "Resource_type": "pod","Resource_name": ["pod-b", "Namespace": ["network-test"], "Severity": "high", "IP_source": ["192.168.1.100"]}
from datetime import datetime
import time
from Exportable_Response_agent.Response_logic_functions import *
from step_executor import StepExecutor

import threading
import uvicorn

from Exportable_Response_agent.Response_Orchastrator_calling_fuctions.reaction_api import (
    app,
    new_issues,
    manual_requests_list,
    list_lock
)

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

    api_client, apis = initialize_kubernetes() #Initializes API

    issues = {}

    manual_response_call = {}
    manual_interventions = {}
    

    Rule_selector = RuleSelector(r'C:\Users\mrash\Python_Projects\Kubernetes_Project\Kubernetes_reaction_agent\response_rules') #Initialize Rule Selector with the path to the response rules directory
    
    start_time = datetime.now()
    print("Start:", start_time)

    #Options for responses, Validations, Escalations, and Descalations.
    Actions = {}
    Validations = {}
    Escalations = {}
    Descalations = {}

    #Currently loaded rules:
    rules = {}

    while True:
        current_time = datetime.now()
        
        for new_issue in new_issues: #If new issue is detected, check if it already exists in the issues dictionary. If it is the issue is updated.
            ID = new_issue["Issue_ID"]
            if ID not in issues:
                issues[ID], rules = create_issue(new_issue, Rule_selector,  rules, current_time,) #Create New Issue
            else:
                issues[ID] = update_issue(issues[ID], new_issue, current_time) #Update Existing Issue
        

        for ID, issue in issues.items():#Loops through each issue:

            if issue["Execution_Status"] not in ("Completed", "Failed"):#Executes step if step has not been executed.
                result, error = execute_tier(issue,current_time,Actions)

            

            if issue["Validation_Status"] not in ("Completed", "Failed"):#Executes validation if validation status is not complete.
                result, error = validate_tier(issue,current_time,Validations)

            if(issue["Execution_Status"] not in ("Completed", "Failed") and issue["Validation_Status"] not in ("Completed", "Failed")):#If both Executed and validated escalates on escalate check.
                result, error = escalate_tier_or_descalate(issue,current_time,Escalations)

            if(issue["Execution_Status"] not in ("Completed", "Failed") and issue["Validation_Status"] not in ("Completed", "Failed")):#If both executed and validated descalates on escalation check.
                result, error = escalate_tier_or_descalate(issue,current_time,Descalations)
        
            

       

main()
'''
Considerations as of now:

Need to handle errors that occur when Actions, Validations, Escalations, Descalations are not in the list.
Need to handle errors when responses fail.
Create a "Handle_Error" function that checks if an error occurred and what type then acts accordingly.
'''
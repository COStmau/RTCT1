
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field
from threading import Lock

app = FastAPI(title="Reaction Agent API")

# Shared incoming lists
new_issues = []
manual_requests_list = []

# Protect shared lists from simultaneous access
list_lock = Lock()


# -----------------------------
# Incoming data formats
# -----------------------------

class NewIssue(BaseModel):
    model_config = ConfigDict(extra="allow")

    Issue_ID: str
    Issue_type: str
    Resource_type: str
    Resource_name: str | list[str]
    Namespace: str | list[str]
    Severity: str


class ManualRequest(BaseModel):
    Issue_ID: str
    Action: str = Field(pattern="^(escalate|deescalate)$")


# -----------------------------
# API endpoints
# -----------------------------

@app.post("/issues", status_code=202)
def receive_issue(issue: NewIssue):

    data = issue.model_dump()

    data["Current_Severity"] = data.pop("Severity")
    data.setdefault("Information", {})

    with list_lock:
        new_issues.append(data)

    return {
        "status": "queued",
        "Issue_ID": data["Issue_ID"]
    }


@app.post("/manual", status_code=202)
def receive_manual_request(request: ManualRequest):

    data = request.model_dump()

    with list_lock:
        manual_requests_list.append(data)

    print(
        f"Manual request received: {data}",
        flush=True
    )

    return {
        "status": "queued",
        "request": data
    }


@app.get("/state")
def get_state():

    with list_lock:
        return {
            "new_issues": list(new_issues),
            "manual_requests_list": list(manual_requests_list)
        }


@app.get("/health")
def health():
    return {"status": "ok"}

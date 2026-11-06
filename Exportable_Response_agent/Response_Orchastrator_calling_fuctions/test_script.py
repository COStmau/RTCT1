
import time
import threading
import uvicorn

from reaction_api import app

from Get_Pending_Requests import get_pending_requests


def start_api():

    api_thread = threading.Thread(
        target=uvicorn.run,
        kwargs={
            "app": app,
            "host": "127.0.0.1",
            "port": 8000
        },
        daemon=True
    )

    api_thread.start()


def main():

    # Start FastAPI in a separate thread
    start_api()

    print("API test started!")
    print("Waiting for incoming requests...")

    while True:

        # Retrieve requests
        incoming_issues, manual_requests = get_pending_requests()

        if incoming_issues:
            print("\nReceived issues:", incoming_issues)

        if manual_requests:
            print("\nReceived manual requests:", manual_requests)

        time.sleep(0.1)


if __name__ == "__main__":
    main()


import logging

logging.basicConfig(
    filename="response_test.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

def dummy_action(issue, Time, parameters, API):
    """
    Dummy action for testing.
    Does not modify Kubernetes.
    """

    logging.info("Action executed")

    return True, None

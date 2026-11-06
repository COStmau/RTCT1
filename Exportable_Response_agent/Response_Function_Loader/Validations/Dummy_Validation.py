
import logging

def dummy_validation(issue, Time, parameters, API):
    """
    Dummy validation for testing.
    Does not interact with Kubernetes.
    """

    logging.info("Validation executed")

    return True, None

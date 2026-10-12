from kubernetes.client.exceptions import ApiException
import logging

def safe_api_call(func, **kwargs):
    try:
        return (func(**kwargs), None)

    except ApiException as e:
        logging.error(
            "%s failed: HTTP %s - %s",
            func.__name__, e.status, e.reason
        )
        return (None, e)
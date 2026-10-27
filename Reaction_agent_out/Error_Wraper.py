from kubernetes.client.exceptions import ApiException
import logging

def safe_api_call(func, **kwargs):
    try:
        result =  (func(**kwargs), None)

        logging.info(
            "%s succeeded with arguments: %s",
            func.__name__, kwargs
        )
        return result

    except ApiException as e:
        logging.error(
            "%s failed: HTTP %s - %s",
            func.__name__, e.status, e.reason
        )
        return (None, (e, func.__name__, e.status, e.reason))
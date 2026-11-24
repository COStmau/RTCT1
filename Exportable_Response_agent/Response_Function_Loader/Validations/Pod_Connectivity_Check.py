import time

from kubernetes import client
from kubernetes.stream import stream
from kubernetes.client.rest import ApiException

from ..Kubernetes_API_calls.Kube_API_calls import (
    read_namespaced_pod
)


def pod_connectivity_check(issue, Time, parameters, API):
    """
    Attempts a TCP connection from a source Pod to the target Pod.

    Returns:
        True, None  - Connection succeeded
        False, None - Connection failed
        None, error - Unable to perform validation
    """

    response = None

    try:
        namespace = issue["Namespace"]
        target_pod_name = issue["Resource_name"]

        parameters = parameters or {}

        source_pod_name = parameters.get("source_pod")
        source_namespace = parameters.get(
            "source_namespace", namespace
        )

        port = parameters.get("port", 80)
        timeout = parameters.get("timeout", 3)

        if not source_pod_name:
            return None, "Source pod must be specified"

        if source_pod_name == target_pod_name and source_namespace == namespace:
            return None, "Source and target pods must be different"

        if type(port) is not int or not 1 <= port <= 65535:
            return None, "Invalid target port"

        if type(timeout) is not int or timeout < 1:
            return None, "Invalid connection timeout"

        # 1. Retrieve target Pod
        target_pod, error = read_namespaced_pod(
            vi=API["core"],
            name=target_pod_name,
            namespace=namespace
        )

        if error:
            return None, error

        target_ip = target_pod.status.pod_ip

        if not target_ip:
            return None, "Target pod does not have an IP address"

        # 2. Retrieve source Pod
        source_pod, error = read_namespaced_pod(
            vi=API["core"],
            name=source_pod_name,
            namespace=source_namespace
        )

        if error:
            return None, error

        if source_pod.status.phase != "Running":
            return None, "Source pod is not running"

        # 3. Construct TCP connection test
        command = [
            "nc",
            "-z",
            "-w",
            str(timeout),
            target_ip,
            str(port)
        ]

        # Use a separate API client for exec streaming
        with client.ApiClient(
            configuration=API["core"].api_client.configuration
        ) as exec_client:

            exec_api = client.CoreV1Api(exec_client)

            # 4. Execute connection test from source Pod
            response = stream(
                exec_api.connect_get_namespaced_pod_exec,
                name=source_pod_name,
                namespace=source_namespace,
                command=command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=False
            )

            # 5. Wait for command completion
            deadline = time.monotonic() + timeout + 5

            while response.is_open():

                if time.monotonic() >= deadline:
                    return None, "Connectivity test execution timed out"

                response.update(timeout=1)

            exit_code = response.returncode
            stderr = response.read_stderr()

            # 6. Evaluate connection result
            if exit_code == 0:
                return True, None

            if exit_code == 1:
                print(f"TCP connection failed: {stderr}")
                return False, None

            return None, (
                f"Connectivity test failed to execute. "
                f"Exit code: {exit_code}. Error: {stderr}"
            )

    except ApiException as error:
        return None, (
            f"Kubernetes API error ({error.status}): "
            f"{error.reason}"
        )

    except Exception as error:
        return None, str(error)

    finally:
        if response is not None:
            response.close()
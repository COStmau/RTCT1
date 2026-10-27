from api_calls import *
from kubernetes import client, config
import time
import logging
next = time.perf_counter()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("response_agent.log")
    ]
)

try:
    config.load_incluster_config()
    print("Running inside Kubernetes")
except config.ConfigException:
    config.load_kube_config()
    print("Running outside Kubernetes")

def execute_command(input_com,policy=None):

    if(input_com[0] == 'list_namespace_pods' and len(input_com) == 2):
        pods = list_namespace_pods(v1, input_com[1])
        if pods[0] is None:
            print("Error occurred while listing pods:", pods[1])
        else:
            #print(pods[0])
            for pod in pods[0].items:
                print(pod.metadata.namespace, pod.metadata.name)

    elif(input_com[0] == 'get_pod_names' and len(input_com) == 2):
        pod_names = get_pod_names(v1, input_com[1])
        print(pod_names)

    elif(input_com[0] == 'read_namespace_pod' and len(input_com) == 3):
        pod = read_namespace_pod(v1, input_com[1], input_com[2])
        print(pod)

    elif(input_com[0] == 'read_namespaced_pod_status' and len(input_com) == 3):
        pod_status = read_namespaced_pod_status(v1, input_com[1], input_com[2])
        print(pod_status)

    elif(input_com[0] == 'read_pod_log' and len(input_com) == 3):
        pod_log = read_pod_log(v1, input_com[1], input_com[2])
        print(pod_log)

    elif(input_com[0] == 'delete_namespaced_pod' and len(input_com) == 3):
        delete_result = delete_namespaced_pod(v1, input_com[1], input_com[2])
        print(delete_result)

    elif(input_com[0] == 'list_deployments' and len(input_com) == 2):
        deployments = list_deployments(apps_v1, input_com[1])
        if deployments[0] is None:
            print("Error occurred while listing deployments:", deployments[1])
        else:
            for deployment in deployments[0].items:
                print(deployment.metadata.namespace,":", deployment.metadata.name)

    elif(input_com[0] == 'read_namespaced_deployment' and len(input_com) == 3):
        deployment = read_namespaced_deployment(apps_v1, input_com[1], input_com[2])
        print(deployment)

    elif(input_com[0] == 'patch_namespaced_deployment_scale' and len(input_com) == 4):
        patch_result = patch_namespaced_deployment_scale(apps_v1, input_com[1], input_com[2], body=input_com[3])
        print(patch_result)

    elif(input_com[0] == 'create_network_policy' and len(input_com) == 2):
        create_result = create_network_policy(networking_v1, input_com[1], body=policy)
        print(create_result)

    elif(input_com[0] == 'delete_network_policy' and len(input_com) == 3):
        delete_result = delete_network_policy(networking_v1, name=input_com[1], namespace=input_com[2])
        print(delete_result)

    elif(input_com[0] == 'list_network_policies' and len(input_com) == 2):
        network_policies = list_network_policies(networking_v1, input_com[1])
        if(network_policies[0] is None):
            print("Error occurred while listing network policies:", network_policies[1])
        else:
            for policy in network_policies:
                print(policy.metadata.namespace, policy.metadata.name)

    elif(input_com[0] == 'list_of_all_pods_all_namespaces' and len(input_com) == 1):
        all_pods = list_all_pods_all_namespaces(v1)
        if(all_pods[0] is None):
            print("Error occurred while listing all pods in all namespaces:", all_pods[1])
        else:
            for pod in all_pods[0]:
                print(pod.metadata.namespace, pod.metadata.name)

    elif(input_com[0] == 'list_events' and len(input_com) == 2):
        events = list_events(v1, input_com[1])
        if(events[0] is None):
            print("Error occurred while listing events:", events[1])
        else:
            for event in events:
                print(event.metadata.namespace, event.metadata.name)

    elif(input_com[0] == 'read_network_policy' and len(input_com) == 3):
        network_policy = read_network_policy(networking_v1, name=input_com[1], namespace=input_com[2])
        print(network_policy)
    else:
        print("Invalid command or incorrect number of arguments. Please try again.")

v1 = client.CoreV1Api()
apps_v1 = client.AppsV1Api()
networking_v1 = client.NetworkingV1Api()
policy = client.V1NetworkPolicy(metadata=client.V1ObjectMeta(name="deny-pod-a-egress"), spec=client.V1NetworkPolicySpec(pod_selector=client.V1LabelSelector(match_labels={"app": "pod-a"}), policy_types=["Egress"]))
patch = {"spec": {"replicas": 2}}
while True:
    print("time elapsed: ", time.perf_counter()-next)
    input_command = input("Enter values separated by commas: ").replace(" ", "").split(",")
    next = time.perf_counter()
    if(input_command[0] == '-1'):
        break
    execute_command(input_command, policy)






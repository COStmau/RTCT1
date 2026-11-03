from kubernetes import client, config

config.load_kube_config() #Loads the configuration required to communicate with the current kubernetes cluster

v1 = client.CoreV1Api() #Creates an instance of the CoreV1Api class, which provides methods for interacting with the Kubernetes API

print("Listing pods with their IPs:")

#Full list of commands: https://github.com/kubernetes-client/python/blob/master/kubernetes/README.md

ret = v1.list_namespaced_pod(namespace="default", watch=False) #Retrieves a list of all pods in the default namespace
pods= ret.items
for pod in pods:
    print(pod.metadata.namespace, pod.metadata.name)

v1.delete_namespaced_pod(name=pods[0].metadata.name, namespace="default") #Deletes the first pod in the default namespace

print("deleted pod: ", pods[0].metadata.name)

ret = v1.list_namespaced_pod(namespace="default", watch=False) #Retrieves a list of all pods in the default namespace
pods = ret.items
for pod in pods:
    print(pod.metadata.namespace, pod.metadata.name)

#This script acts as a test for the api calls 


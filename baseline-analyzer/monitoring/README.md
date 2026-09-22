\# Baseline Analyzer Monitoring Stack



\## Environment



Local development environment:



\- Windows

\- Docker Desktop

\- Minikube

\- Kubernetes

\- Helm

\- kube-prometheus-stack



\## Start Environment



1\. Start Docker Desktop.



2\. Start Minikube:



&#x20;  minikube start



3\. Verify Kubernetes:



&#x20;  kubectl get nodes

&#x20;  kubectl get pods -A



\## Install Monitoring Stack



Add Prometheus Community repository:



&#x20;  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

&#x20;  helm repo update



Install monitoring stack:



&#x20;  helm install monitoring prometheus-community/kube-prometheus-stack --namespace monitoring --create-namespace -f monitoring/values.yaml



Verify:



&#x20;  kubectl get pods -n monitoring



\## Access Grafana



Port forward:



&#x20;  kubectl port-forward -n monitoring svc/monitoring-grafana 3000:80



Open:



&#x20;  http://localhost:3000



Username:



&#x20;  admin



Retrieve password from Kubernetes secret.



\## Shutdown



&#x20;  minikube stop



Then quit Docker Desktop.


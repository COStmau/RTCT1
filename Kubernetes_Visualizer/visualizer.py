
"""Read-only Kubernetes Pod/NetworkPolicy relationship explorer.

Install: pip install 'streamlit>=1.35' kubernetes graphviz pandas
Run:     streamlit run cluster_visualizer.py
"""
import json
import streamlit as st
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

st.set_page_config(page_title="Kubernetes Policy Explorer", layout="wide")
st.title("Kubernetes Pod & NetworkPolicy Explorer")
st.caption("Live API snapshot. Relationships indicate podSelector matches, not verified network connectivity.")


def selector_matches_pod(selector, labels):
    """Match a Kubernetes LabelSelector with correct empty and NotIn semantics."""
    if selector is None:
        return False
    labels = labels or {}
    for k, v in (selector.match_labels or {}).items():
        if labels.get(k) != v:
            return False
    for e in selector.match_expressions or []:
        exists = e.key in labels
        values = e.values or []
        if e.operator == "In" and (not exists or labels[e.key] not in values):
            return False
        if e.operator == "NotIn" and (not exists or labels[e.key] in values):
            return False
        if e.operator == "Exists" and not exists:
            return False
        if e.operator == "DoesNotExist" and exists:
            return False
        if e.operator not in ("In", "NotIn", "Exists", "DoesNotExist"):
            return False
    return True


def serialize(obj):
    return client.ApiClient().sanitize_for_serialization(obj)


def pretty(obj):
    st.json(serialize(obj))


def policy_types(policy):
    # API responses typically have defaulted types, but explicitly handle omitted values.
    if policy.spec.policy_types:
        return list(policy.spec.policy_types)
    return ["Ingress"] + (["Egress"] if policy.spec.egress else [])


def node_id(kind, name):
    return json.dumps(f"{kind}:{name}")


def dot_text(s):
    return json.dumps(str(s))[1:-1]


try:
    config.load_kube_config()
    core = client.CoreV1Api()
    network = client.NetworkingV1Api()
    namespaces = sorted(ns.metadata.name for ns in core.list_namespace().items)
except Exception as exc:
    st.error(f"Cannot reach Kubernetes: {exc}")
    st.info("Verify `kubectl get pods -A` works and that your kubeconfig uses the intended cluster.")
    st.stop()

with st.sidebar:
    st.header("Cluster view")
    current = "network-test" if "network-test" in namespaces else (namespaces[0] if namespaces else None)
    if not namespaces:
        st.error("No namespaces returned")
        st.stop()
    namespace = st.selectbox("Namespace", namespaces, index=namespaces.index(current))
    st.button("Refresh snapshot", help="Rerun all read-only Kubernetes API queries")
    st.caption("Click a table row to open its inspector. Graph arrows mean 'selects', not 'allows'.")

try:
    pods = sorted(core.list_namespaced_pod(namespace).items, key=lambda p: p.metadata.name)
    policies = sorted(network.list_namespaced_network_policy(namespace).items, key=lambda n: n.metadata.name)
except ApiException as exc:
    st.error(f"Kubernetes API request failed: {exc}")
    st.stop()

pod_by_name = {p.metadata.name: p for p in pods}
policy_by_name = {p.metadata.name: p for p in policies}
pod_to_policies = {
    p.metadata.name: [n.metadata.name for n in policies if selector_matches_pod(n.spec.pod_selector, p.metadata.labels)]
    for p in pods
}
policy_to_pods = {
    n.metadata.name: [p.metadata.name for p in pods if selector_matches_pod(n.spec.pod_selector, p.metadata.labels)]
    for n in policies
}

m1, m2, m3 = st.columns(3)
m1.metric("Pods", len(pods))
m2.metric("NetworkPolicies", len(policies))
m3.metric("Policy selector matches", sum(map(len, policy_to_pods.values())))

st.subheader("Pod ↔ NetworkPolicy relationships")
lines = [
    "digraph G {", "rankdir=LR;", 'graph [bgcolor="transparent", pad="0.2", nodesep="0.3", ranksep="1.0"];',
    'node [shape=box, style="rounded,filled", fontname="Arial", fontsize=11, color="#8293a7"];',
    'edge [color="#ba8b2f", fontname="Arial", fontsize=9, arrowsize=0.7];',
    'subgraph cluster_pods { label="Pods"; style="rounded"; color="#8293a7";',
]
for p in pods:
    phase = p.status.phase or "Unknown"
    fill = "#d8f3e4" if phase == "Running" else "#fff1ce" if phase == "Pending" else "#ffdddd"
    lines.append(f'{node_id("pod", p.metadata.name)} [label="{dot_text(p.metadata.name)}\\n{dot_text(phase)}", fillcolor="{fill}"];')
lines += ["}", 'subgraph cluster_policies { label="NetworkPolicies"; style="rounded"; color="#8293a7";']
for n in policies:
    lines.append(f'{node_id("np", n.metadata.name)} [label="{dot_text(n.metadata.name)}", fillcolor="#ffedcc"];')
lines.append("}")
for n, names in policy_to_pods.items():
    for pod_name in names:
        lines.append(f'{node_id("np", n)} -> {node_id("pod", pod_name)} [label="selects"];')
lines.append("}")
st.graphviz_chart("\n".join(lines), use_container_width=True)
st.caption("The diagram is an overview. Click a row in either resource table below for its details. An empty podSelector matches every pod in the namespace.")

left, right = st.columns(2)
with left:
    st.subheader("Pods")
    pod_rows = [{
        "Name": p.metadata.name,
        "Phase": p.status.phase or "Unknown",
        "IP": p.status.pod_ip or "—",
        "Policies selecting pod": ", ".join(pod_to_policies[p.metadata.name]) or "None",
    } for p in pods]
    pod_event = st.dataframe(pod_rows, use_container_width=True, hide_index=True,
                             on_select="rerun", selection_mode="single-row", key="pod_table") if pod_rows else None
    if not pod_rows:
        st.info("No pods in this namespace.")
with right:
    st.subheader("NetworkPolicies")
    policy_rows = [{
        "Name": n.metadata.name,
        "Types": ", ".join(policy_types(n)),
        "Selected pods": ", ".join(policy_to_pods[n.metadata.name]) or "None",
    } for n in policies]
    policy_event = st.dataframe(policy_rows, use_container_width=True, hide_index=True,
                                on_select="rerun", selection_mode="single-row", key="policy_table") if policy_rows else None
    if not policy_rows:
        st.info("No NetworkPolicies in this namespace.")

st.divider()
st.subheader("Resource details")
pod_selected = pod_rows[pod_event.selection.rows[0]]["Name"] if pod_event and pod_event.selection.rows else None
policy_selected = policy_rows[policy_event.selection.rows[0]]["Name"] if policy_event and policy_event.selection.rows else None
# Keep dropdowns synchronized when the user clicks a different table row.
if pod_selected and st.session_state.get("last_clicked_pod") != pod_selected:
    st.session_state["inspect_pod"] = pod_selected
    st.session_state["last_clicked_pod"] = pod_selected
if policy_selected and st.session_state.get("last_clicked_policy") != policy_selected:
    st.session_state["inspect_policy"] = policy_selected
    st.session_state["last_clicked_policy"] = policy_selected
if pods and st.session_state.get("inspect_pod") not in pod_by_name:
    st.session_state["inspect_pod"] = pods[0].metadata.name
if policies and st.session_state.get("inspect_policy") not in policy_by_name:
    st.session_state["inspect_policy"] = policies[0].metadata.name
pod_tab, policy_tab = st.tabs(["Pod inspector", "NetworkPolicy inspector"])

with pod_tab:
    if not pods:
        st.info("No pods available.")
    else:
        pod_name = st.selectbox("Inspect pod", list(pod_by_name), key="inspect_pod")
        pod = pod_by_name[pod_name]
        st.markdown(f"### `{pod_name}`")
        c1, c2, c3 = st.columns(3)
        c1.metric("Phase", pod.status.phase or "Unknown")
        c2.metric("Pod IP", pod.status.pod_ip or "—")
        c3.metric("Node", pod.spec.node_name or "—")
        st.write("**Selecting NetworkPolicies**")
        selected_policies = pod_to_policies[pod_name]
        if not selected_policies:
            st.info("No NetworkPolicy selects this pod (within this namespace).")
        else:
            st.write(", ".join(f"`{name}`" for name in selected_policies))
            ingress = [name for name in selected_policies if "Ingress" in policy_types(policy_by_name[name])]
            egress = [name for name in selected_policies if "Egress" in policy_types(policy_by_name[name])]
            st.write(f"**Ingress isolated:** {'Yes' if ingress else 'No'} | **Egress isolated:** {'Yes' if egress else 'No'}")
            st.caption("Isolation describes whether at least one policy selects this pod for that direction, not whether specific peers can connect.")
        with st.expander("Metadata and labels", expanded=True):
            pretty(pod.metadata)
        with st.expander("Status, conditions, and container statuses"):
            pretty(pod.status)
        with st.expander("Pod spec (containers, images, volumes, resources, node, etc.)"):
            pretty(pod.spec)
        with st.expander("Complete Pod API object"):
            pretty(pod)

with policy_tab:
    if not policies:
        st.info("No NetworkPolicies available.")
    else:
        policy_name = st.selectbox("Inspect NetworkPolicy", list(policy_by_name), key="inspect_policy")
        policy = policy_by_name[policy_name]
        st.markdown(f"### `{policy_name}`")
        st.write("**Pods selected by this NetworkPolicy**")
        selected_pods = policy_to_pods[policy_name]
        if selected_pods:
            st.write(", ".join(f"`{name}`" for name in selected_pods))
        else:
            st.info("This policy currently selects no pods in this namespace.")
        st.write("**Policy types:**", ", ".join(policy_types(policy)))
        a, b = st.columns(2)
        with a:
            st.write("**Pod selector**")
            pretty(policy.spec.pod_selector)
            st.write("**Ingress rules**")
            pretty(policy.spec.ingress or [])
        with b:
            st.write("**Egress rules**")
            pretty(policy.spec.egress or [])
            st.write("**Metadata, labels and annotations**")
            pretty(policy.metadata)
        with st.expander("Complete NetworkPolicy API object"):
            pretty(policy)

st.info("Read-only: no labels, pods, or NetworkPolicies are created, patched, or deleted by this dashboard.")

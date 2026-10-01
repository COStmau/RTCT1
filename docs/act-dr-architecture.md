# Team 1 ACT-DR Architecture

Automated Network-Threat Diagnosis and Response — pipeline, testbed, and data flow.

```mermaid
%%{init: {"theme": "base", "themeVariables": {"fontFamily": "-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif", "fontSize": "15px", "primaryTextColor": "#111827", "secondaryTextColor": "#111827", "tertiaryTextColor": "#111827", "lineColor": "#475569", "edgeLabelBackground": "#ffffff", "clusterBkg": "#f8fafc", "clusterBorder": "#cbd5e1"}}}%%
flowchart TB

    subgraph K8S["Kubernetes C2 Testbed"]
        direction TB
        CP["RKE2 Control Plane<br/>Kubernetes API<br/>Cluster state / orchestration"]
        CP --> W1["Worker 1 - x86<br/>LiDAR workload"]
        CP --> W2["Worker 2 - x86<br/>Camera workload"]
        CP --> W3["Worker 3 - Raspberry Pi<br/>ROS 2 workload"]
        CP --> OT["Other C2 Workloads<br/>NGINX web service<br/>ROS controller<br/>Background network traffic"]
        W1 --> TEL["Multi-Point Telemetry<br/><br/>• Pod-level capture<br/>• Node-level capture<br/>• Router-level capture<br/>• tcpdump / ptcpdump<br/>• Zeek-capable sidecars"]
        W2 --> TEL
        W3 --> TEL
        OT --> TEL
    end

    subgraph PIPE["Team 1 ACT-DR Pipeline"]
        direction LR
        B["1. Baseline / Monitoring<br/><br/>• Characterize expected network behavior<br/>• Organize traffic into analysis windows<br/>• Prometheus metrics + PromQL<br/>• Grafana visualization<br/>• Update baseline only with trusted behavior"]
        DD["2. Detection & Diagnosis<br/><br/>• Compare live behavior against baseline<br/>• Thresholds + statistical deviation scores<br/>• Correlate indicators across time/resources<br/>• Explore ML methods where useful<br/>• Identify affected resource<br/>• Estimate severity and possible cause<br/>• Track improving / persisting / worsening state"]
        R["3. Response Agent<br/><br/>• Deterministic response policies first<br/>• Begin with least-disruptive action<br/>• Escalate if condition persists/worsens<br/>• Maintain, reduce, reverse, or escalate<br/>• Execute through Kubernetes API"]
        B -->|"Baseline model /<br/>expected ranges"| DD
        DD -->|"Location, severity,<br/>cause, status"| R
    end

    subgraph DATA["Development / Validation Data"]
        D1["Existing Dataset<br/>• Benign operation<br/>• Distributed web traffic<br/>• LiDAR replay attack<br/>• Sidecar / Nmap reconnaissance"]
    end

    D1 -->|"Evaluate detection methods"| DD
    TEL -->|"Live metrics"| B
    TEL -->|"Live observations"| DD
    R -->|"Kubernetes API actions"| CP
    R -.->|"Response changes<br/>cluster state"| TEL
    DD -.->|"Exclude anomalous windows<br/>from baseline updates"| B

    classDef baseline fill:#dbeafe,stroke:#2563eb,color:#111827,stroke-width:2px;
    classDef detection fill:#fef3c7,stroke:#d97706,color:#111827,stroke-width:2px;
    classDef response fill:#fee2e2,stroke:#dc2626,color:#111827,stroke-width:2px;
    classDef k8snode fill:#ecfdf5,stroke:#059669,color:#111827,stroke-width:2px;
    classDef data fill:#f3f4f6,stroke:#6b7280,color:#111827,stroke-width:1.5px;

    class B baseline;
    class DD detection;
    class R response;
    class CP,W1,W2,W3,OT,TEL k8snode;
    class D1 data;
```

## Reading the diagram

- **Subsystems 1–3** (blue / amber / red) are the three Team 1 deliverables. Subsystem 2 (`Threat_Detection/`) is the detector/diagnoser between the baseline and the response agent.
- **Kubernetes C2 Testbed** is where the pipeline runs: an RKE2 control plane over three workers (two x86, one Raspberry Pi) plus the C2 workloads. The green boxes are cluster components; the enclosing subgraph is deliberately neutral so it reads as a container, not a subsystem.
- **The baseline is fed only by live cluster telemetry** (`Multi-Point Telemetry` → `Baseline / Monitoring`). The development dataset now feeds the detector only, for evaluating detection methods, and is no longer a second input to the baseline.
- **Solid arrows** are primary data flow; **dashed arrows** are feedback loops. The response agent's actions change cluster state, which the same telemetry observes, and anomalous windows are excluded from baseline updates so the detector does not learn the attack as normal.

## Rendering notes

Both workarounds below were measured, not assumed.

- **Pinned light theme.** The diagram sets `theme: base` with explicit `themeVariables`, and every `classDef` carries an explicit `color:`. GitHub re-themes Mermaid to match its own light/dark setting; without the pin, label text inherits a theme colour that clashes with the light box fills and the figure becomes unreadable in dark mode. All 50 labels now clear WCAG AA (4.5:1) in both light and dark, worst case 14.5:1.
- **`cluster` is a reserved class name.** Mermaid uses `.cluster` internally for subgraph boxes, so a `classDef cluster` silently repaints *every* subgraph in the diagram. The Kubernetes component class is named `k8snode` for that reason.
- **Layout is `flowchart TB`, not `LR`.** The original horizontal layout rendered a 3199px-wide SVG that GitHub scaled to 0.32×, shrinking 16px text to roughly 5px — the main cause of the "hard to read" symptom. The current layout is 1353px wide and scales to 0.75×.
- `direction` inside a subgraph is ignored when edges enter those nodes from outside, so the subgraphs keep their inherited direction. That is expected Mermaid behaviour, not a defect in the diagram.

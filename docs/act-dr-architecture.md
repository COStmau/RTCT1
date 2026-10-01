# Team 1 ACT-DR Architecture

Automated Network-Threat Diagnosis and Response — pipeline, testbed, and data flow.

```mermaid
flowchart LR

    %% =========================
    %% DEVELOPMENT / TEST DATA
    %% =========================
    subgraph DATA["Development / Validation Data"]
        D1["Existing Dataset<br/>• Benign operation<br/>• Distributed web traffic<br/>• LiDAR replay attack<br/>• Sidecar / Nmap reconnaissance"]

        D2["Stretch Inputs<br/>• Threat intelligence<br/>• Indicators of Compromise<br/>• abuse.ch"]
    end

    %% =========================
    %% ACT-DR PIPELINE
    %% =========================
    subgraph PIPE["Team 1 ACT-DR Pipeline"]

        B["1. Baseline / Monitoring Subsystem<br/><br/>
        • Characterize expected network behavior<br/>
        • Organize traffic into analysis windows/checkpoints<br/>
        • Prometheus metrics + PromQL<br/>
        • Grafana visualization<br/>
        • Update baseline only with trusted behavior"]

        DD["2. Detection & Diagnosis Subsystem<br/><br/>
        • Compare live behavior against baseline<br/>
        • Thresholds + statistical deviation scores<br/>
        • Correlate indicators across time/resources<br/>
        • Explore ML methods where useful<br/>
        • Identify affected resource<br/>
        • Estimate severity and possible cause<br/>
        • Track improving / persisting / worsening state"]

        R["3. Response Agent<br/><br/>
        • Deterministic response policies first<br/>
        • Begin with least-disruptive action<br/>
        • Escalate if condition persists/worsens<br/>
        • Maintain, reduce, reverse, or escalate response<br/>
        • Execute through Kubernetes API"]

        B -->|"Baseline model / expected ranges"| DD
        DD -->|"Location, severity, cause,<br/>uncertainty, status"| R
    end

    %% =========================
    %% KUBERNETES TESTBED
    %% =========================
    subgraph K8S["Kubernetes C2 Testbed"]

        CP["RKE2 Control Plane<br/>Kubernetes API<br/>Cluster state / orchestration"]

        W1["Worker 1 - x86<br/>LiDAR workload"]
        W2["Worker 2 - x86<br/>Camera workload"]
        W3["Worker 3 - Raspberry Pi<br/>ROS 2 workload"]

        OTHER["Other C2 Workloads<br/>NGINX web service<br/>ROS controller<br/>Background network traffic"]

        TEL["Multi-Point Telemetry<br/><br/>
        • Pod-level capture<br/>
        • Node-level capture<br/>
        • Router-level capture<br/>
        • tcpdump<br/>
        • ptcpdump<br/>
        • Zeek-capable sidecars"]

        CP --> W1
        CP --> W2
        CP --> W3
        CP --> OTHER

        W1 --> TEL
        W2 --> TEL
        W3 --> TEL
        OTHER --> TEL
    end

    %% =========================
    %% DATA FLOW
    %% =========================
    D1 -->|"Establish normal behavior"| B
    D1 -->|"Evaluate detection methods"| DD
    D2 -.->|"Stretch goal"| DD

    TEL -->|"Live telemetry / metrics"| B
    TEL -->|"Live telemetry / observations"| DD

    R -->|"Kubernetes API actions"| CP

    %% =========================
    %% RESPONSE FEEDBACK
    %% =========================
    R -.->|"Response changes cluster state"| TEL
    DD -.->|"Exclude anomalous windows<br/>from baseline updates"| B

    %% =========================
    %% RESPONSE TYPES
    %% =========================
    RESP["Tiered Response Actions<br/><br/>
    Monitor<br/>↓<br/>
    Restrict traffic<br/>↓<br/>
    Isolate / modify workload<br/>↓<br/>
    Restart pod<br/>↓<br/>
    Remove / reset node"]

    R --> RESP

    %% =========================
    %% STYLING
    %% =========================
    classDef baseline fill:#dbeafe,stroke:#2563eb,stroke-width:2px;
    classDef detection fill:#fef3c7,stroke:#d97706,stroke-width:2px;
    classDef response fill:#fee2e2,stroke:#dc2626,stroke-width:2px;
    classDef cluster fill:#ecfdf5,stroke:#059669,stroke-width:2px;
    classDef data fill:#f3f4f6,stroke:#6b7280,stroke-width:1.5px;

    class B baseline;
    class DD detection;
    class R,RESP response;
    class CP,W1,W2,W3,OTHER,TEL cluster;
    class D1,D2 data;
```

## Reading the diagram

- **Subsystems 1–3** (blue / amber / red) are the three Team 1 deliverables. Subsystem 2 (`Threat_Detection/`) is the detector/diagnoser between the baseline and the response agent.
- **Kubernetes C2 Testbed** (green) is where the pipeline runs: an RKE2 control plane over three workers (two x86, one Raspberry Pi) plus the C2 workloads.
- **Solid arrows** are primary data flow; **dashed arrows** are stretch inputs and feedback loops.
- The **response feedback** loop is the part that closes the architecture: the response agent's actions change cluster state, which is observed by the same telemetry feeding the baseline, and anomalous windows are excluded from baseline updates so the detector does not learn the attack as normal.
- **Tiered response actions** run least-disruptive to most: monitor → restrict traffic → isolate/modify workload → restart pod → remove/reset node.

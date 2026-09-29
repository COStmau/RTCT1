\# Candidate Baseline Metrics



This document records Prometheus metrics being evaluated for use in the

Baseline Analyzer subsystem.



\## Test Workload



A benign nginx workload was deployed in the `baseline-test` namespace.



Normal HTTP requests were generated and the resulting metrics were visualized within Grafana.





\# Baseline Metrics



| Metric | Result | Decision |

|---|---|---|

| Pod CPU Usage | Reacted to HTTP requests | Keep |

| Pod Memory Usage | Reacted to HTTP requests | Keep |

| Network RX | Did not react | Remove |

| Network TX | Did not react clearly to HTTP requests | Retest |

| Node Memory Usage | Reacted to HTTP requests | Keep |

| Node CPU Usage | Reacted somewhat to HTTP requests | Retest |

| Pod Restarts | Did not react | Supporting Metric (Remove) |

| Pod Readiness | Did not react | Supporting Metric (Remove) |





The initial statistical baseline will focus primarily on:



* Pod CPU Usage
* Pod Memory Usage
* Network Transmit Rate



The Node Usages will be retained for a broader overview



Next step is to:



* Repeat the process but with a heavier workload than the previous few runs 
* Determine Consistency with the metrics
* Calculate statistical data (mean, median, std)


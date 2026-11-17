"""The hybrid feature-set verdict: the eight features plus `packet_count`, fixed before it ran.

`dev/verdicts/feature_set.py` dropped the eight-feature set because of one condition, ptcp
injection AUROC (0.152 lost, 0.10 allowed), carried by two strata of 6 and 11 windows. The
hypothesis here is that injection is seen partly through volume, so one volume feature put
back protects it. `packet_count` is the choice because `total_bytes` is clipped at the
recorder's size limit on the three bulk taps and `payload_bytes` underperformed it as a ranker;
the choice was made before this candidate was run, and it is the only one that will be run.

The rule is the previous rule, unchanged: the thresholds are imported from
`dev/verdicts/feature_set.py` rather than copied, so they cannot differ. Changing them to suit this
candidate would be editing the old rule, which is a different commit and has to be said so.

Disclosure, in addition to the previous module's: this is the second candidate judged on the
same benign and attack recordings. The first one's results are known and guided this one, so
the false-alarm side is more optimistic than before, not less, and a pass here is evidence the
set is worth taking to data the project has not seen, not proof. There is no third candidate:
a drop here means the project stays on all 13.

"keep" means adopt the hybrid, "drop" means stay on all 13.
"""
from verdicts import feature_set as previous
from verdicts.feature_set import (MAX_AUROC_LOSS, MAX_DETECTION_LOSS, METHODS,   # noqa: F401
                                  MIN_ALERT_REDUCTION, MIN_BENIGN_WINDOWS, SCENARIOS, decide)

CANDIDATE = ["packet_count", "unique_dst_ips", "unique_dst_ports", "syn_count", "rst_count",
             "http_count", "dns_count", "https_count", "http_frac"]
PREVIOUS_CANDIDATE = ["unique_dst_ips", "unique_dst_ports", "syn_count", "rst_count",
                      "http_count", "dns_count", "https_count", "http_frac"]
assert set(CANDIDATE) == set(PREVIOUS_CANDIDATE) | {"packet_count"}
assert decide is previous.decide

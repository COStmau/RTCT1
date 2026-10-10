# 2-minute progress update for the TA

Read the blocks in order. About 250 words, close to two minutes at a normal pace.
Point at the screen when a block says so.

---

**1. What I did this week (about 45 seconds).**
"Last week I said the alarm level was not calibrated, and that three capture points were
flagging up to eighty-five percent of normal traffic. That framing was wrong, and I want to
correct it plainly. Those three points are where the recording tool hit its own size limit —
fifty-nine percent of packets there are truncated at the capture ceiling — and they are also
where normal traffic changes character mid-recording, from about fifty kilobytes a second to
several hundred megabytes. A detector is supposed to notice that. So this week I stopped
tuning against those numbers and measured what is actually happening instead."

**2. Point at the screen, step 5 (about 40 seconds).**
"[run: `.venv/bin/python walkthrough.py` — scroll to step 5.] Each second of traffic
is compared against what normal looks like, and that normal is learned only from normal
traffic. The last thirty percent of the normal recording is held back, so the detector is
never graded on the seconds it learned from. Of the normal seconds it had never seen,
three of nineteen flag — and none of them in a run, so no alert fires. Of the attack
seconds, fifty-one of sixty are flagged, forty-nine of them in sustained runs of three or
more — that is what my part actually raises on. Step 6 shows the evidence: total bytes go
from two hundred and sixty-four to seven thousand eight hundred and seventy."

**3. How this gets me to my end goal (about 30 seconds).**
"My part of the system has to turn raw traffic into a diagnosis another part can act on:
recognise that behaviour has drifted from normal, say where it happened and how strong the
evidence is, and be honest about what it cannot tell. This week I also added the protocol
measurements the design asked for and never had — how much of a second's traffic is HTTP,
DNS, or HTTPS. On the web attack those are the second-strongest single trigger I have."

**4. What is next (about 25 seconds).**
"Two things. First, quote the numbers properly: I can give a false-alarm figure from the
sixteen capture points whose traffic is steady, and a separate detection figure per attack
scenario, and I will not blend them together. Second, the real blocker: we have one benign
recording per capture point. Per-point calibration needs several, or there is nothing
stationary to calibrate against. That is a question for the sponsor, and it is what I want
to bring to Friday."

---

## If he cuts you off after 30 seconds

"Progress: I corrected last week's false-alarm claim — the three worst capture points are
where the recorder truncates and where normal traffic changes character, so flagging there
is correct, not a defect. The honest number is zero-point-three-one on the sixteen steady
capture points. Next: more than one benign recording per point, or there is nothing
stationary to calibrate against."

## Numbers to have ready if asked

- Steady-state benign flag fraction, 16 captures, held-out windows: **0.31** (max 0.65).
- Bulk-transfer captures, 6 of 22: **0.93** — drift detection, not false alarms.
- Detection, 8 steady strata, tcp: injection **0.60**, lidar **0.46**, nginx **0.66**.
- The step-5 demo pair is `pod-nginx` benign vs nginx attack: 3 of 19 unseen benign seconds
  flag with zero alerts, 51 of 60 attack seconds flag with 49 alerts. That single pair is a
  clean case and is not the same as the 0.31 pooled figure — say which one you mean.
- Snaplen: **22 of 88** captures truncated at the 65535-byte ceiling; all 22 are the three
  vantages that also carry the regime change.
- New features: `http_count` auc 0.794 on nginx attack, flags 0.703 of attack windows at a 5%
  benign budget. `https_count` does not earn a slot — little HTTPS in this testbed.
- Baseline is now median + MAD rather than mean + std, because mean/std was set by the
  bulk-transfer windows.
- Tests: 41, all passing.
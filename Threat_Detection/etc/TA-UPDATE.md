# 2-minute progress update for the TA

Read the blocks in order. About 240 words, close to two minutes at a normal pace.
Point at the screen when a block says so.

---

**1. What I did this week (about 40 seconds).**
"Last week I showed a chart that only illustrated the shape of the output. It was not
generated from the data, and I want to say that plainly. This week the same analysis runs
for real, across every recording the sponsor gave us: four scenarios, eleven capture
points, two capture methods, eighty-eight files, in about eight seconds. One of those
files turned out to be damaged, and the run flags it rather than quietly working around
it."

**2. Point at the screen, step 5 (about 45 seconds).**
"[run: `.venv/bin/python walkthrough.py` — scroll to step 5.] Each second of traffic
is compared against what normal looks like, and that normal is learned only from normal
traffic. The last thirty percent of the normal recording is held back, so the detector is
never graded on the seconds it learned from. Of the normal seconds it had never seen,
zero are flagged. Of the attack seconds, forty-eight of sixty are flagged, and forty-one
of those are in sustained runs of three or more — that is what my part actually raises on.
Step 6 shows the evidence: mean packet size goes from one hundred and five bytes to two
hundred and seventy-three."

**3. How this gets me to my end goal (about 30 seconds).**
"My part of the system has to turn raw traffic into a diagnosis another part can act on:
recognise that behaviour has drifted from normal, say where it happened and how strong the
evidence is, and be honest about what it cannot tell. This week is the first time that
works end to end on real data, at every observation point we have — and it also shows
which of those points are worth instrumenting, which I could not answer before."

**4. What is next (about 25 seconds).**
"Two things. The alarm level is not calibrated yet: at the current setting thirty-one
percent of normal seconds flag on average, and it is worse at some capture points than
others, so I am not quoting those as a detection rate. Next is calibrating per capture
point to a fixed false-alarm budget, then settling which measurements the monitoring side
can actually supply, because most of what I measure only exists in the packet recordings.
That is the Friday discussion."

---

## If he cuts you off after 30 seconds

"Progress: my part now runs for real across all eighty-eight recordings instead of one
pair of files, and it flags zero of the normal seconds it had not seen against forty-eight
of sixty attack seconds. Next: calibrating the alarm level per capture point, because it
currently over-flags normal traffic."

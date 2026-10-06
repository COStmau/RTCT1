# 2-minute update for the TA

Say it in this order, point at the screen when the block says so. Roughly 280 words,
which is about two minutes at a normal pace.

---

**1. Where my part sits (about 25 seconds).**
"The team's threat system has three parts, and I own the middle one. Part one watches
the cluster and decides what normal looks like. Part two, mine, decides when behaviour
has moved far enough away from that normal that somebody should be told, and explains
where it happened and how strong the evidence is. Part three takes the action, like
isolating a pod. Mine never touches the cluster; it produces the diagnosis the other two
work from."

**2. What is new this week (about 30 seconds).**
"Last week I showed a chart that only illustrated the shape of the output. It was not
generated from the data, and I want to be clear about that. This week the same analysis
runs for real, over every recording the sponsor gave us: four scenarios, eleven capture
points, two capture methods, eighty-eight files, in about eight seconds. One of those
files turned out to be damaged, and instead of quietly working around it the run flags
it."

**3. Point at the screen, step 5 (about 40 seconds).**
"[run: `.venv/bin/python ta_walkthrough.py`, scroll to step 5] Here it is on one pair of
recordings. Each second of traffic gets compared to what normal looks like. Of the
normal seconds the detector had never seen, zero are flagged. Of the attack seconds,
forty-eight of sixty are flagged, and forty-one of those come in sustained runs of three
or more, which is what my part actually raises an alarm on. Step 6 shows what stood out:
mean packet size went from about a hundred and five bytes to two hundred and seventy."

**4. What it feeds (about 20 seconds).**
"That flagged set of seconds, with the location and the evidence, is what my part hands
to part three. It also tells part one which intervals were suspicious, so attack traffic
is not learned as normal the next time the baseline is updated."

**5. The honest state of it (about 25 seconds).**
"Two things are not finished. The alarm level is not calibrated yet: with the current
setting, thirty-one percent of normal seconds flag on average, and it is worse at some
capture points than others, so those detection numbers cannot be quoted as a success
rate yet. And the measurement question is open: most of what I measure only exists in
the packet recordings, so part one's monitoring stack may not be able to supply it.
That is what I want to settle with the sponsor on Friday."

---

## If he cuts you off after 30 seconds

"My part is the detection and diagnosis in the middle: it decides when behaviour has
drifted far enough from normal to report, where it happened, and with what evidence, and
it hands that to the response part. This week it runs for real across all eighty-eight
recordings instead of one pair, and it flags zero of the normal seconds it had not seen
and forty-eight of sixty attack seconds, with the alarm level still needing calibration."

## If he asks "how do you know it's right?"

"Three checks. The normal recording is split, and the detector never sees the last
thirty percent while learning, so it is not marking its own homework. Every detection
number is paired with how often the same capture point flags on normal traffic. And when
the numbers looked good at a capture point where normal traffic is noisy, that is printed
next to them instead of being hidden."

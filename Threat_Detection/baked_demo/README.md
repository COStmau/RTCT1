# baked_demo/

The results of the KUBEDATA build, precomputed so that a clone with no dataset still has
something to look at. No raw capture is in here.

| File | What it is |
|---|---|
| `state_machine.html` | The interactive page, self-contained. Double-click it; it opens offline in any browser, no Python needed. |
| `bundle.json.gz` | The same page's data. `viz/serve.py` (and `run.py`) open on it when `local_paths.KUBEDATA_ROOT` is not set. |

Provenance paths are written relative to the dataset root (`KUBEDATA/benign/...`), and
`viz/bake.py` refuses to write if any local path is still inside.

Regenerate after a pipeline change, on a machine that has the captures:

```bash
.venv/bin/python viz/bake.py
```

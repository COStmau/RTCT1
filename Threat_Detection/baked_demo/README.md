# baked_demo/

The results of the KUBEDATA build, precomputed. A clone with no dataset still has something to
look at. This folder holds no raw capture.

| File | What it is |
|---|---|
| `state_machine.html` | The interactive page, self-contained. Double-click it. It opens offline in any browser and needs no Python. |
| `bundle.json.gz` | The data for the same page. `viz/serve.py` (and `run.py`) open on it when `local_paths.KUBEDATA_ROOT` is not set. |

The build writes provenance paths relative to the dataset root (`KUBEDATA/benign/...`).
`viz/bake.py` refuses to write if a local path is still inside.

To regenerate after a pipeline change, use a machine that has the captures:

```bash
.venv/bin/python viz/bake.py
```

"""Bake today's page into baked_demo/, so a clone with no dataset still has something to open.

    .venv/bin/python viz/bake.py

Builds the same bundle the harness preloads from KUBEDATA (viz/serve.Harness.preload), then
writes two files into Threat_Detection/baked_demo/, which is tracked in git:

  bundle.json.gz      the bundle; viz/serve.py opens on it when there is no KUBEDATA_ROOT
  state_machine.html  the static page; opens offline in any browser, no Python needed

No raw capture is copied. Provenance paths are rewritten relative to the dataset root
(KUBEDATA/benign/...), and the write is refused if any local path is still inside.
"""
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from viz import page

BAKED_DIR = Path(__file__).resolve().parents[1] / "baked_demo"
BUNDLE_FILE = "bundle.json.gz"
PAGE_FILE = "state_machine.html"
ORIGIN = "KUBEDATA manifest (baked)"


def _relative(path, root):
    """`path` as KUBEDATA/<path under root>, with forward slashes; unchanged if not under it."""
    try:
        return "KUBEDATA/" + Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).name


def _replace(value, old, new):
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, dict):
        return {k: _replace(v, old, new) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace(v, old, new) for v in value]
    return value


def scrub(bundle, root):
    """The bundle with every local path rewritten relative to the dataset root."""
    source = dict(bundle.get("source") or {})
    source["files"] = [dict(f, path=_relative(f["path"], root)) for f in source.get("files", [])]
    source["origin"] = ORIGIN
    bundle = dict(bundle, source=source)
    for old in {str(Path(root).expanduser()), str(Path(root).expanduser().resolve())}:
        bundle = _replace(bundle, old, "KUBEDATA")
    return bundle


def leaks(text, root=None):
    """The local-path markers still present in `text` (empty when it is safe to share)."""
    markers = [str(Path.home()), "/Users/", "GoogleDrive", "tamu.edu", "CloudStorage"]
    if root:
        markers.append(str(root))
    return [m for m in markers if m and m in text]


def load_bundle(path):
    """A bundle from .json or .json.gz."""
    path = Path(path)
    raw = path.read_bytes()
    if path.suffix == ".gz":
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8"))


def bake(root, out_dir=BAKED_DIR):
    from viz.serve import Harness

    bundle = scrub(Harness(root, quiet=True).preload(), root)
    data = page.to_json(bundle)
    html = page.page_html(bundle)
    found = leaks(data, root) + leaks(html, root)
    if found:
        raise ValueError(f"Refusing to bake: local paths still inside ({', '.join(sorted(set(found)))})")
    out_dir.mkdir(exist_ok=True)
    # mtime=0 keeps the gzip byte-identical across rebakes of the same bundle
    (out_dir / BUNDLE_FILE).write_bytes(gzip.compress(data.encode("utf-8"), mtime=0))
    written = page.write_html(bundle, out_dir / PAGE_FILE)
    if leaks(written.read_text(encoding="utf-8"), root):
        written.unlink()
        raise ValueError("Refusing to bake: the trimmed page carries a local path")
    return bundle, out_dir / BUNDLE_FILE, written


def main():
    try:
        import local_paths
        root = getattr(local_paths, "KUBEDATA_ROOT", "")
    except ImportError:
        root = ""
    if not root:
        sys.exit("Baking needs the KUBEDATA captures: set KUBEDATA_ROOT in local_paths.py.")
    bundle, data, html = bake(root)
    print(f"{len(bundle['vantages'])} taps, opens on {bundle['selected']}")
    for path in (data, html):
        print(f"  wrote {path.relative_to(BAKED_DIR.parent)}  {path.stat().st_size / 1e6:.2f} MB")


if __name__ == "__main__":
    main()

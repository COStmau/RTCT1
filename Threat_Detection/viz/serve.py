"""The harness: the state-machine page served live, so its Data tab can load any capture.

viz/page.py bakes one bundle into a static file. This serves the same page from a small local
server, whose Data tab scans folders, takes uploads, assigns each capture a role and tap,
sets the cluster profile and rebuilds; Cluster, Learning and Detection then redraw from the
new bundle. Export writes the static page again, for sharing without the server.

Run it with:  .venv/bin/python viz/serve.py                 (opens on today's page when
                                                            local_paths.KUBEDATA_ROOT is set)
              .venv/bin/python viz/serve.py --open --data ~/captures
              .venv/bin/python viz/serve.py --no-preload --port 9000

Python standard library only. It binds 127.0.0.1: it reads any path you type into it, so it
is a tool for the machine it runs on, never a service to expose.

  GET  /                  the page (server mode)
  GET  /api/state         current build's provenance, profile presets, defaults
  POST /api/scan          {paths, recursive} -> scan rows
  POST /api/manifest      {root, method} -> assignment rows from a KUBEDATA tree
  POST /api/upload        raw body, X-Filename header -> the stored file's scan row
  POST /api/build         {assignments, profile, forget, selected, allow_bulk} -> bundle
  GET  /api/export        the current bundle as a static page (outputs/harness_export.html)
  GET  /api/live          ?path=&speed= -> text/event-stream of 1-second windows (replay)
"""
import json
import sys
import threading
import traceback
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# A script run as `python viz/serve.py` gets viz/ as sys.path[0], so the
# project root has to go back on the path before any project import.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.data_io import MANIFEST_NAME, load_manifest
from methods.scores import FORGET_SECONDS
from viz import cluster as topology
from viz import page
from viz import sources

HOST = "127.0.0.1"
EXPORT_HTML = "harness_export.html"   # never state_machine.html: that is viz/page.py's page
DEFAULT_PORT = 8765
MAX_UPLOAD = 2 * 1024 ** 3        # bytes; captures are large, but not unbounded
MAX_JSON = 16 * 1024 ** 2


class Harness:
    """The server's state: one current bundle, one upload folder per run."""

    def __init__(self, kubedata_root=None, manifest_name=MANIFEST_NAME, quiet=False):
        self.bundle = None
        self.quiet = quiet
        self.kubedata_root = kubedata_root
        self.manifest_name = manifest_name
        self.session = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.lock = threading.Lock()
        self.notes = []
        self.initial_scan = ""

    def manifest_rows(self, root=None, method="tcp"):
        root = root or self.kubedata_root
        if not root:
            raise ValueError("No KUBEDATA root: type one, or set KUBEDATA_ROOT in local_paths.py.")
        if not Path(root).expanduser().is_dir():
            raise ValueError(f"No such folder: {root}")
        # a cached manifest belongs to the root it was built from; another root rebuilds it
        same = self.kubedata_root and Path(root).expanduser() == Path(self.kubedata_root).expanduser()
        manifest = load_manifest(str(Path(root).expanduser()), name=self.manifest_name,
                                 rebuild=not same)
        return sources.manifest_assignments(manifest, method)

    def preload(self):
        """Build today's default page from KUBEDATA, so the harness opens where the demo does."""
        rows = self.manifest_rows()
        bundle = sources.build(rows, origin="KUBEDATA manifest")
        with self.lock:
            self.bundle = bundle
        return bundle

    def build(self, request):
        profile = topology.profile_from_dict(request.get("profile"))
        bundle = sources.build(request.get("assignments") or [], profile=profile,
                               forget=float(request.get("forget") or FORGET_SECONDS),
                               selected=request.get("selected") or None,
                               allow_bulk=bool(request.get("allow_bulk")),
                               origin=request.get("origin") or "files")
        with self.lock:
            self.bundle = bundle
        return bundle

    def state(self):
        return {"source": (self.bundle or {}).get("source"),
                "has_bundle": self.bundle is not None,
                "profiles": {name: p.to_dict() for name, p in topology.PROFILES.items()},
                "defaults": {"forget": FORGET_SECONDS, "kubedata_root": self.kubedata_root or "",
                             "upload_folder": str(sources.resolve_output(sources.UPLOAD_DIR) / self.session),
                             "scan": self.initial_scan},
                "roles": list(sources.ROLES), "levels": ["pod", "node", "router"],
                "notes": self.notes}


def make_handler(harness):
    class Handler(BaseHTTPRequestHandler):
        server_version = "viz-harness/1"

        def log_message(self, fmt, *args):   # one quiet line per request
            if harness.quiet:
                return
            sys.stderr.write(f"  {self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}\n")

        # ------------------------------------------------ responses
        def send_json(self, payload, status=200, bundle=False):
            # a bundle goes out as the page reads it, every string HTML-escaped (page.to_json);
            # everything else is plain JSON, so a path with '&' comes back as typed
            text = page.to_json(payload) if bundle else json.dumps(payload, default=str)
            body = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def send_error_json(self, error, status=400):
            self.send_json({"error": str(error)}, status)

        def read_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_JSON:
                raise ValueError("request too large")
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def guarded(self, action):
            try:
                action()
            except (ValueError, KeyError, FileNotFoundError, NotImplementedError) as error:
                self.send_error_json(error, 400)
            except Exception as error:   # report, keep serving
                traceback.print_exc()
                self.send_error_json(f"{type(error).__name__}: {error}", 500)

        # ------------------------------------------------ routes
        def do_GET(self):
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                return self.guarded(self.page)
            if url.path == "/api/state":
                return self.guarded(lambda: self.send_json(harness.state()))
            if url.path == "/api/export":
                return self.guarded(self.export)
            if url.path == "/api/live":
                return self.guarded(lambda: self.live(parse_qs(url.query)))
            self.send_error_json("not found", 404)

        def do_HEAD(self):
            self.send_response(200 if urlparse(self.path).path in ("/", "/index.html") else 404)
            self.end_headers()

        def do_POST(self):
            url = urlparse(self.path)
            routes = {"/api/scan": self.scan, "/api/manifest": self.manifest,
                      "/api/build": self.build, "/api/upload": self.upload}
            if url.path not in routes:
                return self.send_error_json("not found", 404)
            self.guarded(routes[url.path])

        def page(self):
            body = page.page_html(harness.bundle, server=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def scan(self):
            request = self.read_json()
            paths = request.get("paths") or []
            if isinstance(paths, str):
                paths = [p for p in paths.splitlines() if p.strip()]
            self.send_json({"files": sources.scan(paths, bool(request.get("recursive", True)))})

        def manifest(self):
            request = self.read_json()
            rows = harness.manifest_rows(request.get("root") or None, request.get("method") or "tcp")
            self.send_json({"files": rows})

        def build(self):
            self.send_json(harness.build(self.read_json()), bundle=True)

        def upload(self):
            name = sources.safe_upload_name(self.headers.get("X-Filename"))
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                raise ValueError("empty upload")
            if length > MAX_UPLOAD:
                raise ValueError(f"upload over {MAX_UPLOAD / 1024 ** 3:.0f} GB")
            target = sources.upload_folder(harness.session) / name
            remaining = length
            with open(target, "wb") as handle:
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1 << 20))
                    if not chunk:
                        raise ValueError("upload ended early")
                    handle.write(chunk)
                    remaining -= len(chunk)
            self.send_json({"file": sources.describe_file(target),
                            "folder": str(target.parent)})

        def export(self):
            if harness.bundle is None:
                raise ValueError("Nothing built yet: build a page on the Data tab first.")
            out = page.write_html(harness.bundle, EXPORT_HTML)
            body = out.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{EXPORT_HTML}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def live(self, query):
            path = (query.get("path") or [""])[0]
            if not path or not Path(path).expanduser().is_file():
                raise ValueError("choose a capture file to replay")
            speed = float((query.get("speed") or ["1"])[0])
            stream = sources.ReplaySource(Path(path).expanduser(), speed).windows()
            first = next(stream, None)   # load before the headers, so a bad file is a 400
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                window = first
                while window is not None:
                    self.wfile.write(f"data: {json.dumps(window)}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    window = next(stream, None)
                self.wfile.write(b"event: end\ndata: {}\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass   # the page pressed Stop

    return Handler


def serve(harness, port=DEFAULT_PORT):
    """A server bound to 127.0.0.1 (port 0 picks a free one). Call serve_forever() on it."""
    server = ThreadingHTTPServer((HOST, port), make_handler(harness))
    server.daemon_threads = True
    return server


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="The state-machine page as a live harness.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--open", action="store_true", help="open the page in a browser")
    parser.add_argument("--no-preload", action="store_true",
                        help="start empty instead of building today's KUBEDATA page")
    parser.add_argument("--data", default=None, help="a folder to scan when the page opens")
    parser.add_argument("--manifest", default=MANIFEST_NAME)
    args = parser.parse_args(argv)

    root = None
    try:
        import local_paths
        root = getattr(local_paths, "KUBEDATA_ROOT", "") or None
    except ImportError:
        pass
    harness = Harness(root, args.manifest)
    if args.data:
        harness.initial_scan = str(Path(args.data).expanduser())
    if root and not args.no_preload:
        print(f"Building today's page from {root} (pass --no-preload to skip) ...")
        try:
            built = harness.preload()
            print(f"  {len(built['vantages'])} taps, opens on {built['selected']}")
        except Exception as error:   # the harness still opens; the Data tab says why
            harness.notes.append(f"Preload failed: {error}")
            print(f"  preload failed: {error}")
    server = serve(harness, args.port)
    url = f"http://{HOST}:{server.server_address[1]}/"
    print(f"Harness at {url}  (Ctrl-C to stop)")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

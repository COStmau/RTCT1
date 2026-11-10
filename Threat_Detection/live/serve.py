"""The live monitor's own server: one dashboard, the monitor's state, its event stream.

Separate from the demo (viz/serve.py): it shares the detector (methods/calibration.py) and
nothing else. Run it beside a local cluster, or on recordings with no cluster at all:

    .venv/bin/python live/serve.py --open                       the running local k3d cluster
    .venv/bin/python live/serve.py --open --replay attack.pcap --speed 10
    .venv/bin/python live/serve.py --replay ~/rtct-data/general/"http-flood attack" --watch

Python standard library only for the server. It binds 127.0.0.1: it can start captures and
launch the local cluster's attacks, so it is a tool for the machine it runs on.

  GET  /                   the dashboard (live/web/)
  GET  /static/<file>      its script, styles and D3
  GET  /api/state          the snapshot: inventory, taps and their machines, attacks, limits
  GET  /api/stream         text/event-stream of windows, alerts, tap changes, attacks;
                           resumes from Last-Event-ID (or ?since=) instead of replaying
  POST /api/taps/start     {taps, record} -> watch those taps (default ones when none named)
  POST /api/taps/stop      {taps} -> stop those, or all
  POST /api/learn          {taps, seconds} -> re-learn from the next N s of their own traffic
  POST /api/attack         {scenario, seconds} -> launch one of the provider's attacks
  POST /api/attack/stop

Every POST must come from this page: a request whose Origin is another site is refused, so
no web page open in the same browser can launch an attack.
"""
import argparse
import json
import mimetypes
import queue
import signal
import sys
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from live.monitor import Monitor, MonitorError
from live.taps import LocalClusterProvider, ProviderError, ReplayProvider

HOST = "127.0.0.1"
DEFAULT_PORT = 8766
WEB = Path(__file__).resolve().parent / "web"
MAX_JSON = 1024 ** 2


def same_origin(headers):
    """True unless the request carries an Origin that is not this server's own address.

    A browser sends Origin on every cross-site POST, and a page cannot forge it; a request
    without one comes from a tool such as curl, not from a web page.
    """
    origin = headers.get("Origin")
    if origin is None:
        return True
    host = headers.get("Host", "")
    return origin in (f"http://{host}", f"https://{host}")


def _pick(request, **names):
    """{argument: request[key]} for the keys present: the monitor's arguments from a body."""
    return {arg: request[key] for arg, key in names.items() if key in request}


def static_file(name):
    """A file of live/web/ by its relative name, or None for anything outside it."""
    path = (WEB / name).resolve()
    return path if path.is_file() and WEB in path.parents else None


def make_handler(monitor, quiet=False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "rtct-live/1"

        def log_message(self, fmt, *args):
            if not quiet and not self.path.startswith(("/static/", "/api/state")):
                sys.stderr.write(f"  {self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}\n")

        def send_bytes(self, body, content_type, status=200):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, payload, status=200):
            self.send_bytes(json.dumps(payload, default=str).encode("utf-8"),
                            "application/json; charset=utf-8", status)

        def read_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_JSON:
                raise ValueError("request too large")
            return json.loads((self.rfile.read(length) if length else b"{}").decode("utf-8") or "{}")

        def guarded(self, action):
            try:
                action()
            except (MonitorError, ProviderError, ValueError) as error:
                self.send_json({"error": str(error)}, 400)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as error:   # report, keep serving
                traceback.print_exc()
                self.send_json({"error": f"{type(error).__name__}: {error}"}, 500)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                return self.send_bytes((WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
            if url.path.startswith("/static/"):
                path = static_file(url.path[len("/static/"):])
                if path is None:
                    return self.send_json({"error": "not found"}, 404)
                kind = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
                return self.send_bytes(path.read_bytes(), f"{kind}; charset=utf-8")
            if url.path == "/api/state":
                fresh = "fresh" in parse_qs(url.query)
                return self.guarded(lambda: self.send_json(monitor.state(fresh)))
            if url.path == "/api/stream":
                return self.guarded(lambda: self.stream(parse_qs(url.query)))
            self.send_json({"error": "not found"}, 404)

        def do_POST(self):
            routes = {
                "/api/taps/start": lambda r: monitor.start(**_pick(r, labels="taps", record="record")),
                "/api/taps/stop": lambda r: monitor.stop(**_pick(r, labels="taps")),
                "/api/learn": lambda r: monitor.learn(**_pick(r, labels="taps", seconds="seconds")),
                "/api/attack": lambda r: monitor.launch(**_pick(r, scenario="scenario", seconds="seconds")),
                "/api/attack/stop": lambda r: monitor.stop_attack(),
            }
            route = routes.get(urlparse(self.path).path)
            if route is None:
                return self.send_json({"error": "not found"}, 404)
            if not same_origin(self.headers):
                return self.send_json({"error": "refused: this request did not come from the monitor page"}, 403)
            self.guarded(lambda: self.send_json(route(self.read_json())))

        def stream(self, query):
            # "<boot>-<seq>": a sequence number only means something to the process that gave it
            last = self.headers.get("Last-Event-ID") or (query.get("since") or [""])[0]
            boot, _, seq = last.rpartition("-")
            since = int(seq) if boot == monitor.boot and seq.isdigit() else None
            events, past = monitor.subscribe(since)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

            def send(event):
                self.wfile.write(f"id: {monitor.boot}-{event['seq']}\ndata: {json.dumps(event)}\n\n".encode("utf-8"))

            try:
                hello = {"kind": "hello", "boot": monitor.boot, "resumed": since is not None}
                self.wfile.write(f"data: {json.dumps(hello)}\n\n".encode("utf-8"))
                for event in past:
                    send(event)
                self.wfile.flush()
                while True:
                    try:
                        send(events.get(timeout=15))
                        while True:              # drain what is waiting before one flush
                            send(events.get_nowait())
                    except queue.Empty:
                        pass
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass   # the page closed or reloaded
            finally:
                monitor.unsubscribe(events)

    return Handler


def serve(monitor, port=DEFAULT_PORT, host=HOST, quiet=False):
    """A server bound to `host` (port 0 picks a free one). Call serve_forever() on it."""
    server = ThreadingHTTPServer((host, port), make_handler(monitor, quiet))
    server.daemon_threads = True
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description="The live monitor and its dashboard.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--host", default=HOST, help="address to bind (default 127.0.0.1)")
    parser.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    parser.add_argument("--replay", nargs="+", metavar="PATH",
                        help="play these pcap files or folders back as taps instead of watching a cluster")
    parser.add_argument("--speed", type=float, default=1.0, help="replay speed (default 1: real time)")
    parser.add_argument("--watch", action="store_true", help="start watching the default taps at once")
    parser.add_argument("--out", default=None, help="where sessions and machines are kept (default ~/rtct-data)")
    args = parser.parse_args(argv)

    try:
        provider = (ReplayProvider(args.replay, args.speed, args.out) if args.replay
                    else LocalClusterProvider(args.out))
    except ProviderError as error:
        sys.exit(str(error))
    monitor = Monitor(provider)
    server = serve(monitor, args.port, args.host)
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '') else args.host}:{server.server_address[1]}/"
    print(f"Live monitor at {url}  ({provider.name}; Ctrl-C to stop)", flush=True)
    if args.watch:
        try:
            monitor.start()
        except (MonitorError, ProviderError) as error:
            print(f"  not watching yet: {error}", flush=True)
    if args.open:
        webbrowser.open(url)

    def terminated(signum, frame):   # a stop from a process manager cleans up like Ctrl-C
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminated)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        monitor.shutdown()   # captures and attack Jobs must not outlive the server
        server.server_close()


if __name__ == "__main__":
    main()

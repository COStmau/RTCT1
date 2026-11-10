"""Every talker in the local clusters, benign and attack, as one stdlib script.

Mounted from a ConfigMap into python:3.12-alpine and started as

    python /app/traffic.py <mode> key=value ...

Benign modes (the lab look-alike): controller, lidar, camera, hardware.
Benign modes (the general app):     web, api, store, worker, loadgen.
Attack modes:                       flood-http, flood-udp, flood-tcp, lateral.

The rates are set so a 60 s recording carries a steady, repetitive pattern per tap, which
is what the state machine learns. Addresses are Service names, so every request also does
the cluster DNS lookups a real workload does. Nothing here is meant to be efficient.
"""
import http.client
import http.server
import json
import os
import random
import socket
import socketserver
import sys
import threading
import time


def log(*parts):
    print(time.strftime("%H:%M:%S"), *parts, flush=True)


def forever(every, action, jitter=0.1):
    """Call action() every `every` seconds (with a little jitter) and keep going on errors."""
    while True:
        try:
            action()
        except Exception as error:   # a peer restarting is normal; say so and continue
            log("error:", type(error).__name__, error)
        time.sleep(max(0.0, every * random.uniform(1 - jitter, 1 + jitter)))


def http_call(host, port, method="GET", path="/", body=None, timeout=3):
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
    try:
        conn.request(method, path, body=body,
                     headers={"Content-Type": "application/octet-stream"} if body else {})
        response = conn.getresponse()
        data = response.read()
        return response.status, data
    finally:
        conn.close()


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status=200, body=b"ok", kind="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))


def serve_http(port, handler):
    server = http.server.ThreadingHTTPServer(("0.0.0.0", int(port)), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ---------------------------------------------------------------- the lab look-alike

def controller(http_port=8080, udp_port=7400, nginx="nginx", poll=1.0):
    """robot-controller: takes lidar datagrams and camera frames, serves state, polls nginx."""
    state = {"points": 0, "frames": 0}

    class Handler(Quiet):
        def do_POST(self):
            self.body()
            state["frames"] += 1
            self.reply()

        def do_GET(self):
            self.reply(body=json.dumps(state).encode(), kind="application/json")

    serve_http(http_port, Handler)

    def udp():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", int(udp_port)))
        while True:
            data, _ = sock.recvfrom(65535)
            state["points"] += len(data)

    threading.Thread(target=udp, daemon=True).start()
    log(f"controller on :{http_port}/tcp and :{udp_port}/udp, polling {nginx}")
    forever(float(poll), lambda: http_call(nginx, 80))


def lidar(target="robot-controller", port=7400, every=0.1, burst=3, size=1200):
    """lidar: a point-cloud scan as a burst of UDP datagrams, ten times a second."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = os.urandom(int(size))

    def scan():
        address = socket.gethostbyname(target)
        for _ in range(int(burst)):
            sock.sendto(payload, (address, int(port)))

    log(f"lidar -> {target}:{port}")
    forever(float(every), scan)


def camera(target="robot-controller", port=8080, every=0.5, size=20000):
    """camera: one compressed frame uploaded over HTTP twice a second."""
    frame = os.urandom(int(size))
    log(f"camera -> {target}:{port}")
    forever(float(every), lambda: http_call(target, port, "POST", "/frame", frame))


def hardware(target="robot-controller", port=8080, every=0.2):
    """robot-hardware: polls the controller for its commanded state five times a second."""
    log(f"hardware -> {target}:{port}")
    forever(float(every), lambda: http_call(target, port, "GET", "/state"))


# ---------------------------------------------------------------- the general app

def resp(sock_file, *parts):
    """One Redis command over RESP; returns the decoded reply (bulk, int, or None)."""
    command = f"*{len(parts)}\r\n" + "".join(f"${len(str(p))}\r\n{p}\r\n" for p in parts)
    sock_file.write(command.encode())
    sock_file.flush()
    line = sock_file.readline().decode().rstrip("\r\n")
    if line.startswith("$"):
        length = int(line[1:])
        if length < 0:
            return None
        data = sock_file.read(length + 2)
        return data[:-2].decode(errors="replace")
    if line.startswith(":"):
        return int(line[1:])
    return line[1:]


def redis_connection(host, port):
    sock = socket.create_connection((host, int(port)), timeout=5)
    return sock.makefile("rwb")


def web(port=8080, api="api", api_port=8080):
    """frontend: renders pages from the api and forwards orders to it."""

    class Handler(Quiet):
        def do_GET(self):
            status, data = http_call(api, api_port, "GET", "/items")
            self.reply(200, b"<html><body>" + data[:2000] + b"</body></html>", "text/html")

        def do_POST(self):
            http_call(api, api_port, "POST", "/order", self.body())
            self.reply(201)

    log(f"web on :{port} -> {api}:{api_port}")
    serve_http(port, Handler)
    threading.Event().wait()


def api(port=8080, redis="redis", redis_port=6379, store="store", store_port=5432):
    """api: items from a Redis cache with a store fallback; orders onto a Redis list."""
    lock = threading.Lock()
    conn = {"r": None}

    def call(*parts):
        with lock:
            if conn["r"] is None:
                conn["r"] = redis_connection(redis, redis_port)
            try:
                return resp(conn["r"], *parts)
            except Exception:
                conn["r"] = None
                raise

    class Handler(Quiet):
        def do_GET(self):
            items = call("GET", "items")
            if items is None or random.random() < 0.2:
                items = store_call(store, store_port, "GET items") or "[]"
                call("SET", "items", items)
            self.reply(200, items.encode(), "application/json")

        def do_POST(self):
            call("LPUSH", "orders", self.body().decode(errors="replace") or "{}")
            self.reply(201)

    log(f"api on :{port} -> redis {redis}:{redis_port}, store {store}:{store_port}")
    serve_http(port, Handler)
    threading.Event().wait()


def store_call(host, port, line):
    with socket.create_connection((host, int(port)), timeout=5) as sock:
        sock.sendall(line.encode() + b"\n")
        return sock.makefile("rb").readline().decode().strip()


def store(port=5432):
    """store: a line-protocol key-value server standing in for the database."""
    data = {"items": json.dumps([{"id": i, "name": f"item-{i}"} for i in range(40)])}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            for raw in self.rfile:
                words = raw.decode(errors="replace").strip().split(" ", 2)
                if words[0] == "GET" and len(words) > 1:
                    self.wfile.write((data.get(words[1], "") + "\n").encode())
                elif words[0] == "PUT" and len(words) > 2:
                    data[words[1]] = words[2]
                    self.wfile.write(b"OK\n")
                else:
                    self.wfile.write(b"ERR\n")

    server = socketserver.ThreadingTCPServer(("0.0.0.0", int(port)), Handler)
    server.daemon_threads = True
    log(f"store on :{port}")
    server.serve_forever()


def worker(redis="redis", redis_port=6379, store="store", store_port=5432, every=0.5):
    """worker: takes orders off the Redis list and records each one in the store."""
    conn = {"r": None}

    def step():
        if conn["r"] is None:
            conn["r"] = redis_connection(redis, redis_port)
        try:
            order = resp(conn["r"], "RPOP", "orders")
        except Exception:
            conn["r"] = None
            raise
        if order:
            store_call(store, store_port, f"PUT order-{time.time():.3f} {order}")

    log(f"worker <- redis {redis}:{redis_port} -> store {store}:{store_port}")
    forever(float(every), step)


def loadgen(target="frontend", port=80, browse=0.3, order_every=2.0):
    """loadgen: shoppers browsing the frontend, with an order every couple of seconds."""
    last = {"order": 0.0}

    def visit():
        http_call(target, port, "GET", "/")
        if time.time() - last["order"] > float(order_every):
            last["order"] = time.time()
            http_call(target, port, "POST", "/order",
                      json.dumps({"item": random.randrange(40), "qty": 1}).encode())

    log(f"loadgen -> {target}:{port}")
    forever(float(browse), visit)


# ---------------------------------------------------------------- attacks

def until(seconds):
    return time.time() + float(seconds)


def flood_http(url_host="nginx", port=80, path="/", threads=16, seconds=40):
    """Many concurrent clients requesting as fast as they can."""
    end, count = until(seconds), [0]

    def client():
        while time.time() < end:
            try:
                http_call(url_host, port, "GET", path, timeout=2)
                count[0] += 1
            except Exception:
                time.sleep(0.01)

    log(f"flood-http {url_host}:{port}{path} x{threads} for {seconds}s")
    workers = [threading.Thread(target=client, daemon=True) for _ in range(int(threads))]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    log(f"sent {count[0]} requests")


def flood_udp(host="robot-controller", port=7400, rate=600, size=1200, seconds=40):
    """Datagrams at `rate` per second into a stream port: far beyond its normal rate."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    address, payload, end, sent = socket.gethostbyname(host), os.urandom(int(size)), until(seconds), 0
    log(f"flood-udp {host}({address}):{port} at {rate}/s for {seconds}s")
    gap = 1.0 / float(rate)
    while time.time() < end:
        sock.sendto(payload, (address, int(port)))
        sent += 1
        time.sleep(gap)
    log(f"sent {sent} datagrams")


def flood_tcp(host="redis", port=6379, threads=16, size=4096, seconds=40):
    """Connections opened over and over, each writing junk into a service port."""
    end, junk = until(seconds), os.urandom(int(size))

    def client():
        while time.time() < end:
            try:
                with socket.create_connection((host, int(port)), timeout=2) as sock:
                    sock.sendall(junk)
            except Exception:
                time.sleep(0.01)

    log(f"flood-tcp {host}:{port} x{threads} for {seconds}s")
    workers = [threading.Thread(target=client, daemon=True) for _ in range(int(threads))]
    for w in workers:
        w.start()
    for w in workers:
        w.join()


def lateral(targets="", every=0.5, seconds=40):
    """From inside a compromised workload: connections to peers and ports it never uses."""
    pairs = [t.rsplit(":", 1) for t in targets.split(",") if t]
    end = until(seconds)
    log(f"lateral to {', '.join(':'.join(p) for p in pairs)} for {seconds}s")
    while time.time() < end:
        for host, port in pairs:
            try:
                with socket.create_connection((host, int(port)), timeout=1) as sock:
                    sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    sock.recv(512)
            except Exception:
                pass
        time.sleep(float(every))


MODES = {"controller": controller, "lidar": lidar, "camera": camera, "hardware": hardware,
         "web": web, "api": api, "store": store, "worker": worker, "loadgen": loadgen,
         "flood-http": flood_http, "flood-udp": flood_udp, "flood-tcp": flood_tcp,
         "lateral": lateral}


def main(argv):
    if not argv or argv[0] not in MODES:
        raise SystemExit(f"usage: traffic.py <{'|'.join(MODES)}> key=value ...")
    options = dict(arg.split("=", 1) for arg in argv[1:])
    MODES[argv[0]](**options)


if __name__ == "__main__":
    main(sys.argv[1:])

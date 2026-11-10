"""One command to try the detector on any machine: sets itself up, then opens the harness.

    macOS / Linux:  python3 run.py
    Windows:        py -3.11 run.py

The first run makes a virtualenv in .venv beside this file and installs requirements.txt
into it (a few minutes, once). Every run after that starts at once. Then the harness
(viz/serve.py) opens in your browser on the baked KUBEDATA page; its Data tab loads your
own captures. Anything after run.py goes to viz/serve.py:

    python3 run.py --data ~/captures     # scan a folder when the page opens
    python3 run.py --port 9000
    python3 run.py --no-open              # don't open a browser

Standard library only, so it runs on a bare Python 3.11 or newer.
"""
import hashlib
import os
import subprocess
import sys
import venv
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV = HERE / ".venv"
REQUIREMENTS = HERE / "requirements.txt"
STAMP = VENV / ".requirements.sha256"
MINIMUM = (3, 11)


def venv_python():
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def ensure_environment():
    """The venv's interpreter, with requirements.txt installed in it."""
    python = venv_python()
    if not python.exists():
        print(f"Setting up {VENV.name} (once) ...", flush=True)
        venv.EnvBuilder(with_pip=True).create(VENV)
    wanted = hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()
    if not STAMP.exists() or STAMP.read_text(encoding="utf-8").strip() != wanted:
        print("Installing numpy, pandas, matplotlib, scikit-learn (a few minutes, once) ...", flush=True)
        subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
                        "-q", "-r", str(REQUIREMENTS)], check=True)
        STAMP.write_text(wanted, encoding="utf-8")
    return python


def main(argv):
    if sys.version_info < MINIMUM:
        found = ".".join(map(str, sys.version_info[:3]))
        sys.exit(f"Python {MINIMUM[0]}.{MINIMUM[1]} or newer is needed (this is {found}).\n"
                 "Install it from https://www.python.org/downloads/ and run this again, "
                 "e.g. `py -3.11 run.py` on Windows or `python3.11 run.py` on macOS.")
    args = list(argv)
    if "--no-open" in args:
        args.remove("--no-open")
    elif "--open" not in args:
        args.append("--open")
    try:
        python = ensure_environment()
    except subprocess.CalledProcessError:
        sys.exit("Installing the requirements failed (see above). Delete the .venv folder "
                 "and run this again; check your internet connection.")
    env = dict(os.environ, PYTHONUTF8="1", PYTHONUNBUFFERED="1")
    try:
        return subprocess.call([str(python), str(HERE / "viz" / "serve.py"), *args],
                               cwd=str(HERE), env=env)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

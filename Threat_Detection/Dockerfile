# The detection harness with nothing installed but Docker.
#
#   docker build -t rtct-detect .
#   docker run --rm -p 127.0.0.1:8765:8765 rtct-detect
#   then open http://127.0.0.1:8765/
#
# Your own captures: mount a folder and scan it when the page opens.
#   docker run --rm -p 127.0.0.1:8765:8765 -v "$PWD/captures:/data" rtct-detect \
#       python viz/serve.py --host 0.0.0.0 --data /data
#
# The server binds 0.0.0.0 inside the container only; "-p 127.0.0.1:..." keeps it off your network.
FROM python:3.11-slim

ENV PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8765
CMD ["python", "viz/serve.py", "--host", "0.0.0.0"]

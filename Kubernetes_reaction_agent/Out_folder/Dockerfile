FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir kubernetes

CMD ["python", "api_calls_test_bed.py"]
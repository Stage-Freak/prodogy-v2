FROM python:3.12.4-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000

RUN adduser --disabled-password --gecos "" appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

HEALTHCHECK --interval=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

USER appuser
CMD ["python", "app.py"]

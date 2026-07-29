FROM python:3.12.4-slim

RUN adduser --disabled-password --gecos "" prodogy

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[dev,llm,web]"

USER prodogy
ENTRYPOINT ["prodogy"]
CMD ["--help"]

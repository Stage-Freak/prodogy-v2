# A deliberately problematic Dockerfile for testing Prodogy.
FROM python:latest

ENV DB_PASSWORD=SuperSecret123Value!

ADD https://example.com/app.tar.gz /app/

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

CMD ["python", "app.py"]

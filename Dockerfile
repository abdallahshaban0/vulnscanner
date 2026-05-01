FROM python:3.12-slim

LABEL maintainer="abdallahshaban0"
LABEL description="Automated Vulnerability Scanner — Ethical Hacking Tool"
LABEL version="1.0.0"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/reports

VOLUME ["/app/reports"]

ENTRYPOINT ["python", "scanner.py"]
CMD ["--help"]

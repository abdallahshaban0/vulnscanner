# ============================================================
#  VulnScanner — Dockerfile
#  Build:  docker build -t vulnscanner .
#  Run:    docker run --rm vulnscanner -t example.com --full
# ============================================================

FROM python:3.11-slim

LABEL maintainer="abdallahshaban0"
LABEL description="Automated Vulnerability Scanner — Ethical Hacking Tool"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies (for dnspython, whois)
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Make scripts executable
RUN chmod +x scanner.py vulnscanner.sh

# Create reports output directory
RUN mkdir -p /app/reports

# Mount point for extracting reports
VOLUME ["/app/reports"]

# Default entrypoint
ENTRYPOINT ["python", "scanner.py"]

# Default help if no args given
CMD ["--help"]

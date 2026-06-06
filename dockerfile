FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy || true

# Create non-root user for security (but honeypot needs iptables)
RUN groupadd -r honeypot && useradd -r -g honeypot -s /bin/false honeypot

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application
COPY simplepot.py .
COPY requirements.txt .

# Make sure Python user binaries are in PATH
ENV PATH=/root/.local/bin:$PATH

# Create data directory with proper permissions
RUN mkdir -p /tmp/honeypot_data/{sessions,payloads,reports,captures,keys,certs} && \
    chown -R honeypot:honeypot /tmp/honeypot_data && \
    chmod 750 /tmp/honeypot_data/keys /tmp/honeypot_data/certs

# Expose all honeypot ports
EXPOSE 2222 8080 8443 2121 3306 2525 2323 6379 27017 3389 5900 502 5353 1610 9090 7777 9091

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7777/api/health')" || exit 1

# Run as non-root (but note: iptables banning may require root)
# For iptables support, run container with --cap-add=NET_ADMIN
USER honeypot

CMD ["python", "-u", "simplepot.py"]

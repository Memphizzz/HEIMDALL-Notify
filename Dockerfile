# Get Gotify binary from official image
FROM gotify/server:latest AS gotify

FROM python:3.12-slim

# Install supervisord and libsodium (for PyNaCl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor libsodium23 \
    && rm -rf /var/lib/apt/lists/*

# Copy Gotify binary from official image
COPY --from=gotify /app/gotify-app /usr/local/bin/gotify

# Install Python dependencies for Threema bridge
RUN pip install --no-cache-dir requests websocket-client pynacl

# Copy bridge script
COPY threema-bridge.py /app/threema-bridge.py

# Copy supervisord config
COPY supervisord.conf /etc/supervisord.conf

# Create data directory for Gotify
RUN mkdir -p /app/data

WORKDIR /app

EXPOSE 8080

CMD ["supervisord", "-c", "/etc/supervisord.conf"]

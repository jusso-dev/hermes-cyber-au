# Read-only dashboard for a cyber-au profile. Build from the repository root:
#   docker build -f dashboard/Dockerfile -t cyberau-dashboard .
# Mount the Hermes data volume read-only and publish the port on a LAN or Tailscale
# address only, for example: -p 192.168.1.10:8765:8765
#
# The server answers only requests whose Host header names an allowed host. Inside
# the container it binds 0.0.0.0, so list every name or address the browser uses,
# comma separated, or the page answers 421 (Misdirected Request):
#   -e CYBERAU_DASHBOARD_ALLOWED_HOSTS=192.168.1.10,dashboard.example.com
# localhost, 127.0.0.1 and ::1 are always allowed.
FROM python:3.15-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CYBERAU_DASHBOARD_ALLOWED_HOSTS=""

WORKDIR /app
COPY dashboard/server.py dashboard/conversations.py dashboard/sources.py /app/
# The Sources page falls back to this copy when the profile has no feeds/catalogue.yaml.
COPY feeds/catalogue.yaml /app/feeds/catalogue.yaml

# The Hermes home is mode 0700 and owned by uid 10000. Run as that uid so a
# read-only mount can be read. This user is not root.
USER 10000:10000

EXPOSE 8765
CMD ["python", "/app/server.py", "--profile", "/opt/data/profiles/cyber-au", "--bind", "0.0.0.0", "--port", "8765"]

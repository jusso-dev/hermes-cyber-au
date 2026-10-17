# Read-only dashboard for a cyber-au profile. Build from the repository root:
#   docker build -f dashboard/Dockerfile -t cyberau-dashboard .
# Mount the Hermes data volume read-only and publish the port on a LAN or Tailscale
# address only, for example: -p 192.168.1.10:8765:8765
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY dashboard/server.py dashboard/conversations.py /app/

# The Hermes home is mode 0700 and owned by uid 10000. Run as that uid so a
# read-only mount can be read. This user is not root.
USER 10000:10000

EXPOSE 8765
CMD ["python", "/app/server.py", "--profile", "/opt/data/profiles/cyber-au", "--bind", "0.0.0.0", "--port", "8765"]

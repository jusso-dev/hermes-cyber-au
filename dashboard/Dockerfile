# Read-only dashboard for a cyber-au profile. Build from the repository root:
#   docker build -f dashboard/Dockerfile -t cyberau-dashboard .
# Mount the Hermes data volume read-only and publish the port on a LAN or Tailscale
# address only, for example: -p 192.168.1.10:8765:8765
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY dashboard/server.py /app/server.py

RUN useradd --system --no-create-home --uid 10001 dashboard
USER dashboard

EXPOSE 8765
CMD ["python", "/app/server.py", "--profile", "/opt/data/profiles/cyber-au", "--bind", "0.0.0.0", "--port", "8765"]

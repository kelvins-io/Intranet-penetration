#!/usr/bin/env bash
# One-shot private deployment helper (Docker Compose).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/deploy"

mkdir -p "$DEPLOY/data/server" "$DEPLOY/data/agent"

echo "==> Building and starting core services (server + redis)"
docker compose -f "$DEPLOY/docker-compose.yml" up -d --build redis server

echo "==> Waiting for healthz..."
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:8088/healthz" >/dev/null 2>&1; then
    echo "Server is up."
    break
  fi
  sleep 1
done

cat <<EOF

Private suite is running.

  Dashboard:  http://127.0.0.1:8088/dashboard/
  Default:    admin@localhost / admin123
  Agent mux:  :7700 (TCP+QUIC)
  HTTPS:      :8443

Optional demo agent:
  docker compose -f deploy/docker-compose.yml --profile with-agent up -d agent

Helm (Kubernetes):
  helm upgrade --install ip deploy/helm/intranet-penetration

EOF

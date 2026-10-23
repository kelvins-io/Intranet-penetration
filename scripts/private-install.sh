#!/usr/bin/env bash
# One-shot private deployment helper (Docker Compose: redis + control + edge).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/deploy"

mkdir -p "$DEPLOY/data/control" "$DEPLOY/data/edge" "$DEPLOY/data/agent"

echo "==> Building and starting Control + Edge + Redis"
docker compose -f "$DEPLOY/docker-compose.yml" up -d --build redis control edge

echo "==> Waiting for control healthz..."
for i in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:8090/healthz" >/dev/null 2>&1; then
    echo "Control is up."
    break
  fi
  sleep 1
done

echo "==> Waiting for edge healthz..."
for i in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:8088/healthz" >/dev/null 2>&1; then
    echo "Edge is up."
    break
  fi
  sleep 1
done

cat <<EOF

Private suite is running (split Control / Edge).

  Dashboard:  http://127.0.0.1:8090/dashboard/
  Control API: :8090
  Edge gateway: http://127.0.0.1:8088/
  Agent mux:  :7700 (TCP+QUIC)
  HTTPS:      :8443
  Default:    admin@localhost / admin123

Optional demo agent:
  docker compose -f deploy/docker-compose.yml --profile with-agent up -d agent

Helm (Kubernetes):
  helm upgrade --install ip deploy/helm/intranet-penetration

EOF

#!/usr/bin/env bash
set -e

PID_FILE="./.pids"
COMPOSE_FILE="./deploy/dev.yaml"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found. Nothing to stop."
  exit 0
fi

if grep -q "compose" "$PID_FILE"; then
  echo "🛑 Stopping Docker Compose services..."
  docker compose -f "$COMPOSE_FILE" down || true
else
  echo "🛑 Stopping local dev processes..."
  while read -r pid; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" && echo "Stopped PID $pid"
    fi
  done < "$PID_FILE"
fi

rm -f "$PID_FILE"
echo "✅ All dev processes stopped."

#!/usr/bin/env bash
set -e

# --- Configuration ---
ENTRYPOINT_DIR="src/WebAPI"
COMPOSE_FILE="./deploy/dev.yaml"
LOG_DIR="./logs"
PID_FILE="./.pids"

# --- Parse args ---
USE_COMPOSE=false
if [[ "$1" == "--with-compose" ]]; then
  USE_COMPOSE=true
fi

mkdir -p "$LOG_DIR"
rm -f "$PID_FILE"  # clear any old PIDs

# --- Run with Docker Compose ---
if $USE_COMPOSE; then
  echo "🚀 Starting app using Docker Compose..."
  docker compose -f "$COMPOSE_FILE" up -d
  echo "compose" > "$PID_FILE"  # mark compose mode
  echo "✅ Docker Compose services started."
  exit 0
fi

# --- Run locally ---
echo "🚀 Starting local development servers..."

# Start WebAPI
(
  cd "$ENTRYPOINT_DIR"
  echo "Starting WebAPI..."
  nohup dotnet run > "../../${LOG_DIR}/WebAPI.log" 2>&1 &
  echo $! >> "../../${PID_FILE}"
  echo "  → PID $!"
)

echo "✅ All processes started in background."
echo "📜 Logs: ${LOG_DIR}/WebAPI.log"

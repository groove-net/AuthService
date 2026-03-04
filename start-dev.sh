#!/usr/bin/env bash
set -e

# --- Configuration ---
AUTH_DIR="src/Auth/WebAPI.REST"
# define more component apis here...
COMPOSE_FILE="./deploy/dev.yaml"
LOG_DIR="./logs"
PID_FILE="./.pids"

# --- Idempotency Check ---
if [ -f "$PID_FILE" ]; then
  echo "❌ Error: PID file ($PID_FILE) already exists."
  echo "The application is likely already running."
  echo "Please stop the current processes before starting new ones."
  exit 1
fi

# --- Parse args ---
USE_COMPOSE=false
if [[ "$1" == "--with-compose" ]]; then
  USE_COMPOSE=true
fi

mkdir -p "$LOG_DIR"

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
  cd "${AUTH_DIR}"
  echo "Starting AuthAPI..."
  nohup dotnet run > "../../../${LOG_DIR}/auth.log" 2>&1 &
  echo $! >> "../../../${PID_FILE}"
  echo "  → PID $!"
)

echo "✅ All processes started in background."
echo "📜 View Logs: ${LOG_DIR}"

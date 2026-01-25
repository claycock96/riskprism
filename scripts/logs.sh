#!/bin/bash
# scripts/logs.sh
# View logs from all services

set -e

# Ensure we are running from the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

if [ -z "$1" ]; then
    echo "📋 Viewing logs from all services (Ctrl+C to exit)..."
    docker compose logs -f
else
    echo "📋 Viewing logs from $1 (Ctrl+C to exit)..."
    docker compose logs -f "$1"
fi

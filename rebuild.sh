#!/bin/bash

# Rebuild and restart services
# Usage: ./rebuild.sh [service_name]
# Example: ./rebuild.sh backend

set -e

if [ -z "$1" ]; then
    echo "🔨 Rebuilding all services..."
    docker compose down
    docker compose build --no-cache
    docker compose up -d
    echo "✅ All services rebuilt and restarted"
else
    echo "🔨 Rebuilding $1..."
    docker compose stop "$1"
    docker compose build --no-cache "$1"
    docker compose up -d "$1"
    echo "✅ $1 rebuilt and restarted"
fi

echo ""
echo "Run './logs.sh' to view logs"

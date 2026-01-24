#!/bin/bash

# Open a shell in a running container
# Usage: ./shell.sh [service_name]
# Example: ./shell.sh backend

SERVICE=${1:-backend}

echo "🐚 Opening shell in $SERVICE container..."
docker compose exec "$SERVICE" /bin/bash

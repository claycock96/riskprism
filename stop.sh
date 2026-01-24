#!/bin/bash

# Stop all services
# Usage: ./stop.sh

set -e

echo "🛑 Stopping Terraform Plan Analyzer..."
docker compose down

echo "✅ Services stopped"

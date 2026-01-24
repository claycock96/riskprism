#!/bin/bash

# Start all services with Docker Compose
# Usage: ./start.sh

set -e

echo "🚀 Starting Terraform Plan Analyzer..."
echo ""

# Build and start services
docker compose up -d --build

echo ""
echo "✅ Services started!"
echo ""
echo "   📡 Backend API:  http://localhost:8000"
echo "   📚 API Docs:     http://localhost:8000/docs"
echo "   ❤️  Health Check: http://localhost:8000/health"
echo ""
echo "📋 Next steps:"
echo "   • View logs:     ./logs.sh"
echo "   • Test API:      ./test_api.sh"
echo "   • Stop services: ./stop.sh"
echo ""

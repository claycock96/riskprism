#!/bin/bash
set -e

# Default behavior: Run ALL tests
RUN_UNIT=true
RUN_API=true

# Parse arguments
if [[ "$1" == "--unit" ]]; then
    RUN_API=false
elif [[ "$1" == "--api" ]]; then
    RUN_UNIT=false
fi

echo "🧪 Terraform Plan Analyzer Test Runner"
echo "===================================="

# Check container
if ! docker ps | grep -q terraform-webapp-backend-1; then
    echo "❌ Error: Backend container is not running."
    echo "👉 Run './start.sh' first."
    exit 1
fi

# Load Auth Code for API Tests
if [ -f .env ]; then
    AUTH_CODE=$(grep INTERNAL_ACCESS_CODE .env | cut -d '=' -f 2)
else
    echo "⚠️  No .env file found. API tests might fail if auth is enabled."
fi

# ---------------------------------------------------------
# 1. Unit Tests (Pytest)
# ---------------------------------------------------------
if [ "$RUN_UNIT" = true ]; then
    echo ""
    echo "🐳 [1/2] Running Unit Tests (Pytest inside container)..."
    docker exec -t terraform-webapp-backend-1 sh -c "export PYTHONPATH=/app && pytest tests/"
fi

# ---------------------------------------------------------
# 2. Integration Tests (Curl API)
# ---------------------------------------------------------
if [ "$RUN_API" = true ]; then
    echo ""
    echo "🌐 [2/2] Running API Integration Tests (Curl)..."
    
    API_URL="http://localhost:8000"
    SAMPLE_PLAN="tests/fixtures/sample_plan.json"

    # Health Check
    echo "   • Checking /health..."
    curl -sf "${API_URL}/health" > /dev/null || { echo "     ❌ API unresponsive"; exit 1; }
    echo "     ✅ API is up"

    # Deep Analysis Test
    echo "   • Testing /analyze with auth..."
    
    if [ ! -f "${SAMPLE_PLAN}" ]; then
        echo "     ❌ Sample plan missing: ${SAMPLE_PLAN}"; exit 1;
    fi

    # Prep payload
    REQUEST_PAYLOAD=$(jq -n --slurpfile plan "${SAMPLE_PLAN}" '{plan_json: $plan[0]}')

    # Send request with Auth Header
    HTTP_CODE=$(curl -s -o test_response.json -w "%{http_code}" -X POST "${API_URL}/analyze" \
        -H "Content-Type: application/json" \
        -H "X-Internal-Code: ${AUTH_CODE}" \
        -d "${REQUEST_PAYLOAD}")

    if [ "$HTTP_CODE" -eq 200 ]; then
        RISK_COUNT=$(jq '.risk_findings | length' test_response.json)
        echo "     ✅ Success! HTTP 200. Found ${RISK_COUNT} risks."
    else
        echo "     ❌ Failed with HTTP ${HTTP_CODE}"
        cat test_response.json
        exit 1
    fi
fi

echo ""
echo "✅ All requested tests passed!"

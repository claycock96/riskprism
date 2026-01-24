#!/bin/bash

# Test script for Terraform Plan Analyzer API
# Usage: ./test_api.sh

set -e

API_URL="http://localhost:8000"
SAMPLE_PLAN="tests/fixtures/sample_plan.json"

echo "🧪 Testing Terraform Plan Analyzer API"
echo "========================================"
echo ""

# Check if API is running
echo "1. Checking if API is running..."
if curl -sf "${API_URL}/health" > /dev/null; then
    echo "   ✅ API is healthy"
else
    echo "   ❌ API is not responding. Make sure Docker containers are running:"
    echo "      docker compose up -d"
    exit 1
fi
echo ""

# Test health endpoint
echo "2. Testing /health endpoint..."
HEALTH_RESPONSE=$(curl -s "${API_URL}/health")

# Parse health status
OVERALL_STATUS=$(echo "${HEALTH_RESPONSE}" | jq -r '.status')
PARSER_STATUS=$(echo "${HEALTH_RESPONSE}" | jq -r '.components.parser.status')
RISK_ENGINE_STATUS=$(echo "${HEALTH_RESPONSE}" | jq -r '.components.risk_engine.status')
LLM_STATUS=$(echo "${HEALTH_RESPONSE}" | jq -r '.components.llm.status')
LLM_PROVIDER=$(echo "${HEALTH_RESPONSE}" | jq -r '.components.llm.provider // "unknown"')
LLM_MODE=$(echo "${HEALTH_RESPONSE}" | jq -r '.components.llm.mode // "unknown"')

echo "   Overall Status: ${OVERALL_STATUS}"
echo "   Parser: ${PARSER_STATUS} - $(echo "${HEALTH_RESPONSE}" | jq -r '.components.parser.message')"
echo "   Risk Engine: ${RISK_ENGINE_STATUS} - $(echo "${HEALTH_RESPONSE}" | jq -r '.components.risk_engine.message')"
echo "   LLM: ${LLM_STATUS} (${LLM_PROVIDER}/${LLM_MODE}) - $(echo "${HEALTH_RESPONSE}" | jq -r '.components.llm.message')"

# Check if any component is unhealthy
if [ "${OVERALL_STATUS}" = "unhealthy" ] || \
   [ "${PARSER_STATUS}" = "unhealthy" ] || \
   [ "${RISK_ENGINE_STATUS}" = "unhealthy" ]; then
    echo "   ❌ Health check failed - one or more components unhealthy"
    exit 1
fi

if [ "${OVERALL_STATUS}" = "degraded" ]; then
    echo "   ⚠️  Health check passed with warnings (degraded mode)"
else
    echo "   ✅ Health check passed"
fi
echo ""

# Test analyze endpoint
echo "3. Testing /analyze endpoint with sample plan..."
if [ ! -f "${SAMPLE_PLAN}" ]; then
    echo "   ❌ Sample plan file not found: ${SAMPLE_PLAN}"
    exit 1
fi

# Wrap the plan JSON in the expected request format
REQUEST_PAYLOAD=$(jq -n --slurpfile plan "${SAMPLE_PLAN}" '{plan_json: $plan[0]}')

ANALYZE_RESPONSE=$(curl -s -X POST "${API_URL}/analyze" \
    -H "Content-Type: application/json" \
    -d "${REQUEST_PAYLOAD}")

# Check if response contains expected fields
if echo "${ANALYZE_RESPONSE}" | jq -e '.summary' > /dev/null 2>&1; then
    echo "   ✅ Analyze endpoint working"
    echo ""

    # Display summary
    echo "4. Analysis Results Summary:"
    echo "   =========================="
    echo "${ANALYZE_RESPONSE}" | jq -r '
        "   Total Changes: \(.summary.total_changes)",
        "   - Creates: \(.summary.creates)",
        "   - Updates: \(.summary.updates)",
        "   - Deletes: \(.summary.deletes)",
        "   - Replaces: \(.summary.replaces)",
        "",
        "   Risk Findings: \(.risk_findings | length)",
        (.risk_findings | group_by(.severity) | map("   - \(.[0].severity | ascii_upcase): \(length)") | join("\n"))
    '
    echo ""

    # Display top risks
    echo "5. Top Risks:"
    echo "   =========="
    echo "${ANALYZE_RESPONSE}" | jq -r '
        .risk_findings[:3] | .[] |
        "   \(.severity | ascii_upcase): \(.title)\n   Resource: \(.resource_type)\n   Evidence: \(.evidence | tostring)\n"
    '

    # Save full response
    echo "6. Full response saved to: test_response.json"
    echo "${ANALYZE_RESPONSE}" | jq '.' > test_response.json

    echo ""
    echo "✅ All tests passed!"
    echo ""
    echo "To view the full PR comment, run:"
    echo "   jq -r '.pr_comment' test_response.json"

else
    echo "   ❌ Unexpected response format"
    echo "   Response: ${ANALYZE_RESPONSE}"
    exit 1
fi

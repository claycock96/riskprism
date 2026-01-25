#!/bin/bash
set -e

# Default behavior: Run Backend tests (Unit + API)
RUN_BACKEND=true
RUN_FRONTEND=false
RUN_CLI=true

# Parse arguments
for arg in "$@"; do
    case $arg in
        --frontend)
            RUN_FRONTEND=true
            ;;
        --no-cli)
            RUN_CLI=false
            ;;
        --only-frontend)
            RUN_BACKEND=false
            RUN_CLI=false
            RUN_FRONTEND=true
            ;;
    esac
done

echo "🧪 RiskPrism Master Test Runner"
echo "==============================="

# ---------------------------------------------------------
# 1. Backend Tests (Unit + Integration)
# ---------------------------------------------------------
if [ "$RUN_BACKEND" = true ]; then
    echo ""
    echo "🐳 [1] Running Backend Tests (Pytest inside container)..."
    
    # Check container
    if ! docker ps | grep -q terraform-webapp-backend-1; then
        echo "❌ Error: Backend container is not running."
        echo "👉 Run './start.sh' first."
        exit 1
    fi

    # Run Pytest (Unit + Integration)
    # The new structure is backend/tests/unit and backend/tests/integration
    docker exec -t terraform-webapp-backend-1 sh -c "export PYTHONPATH=/app && pytest tests/"

    # API Integration Tests (Curl)
    echo ""
    echo "🌐 [2] Running API Integration Tests (Curl)..."
    
    API_URL="http://localhost:8000"
    if [ -f .env ]; then
        AUTH_CODE=$(grep INTERNAL_ACCESS_CODE .env | cut -d '=' -f 2)
    fi

    # IAM Policy Test
    echo "   • Testing /analyze/iam..."
    IAM_FIXTURE="backend/tests/fixtures/iam/iam_admin_policy.json"
    if [ -f "$IAM_FIXTURE" ]; then
        REQUEST_PAYLOAD=$(jq -n --slurpfile policy "$IAM_FIXTURE" '{policy: $policy[0]}')
        HTTP_CODE=$(curl -s -o test_iam_res.json -w "%{http_code}" -X POST "${API_URL}/analyze/iam" \
            -H "Content-Type: application/json" \
            -H "X-Internal-Code: ${AUTH_CODE}" \
            -d "${REQUEST_PAYLOAD}")
        
        if [ "$HTTP_CODE" -eq 200 ]; then
            echo "     ✅ IAM Analysis Success (HTTP 200)"
        else
            echo "     ❌ IAM Analysis Failed (HTTP ${HTTP_CODE})"
            rm -f test_iam_res.json; exit 1
        fi
        rm -f test_iam_res.json
    fi
fi

# ---------------------------------------------------------
# 2. Frontend Tests (Vitest)
# ---------------------------------------------------------
if [ "$RUN_FRONTEND" = true ]; then
    echo ""
    echo "⚛️  [3] Running Frontend Tests (Vitest locally)..."
    if [ -d "frontend" ]; then
        (cd frontend && npm test -- --run) || { echo "❌ Frontend tests failed"; exit 1; }
    else
        echo "⚠️  Frontend directory not found, skipping."
    fi
fi

# ---------------------------------------------------------
# 3. CLI Verification
# ---------------------------------------------------------
if [ "$RUN_CLI" = true ]; then
    echo ""
    echo "💻 [4] Verifying 'riskprism' CLI..."
    if [ -f "scripts/riskprism" ]; then
        # Dry run with help command to verify script loads and branding is correct
        if ./scripts/riskprism 2>&1 | grep -q "Usage: riskprism"; then
            echo "     ✅ CLI Binary Functional & Branded"
        else
            echo "     ❌ CLI Binary failed branding or execution check"
            exit 1
        fi
    else
        echo "⚠️  CLI script not found at scripts/riskprism"
    fi
fi

echo ""
echo "✅ All requested tests passed!"

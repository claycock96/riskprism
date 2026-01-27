#!/bin/bash
# scripts/build-and-push.sh
# Builds production images and pushes to ECR (or mocks it if no creds)

set -e

# Ensure we are running from the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Configuration
REGION=${AWS_REGION:-"us-east-1"}
APP_NAME="riskprism"
GIT_HASH=$(git rev-parse --short HEAD || echo "no-git")
TAG="prod-${GIT_HASH}"
BUILD_ARGS=""

# Parse flags
for arg in "$@"; do
    if [ "$arg" == "--no-cache" ]; then
        BUILD_ARGS="--no-cache"
    fi
done

# Detect Account ID
RAW_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")

if [ -z "$RAW_ACCOUNT_ID" ]; then
    echo "⚠️  AWS CLI not configured or no credentials found. Switching to MOCK mode."
    ACCOUNT_ID="mock_account"
    MOCK=true
else
    echo "✅ AWS credentials found for account $RAW_ACCOUNT_ID. Running in SHIP mode."
    ACCOUNT_ID=$(echo "$RAW_ACCOUNT_ID" | tr '[:upper:]' '[:lower:]')
    MOCK=false
fi

# ECR Repositories (Placeholders if not provided)
BACKEND_REPO="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${APP_NAME}-backend"
FRONTEND_REPO="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${APP_NAME}-frontend"

build_and_tag() {
    local service=$1
    local repo=$2

    echo "🏗️  Building $service production image..."
    docker build $BUILD_ARGS -t "$service:local" -t "$repo:$TAG" -t "$repo:latest" "./$service"
}

push_image() {
    local service=$1
    local repo=$2

    if [ "$MOCK" = true ]; then
        echo "☁️  [MOCK] Would push $service to $repo:$TAG"
        echo "☁️  [MOCK] Would push $service to $repo:latest"
    else
        echo "🔐 Logging in to ECR..."
        aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$repo"

        echo "🚀 Pushing $service to $repo:$TAG..."
        docker push "$repo:$TAG"
        docker push "$repo:latest"
    fi
}

# Execution
echo "🏁 Starting production image workflow..."

# 1. Backend
build_and_tag "backend" "$BACKEND_REPO"
push_image "backend" "$BACKEND_REPO"

# 2. Frontend
build_and_tag "frontend" "$FRONTEND_REPO"
push_image "frontend" "$FRONTEND_REPO"

echo "✅ Workflow complete!"
if [ "$MOCK" = true ]; then
    echo "📝 Images were built locally but NOT pushed to ECR (Mock Mode)."
else
    echo "🚀 Images are now live in ECR."
fi

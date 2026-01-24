#!/bin/bash
set -e

# Log all output
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "Starting user data script..."

# Update system
dnf update -y

# Install Docker
dnf install -y docker git

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Add ec2-user to docker group
usermod -aG docker ec2-user

# Install Docker Compose
DOCKER_COMPOSE_VERSION="2.24.5"
curl -L "https://github.com/docker/compose/releases/download/v$${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose

# Verify installations
docker --version
docker-compose --version

# Clone the application repository
APP_DIR="/opt/terraform-analyzer"
mkdir -p $APP_DIR
cd $APP_DIR

# Clone repository (if not using placeholder)
if [ "${git_repo_url}" != "<INSERT GIT REPO>" ]; then
  git clone -b ${git_branch} ${git_repo_url} .
else
  echo "Git repository URL is a placeholder. Skipping clone."
  echo "Please SSH into the instance and manually clone your repository to $APP_DIR"
fi

# Create .env file with placeholders
cat > .env <<'EOF'
# LLM Provider Configuration
# Choose one: 'bedrock' or 'anthropic'
LLM_PROVIDER=bedrock

# Anthropic API Configuration (if using direct API)
# ANTHROPIC_API_KEY=your-api-key-here

# AWS Bedrock Configuration (if using Bedrock)
# AWS credentials are automatically provided via IAM role
# Bedrock Model ID (optional, defaults to anthropic.claude-3-5-sonnet-20241022-v2:0)
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0

# AWS Region
AWS_REGION=us-east-1

# Frontend Configuration
NEXT_PUBLIC_API_URL=http://backend:8000

# Security
INTERNAL_ACCESS_CODE=${internal_access_code}
EOF

# Set permissions
chown -R ec2-user:ec2-user $APP_DIR

# Start the application (only if repo was cloned)
if [ "${git_repo_url}" != "<INSERT GIT REPO>" ]; then
  echo "Starting Docker Compose..."
  cd $APP_DIR
  docker-compose up -d

  # Wait for services to be healthy
  sleep 10
  docker-compose ps

  echo "Application deployed successfully!"
  echo "Frontend: http://$(hostname -I | awk '{print $1}'):3000"
  echo "Backend: http://$(hostname -I | awk '{print $1}'):8000"
else
  echo "Skipping Docker Compose startup - repository not cloned"
  echo "After cloning your repository, run: cd $APP_DIR && docker-compose up -d"
fi

echo "User data script completed!"

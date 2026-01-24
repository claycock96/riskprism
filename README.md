# Terraform Plan Analyzer

A security-focused web application that analyzes Terraform plans for risks, generates plain-English explanations using AWS Bedrock, and produces review-ready PR comments.

## Features

- **Deterministic Risk Detection**: 20+ security rules covering IAM, networking, encryption, and more
- **Safe Data Handling**: Feature extraction and sanitization - never sends raw plan JSON to LLMs
- **AI-Powered Explanations**: Uses AWS Bedrock (Claude) to generate human-readable analysis
- **PR-Ready Output**: Copy-paste formatted comments for code reviews
- **Dockerized**: Full stack runs in containers for consistent local development

## Architecture

- **Backend**: Python FastAPI with async support
- **Frontend**: Next.js (coming soon)
- **AI**: AWS Bedrock (Claude 3.5 Sonnet)
- **Deployment**: Docker containers

## Quick Start

### Prerequisites

- Docker Desktop (for Mac: Apple Silicon or Intel)
- AWS credentials with Bedrock access (optional for mock mode)
- Terraform plan JSON file to analyze

### 1. Start Services

```bash
# Start all services
./start.sh

# Backend API:  http://localhost:8000
# API Docs:     http://localhost:8000/docs
# Health Check: http://localhost:8000/health
```

### 2. Configure LLM Provider (Optional)

The backend supports two LLM providers for generating explanations:

#### Option A: Anthropic API (Recommended for Development)

Easiest to set up - just need an API key:

```bash
# Copy example env file
cp .env.example .env

# Edit .env and set:
#   LLM_PROVIDER=anthropic
#   ANTHROPIC_API_KEY=your-api-key

# Get your API key from: https://console.anthropic.com/

# Restart backend
./rebuild.sh backend
```

#### Option B: AWS Bedrock (For Production)

Requires AWS account with Bedrock access:

```bash
# Ensure AWS credentials are configured
aws configure

# Or set in .env:
#   LLM_PROVIDER=bedrock
#   AWS_ACCESS_KEY_ID=your_key
#   AWS_SECRET_ACCESS_KEY=your_secret
#   AWS_REGION=us-east-1
```

The docker-compose setup mounts `~/.aws` into the container for local development.

#### Option C: Mock Mode (No Credentials)

Without credentials, the backend runs in mock mode - all risk detection works normally, but explanations are generic.

### 3. Test the API

```bash
# Run automated tests
./test_api.sh

# Or test manually
curl http://localhost:8000/health
```

### Available Scripts

```bash
./start.sh      # Start all services
./stop.sh       # Stop all services
./logs.sh       # View logs (optional: ./logs.sh backend)
./test_api.sh   # Test the API with sample plan
./rebuild.sh    # Rebuild containers (optional: ./rebuild.sh backend)
./shell.sh      # Open shell in container (optional: ./shell.sh backend)
```

## Usage

### Generate Terraform Plan JSON

```bash
cd your-terraform-project
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

### Analyze the Plan

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @plan.json | jq
```

### Example Response

```json
{
  "summary": {
    "total_changes": 5,
    "creates": 3,
    "updates": 1,
    "deletes": 1,
    "replaces": 0
  },
  "risk_findings": [
    {
      "risk_id": "SG-OPEN-INGRESS",
      "title": "Security group allows public internet ingress",
      "severity": "critical",
      "resource_type": "aws_security_group",
      "evidence": {
        "public_cidr": true,
        "exposed_ports": [22, 80, 443]
      },
      "recommendation": "Restrict CIDR blocks to known IP ranges..."
    }
  ],
  "explanation": {
    "executive_summary": [
      "Plan creates 3 new resources and deletes 1",
      "Found 1 critical security issue requiring immediate attention"
    ],
    "top_risks_explained": "...",
    "review_questions": [...]
  },
  "pr_comment": "## 🔍 Terraform Plan Analysis\n\n..."
}
```

## Development

### Project Structure

```
terraform-webapp/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI app
│   │   ├── models.py         # Pydantic models
│   │   ├── parser.py         # Terraform plan parser
│   │   ├── risk_engine.py    # Security rule engine
│   │   └── bedrock_client.py # AWS Bedrock integration
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                  # Coming soon
├── docker-compose.yml
└── design.md                  # Full design documentation
```

### Local Development (without Docker)

```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server with hot reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Running Tests

```bash
cd backend
pytest
```

### Mock Mode

If AWS credentials are not configured, the backend runs in mock mode:
- Parser and risk engine work normally
- Bedrock calls return a generic mock response
- Useful for development without AWS access

## Security Rules

The risk engine implements 8 core rules (with 12+ more planned):

### Implemented
1. **SG-OPEN-INGRESS** - Public security group ingress (Critical/High)
2. **S3-PUBLIC-ACL-OR-POLICY** - Public S3 access (Critical)
3. **S3-PAB-REMOVED** - S3 Block Public Access disabled (High)
4. **S3-ENCRYPTION-REMOVED** - S3 encryption removed (High)
5. **RDS-PUBLICLY-ACCESSIBLE** - Public RDS instance (Critical)
6. **RDS-ENCRYPTION-OFF** - RDS encryption disabled (High)
7. **IAM-ADMIN-WILDCARD** - IAM wildcard permissions (Critical)
8. **CT-LOGGING-DISABLED** - CloudTrail disabled (Critical)

### Planned
- NACL-ALLOW-ALL
- LB-INTERNET-FACING
- IAM-PASSROLE-BROAD
- KMS-DECRYPT-BROAD
- EBS-ENCRYPTION-OFF
- LAMBDA-INTERNET-EGRESS-RISK
- And more...

## Configuration

See [design.md](design.md) for:
- Detailed architecture
- Security model and sanitization spec
- Complete rule definitions
- Bedrock prompt engineering
- API specifications

## AWS Bedrock Setup

1. Enable Bedrock in your AWS account (us-east-1 recommended)
2. Request access to Claude 3.5 Sonnet model
3. Ensure IAM permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel"
         ],
         "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet-*"
       }
     ]
   }
   ```

## Testing Different LLM Providers

The health check shows which provider is active:

```bash
# Check current provider
curl http://localhost:8000/health | jq '.components.llm'
```

### Switch to Anthropic API

```bash
# Create .env file
cat > .env <<EOF
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-actual-api-key-here
EOF

# Rebuild and restart
./rebuild.sh backend

# Verify it's using Anthropic
curl http://localhost:8000/health | jq '.components.llm'
# Should show: "provider": "anthropic", "mode": "api"

# Test with real AI explanations
./test_api.sh
```

### Switch to AWS Bedrock

```bash
# Update .env
cat > .env <<EOF
LLM_PROVIDER=bedrock
EOF

# Ensure AWS credentials are configured
aws configure

# Rebuild and restart
./rebuild.sh backend

# Verify
curl http://localhost:8000/health | jq '.components.llm'
# Should show: "provider": "bedrock", "mode": "api"
```

## Contributing

This is an MVP. Contributions welcome for:
- Additional risk rules
- Frontend development (Next.js)
- Test coverage improvements
- Documentation

## License

MIT

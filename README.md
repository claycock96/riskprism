# Terraform Plan Analyzer

A security-focused web application that analyzes Terraform plans and IAM policies for risks, generates plain-English explanations using AI, and produces review-ready PR comments.

## Features

- **🛡️ Dual Analysis Modes**:
  - **Terraform Plan**: Analyzing infrastructure changes (`terraform show -json tfplan`)
  - **IAM Policy**: Analyzing AWS IAM policies for privilege escalation risks
- **Deterministic Risk Engine**: 24+ production-ready security rules covering IAM, networking, encryption, and more
- **High-Concurrency Engine**: Non-blocking Async AI and SQLite WAL mode support 20+ simultaneous users ⚡
- **Analysis Caching**: SHA-256 Plan Fingerprinting allows skipping redundant AI calls—saves 90%+ in latency and API costs 💸
- **Safe-by-Design**: Safe feature extraction and hashing—sensitive values and resource names never leave your env
- **Persistent History**: Full reports are saved in a localized SQLite database and survive container restarts
- **Consolidated UI Reasoning**: AI insights are merged directly into rule engine findings for a single "Source of Truth"
- **Audit Logging**: Traceable "Paper Trail" recording requester IP and User-Agent for every analysis session
- **Polished UI/UX**: Multi-step progress indicators, deep-link navigation, and "Share Results" quick actions 🎨
- **Interactive UI**: Custom "Risk Card" rendering for deep exploit analysis and attack scenarios
- **PR-Ready Output**: Copy-paste formatted Markdown comments for simplified Pull Request reviews
- **CLI Tool**: Dev-focused `tf-analyze` script for instant feedback in the terminal with CI/CD support

## Architecture

- **Backend**: Python FastAPI with SQLAlchemy, SQLite persistence, and SHA-256 Plan Fingerprinting
- **Frontend**: Next.js 14 with TypeScript, Tailwind CSS, and custom Markdown "Risk Card" rendering
- **Auth**: Shared internal access code protection
- **AI**: AWS Bedrock (Claude 3.5 Sonnet) or Anthropic API
- **Caching**: Intelligent skip-logic for identical infrastructure plans

## Quick Start

### Prerequisites

- Docker Desktop (for Mac: Apple Silicon or Intel)
- AWS credentials with Bedrock access (optional for mock mode)
- Terraform plan JSON file to analyze

### 1. Start Services

```bash
# Start all services
./start.sh

# Frontend:     http://localhost:3000  (Upload and analyze plans via UI)
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

## CLI Tool for Local Development

For developers running Terraform locally, use the included CLI tool for quick analysis:

### Installation

```bash
# Add to your PATH (one-time setup)
sudo cp tf-analyze /usr/local/bin/
# Or use directly: ./tf-analyze
```

### Workflow

```bash
# 1. Generate Terraform plan
terraform plan -out=tfplan

# 2. Analyze with CLI tool
tf-analyze tfplan

# 3. Review output, then apply if safe
terraform apply tfplan
```

### Example Output

```
🔍 Analyzing Terraform Plan...

═══════════════════════════════════════════════════════
                  ANALYSIS SUMMARY ⚡ (Cached Analysis)
═══════════════════════════════════════════════════════

Resource Changes:
  Total: 5
  Creates:  3
  Updates:  1
  Deletes:  1

Security Findings: 2
  🔴 Critical: 1
  🟠 High:     1

High Priority Findings:
───────────────────────────────────────────────────────

[CRITICAL] Security group allows public internet ingress
  Resource: aws_security_group
  → Restrict CIDR blocks to known IP ranges...

═══════════════════════════════════════════════════════
⚠️  CRITICAL ISSUES FOUND - Review required before apply

📋 Full report: http://localhost:3000
```

**Exit Codes:**
- `0` - No critical/high findings (safe to proceed)
- `1` - High severity findings (review recommended)
- `2` - Critical findings (review required)

See [CLI_USAGE.md](CLI_USAGE.md) for advanced usage, git hooks, and Makefile integration.

## Usage

### Web UI

Simply visit [http://localhost:3000](http://localhost:3000) and upload your plan JSON file.

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
├── frontend/
│   ├── src/
│   │   ├── app/              # Next.js app router
│   │   ├── components/       # React components
│   │   │   ├── AIExplanation.tsx
│   │   │   ├── RiskFindings.tsx
│   │   │   ├── Summary.tsx
│   │   │   └── ...
│   │   └── lib/
│   │       ├── resourceMapping.ts  # Hash-to-name mapping
│   │       └── types.ts
│   ├── package.json
│   └── Dockerfile
├── terraform/                 # AWS deployment IaC
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── user_data.sh
│   ├── deploy.sh
│   └── README.md
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

The risk engine implements 14 production-ready rules:

### Networking & Exposure
1.  **SG-OPEN-INGRESS** - Public security group ingress (Critical/High)
2.  **NACL-ALLOW-ALL** - Wide open Network ACLs (High)
3.  **LB-INTERNET-FACING** - Internet-facing Load Balancer (Medium)

### Storage & Datastores
4.  **S3-PUBLIC-ACL-OR-POLICY** - Public S3 access (Critical)
5.  **S3-PAB-REMOVED** - S3 Block Public Access disabled (High)
6.  **S3-ENCRYPTION-REMOVED** - S3 encryption removed (High)
7.  **RDS-PUBLICLY-ACCESSIBLE** - Public RDS instance (Critical)
8.  **RDS-ENCRYPTION-OFF** - RDS encryption disabled (High)
9.  **EBS-ENCRYPTION-OFF** - EBS volume encryption disabled (High)

### IAM & Security
10. **IAM-ADMIN-WILDCARD** - IAM wildcard permissions in inline policies (Critical)
11. **IAM-MANAGED-POLICY** - Dangerous AWS managed policy attachments (Critical/High)
12. **IAM-PASSROLE-BROAD** - Broad iam:PassRole permissions (High)
13. **CT-LOGGING-DISABLED** - CloudTrail disabled (Critical)
14. **KMS-DECRYPT-BROAD** - Overly broad KMS decryption permissions (High)

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

## AWS Deployment

Deploy to AWS EC2 using the included Terraform configuration:

```bash
cd terraform
./deploy.sh
```

The deployment script will:
1. Prompt for VPC ID and Subnet ID
2. Generate and store SSH keys in AWS Secrets Manager
3. Create a t4g.small EC2 instance with Docker + Docker Compose
4. Attach an IAM role with Bedrock permissions
5. Configure security groups for VPC-only access
6. Auto-deploy the application

**Cost**: ~$15/month + Bedrock usage

### Using CLI with Deployed Instance

Once deployed, your team can use the CLI tool with the remote API:

```bash
# Get the private IP from Terraform output
cd terraform
PRIVATE_IP=$(terraform output -raw instance_private_ip)

# Use CLI with remote API (from within VPN/bastion)
tf-analyze tfplan http://${PRIVATE_IP}:8000
```

See [terraform/README.md](terraform/README.md) for detailed deployment instructions.

## Frontend Security Features

The frontend implements privacy-preserving resource name display:

1. **Resource Hashing**: Backend hashes resource addresses (e.g., `aws_db_instance.prod-database` → `res_abc123def4`)
2. **Metadata Only**: Only resource types, actions, and changed paths sent to AI
3. **Sensitive Keys Blocked**: Passwords, tokens, secrets filtered during parsing
4. **Frontend Enhancement**: UI maps hashes back to readable names for display

Result: AI gets privacy-protected data, you see readable resource names. Hover over the "How is data sanitized?" link in the UI for details.

## Contributing

This is an MVP. Contributions welcome for:
- Additional risk rules
- Enhanced frontend features
- Test coverage improvements
- Documentation

## License

MIT

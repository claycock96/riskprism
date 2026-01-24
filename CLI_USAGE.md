# CLI Usage Guide

Quick command-line tool for analyzing Terraform plans during local development.

## Installation

### Option 1: Add to PATH (Recommended)

```bash
# From the terraform-webapp directory
sudo cp tf-analyze /usr/local/bin/
# Or create a symlink
sudo ln -s $(pwd)/tf-analyze /usr/local/bin/tf-analyze
```

### Option 2: Use Directly

```bash
# From the terraform-webapp directory
./tf-analyze path/to/tfplan
```

### Prerequisites

- `terraform` CLI installed
- `jq` installed (for JSON parsing)
  - macOS: `brew install jq`
  - Ubuntu/Debian: `sudo apt-get install jq`
  - RHEL/CentOS: `sudo yum install jq`
- API server running (local or remote)

## Usage

### Basic Workflow

```bash
# 1. Write your Terraform code
cd your-terraform-project

# 2. Generate plan file
terraform plan -out=tfplan

# 3. Analyze the plan
tf-analyze tfplan

# 4. Review output, then apply if safe
terraform apply tfplan
```

### With Remote API

If your analyzer is deployed on AWS or another server:

```bash
# Analyze using remote API
tf-analyze tfplan http://10.0.1.50:8000

# Or set environment variable
export TF_ANALYZE_API=http://10.0.1.50:8000
tf-analyze tfplan $TF_ANALYZE_API
```

## Output

The tool provides a color-coded terminal summary:

```
🔍 Analyzing Terraform Plan...

═══════════════════════════════════════════════════════
                  ANALYSIS SUMMARY
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

[HIGH] S3 Block Public Access disabled
  Resource: aws_s3_bucket_public_access_block
  → Keep PAB on except explicitly approved.

AI Summary:
───────────────────────────────────────────────────────
  • Plan creates 3 new resources and deletes 1
  • Found 2 security issues requiring attention
  • Public access controls are being modified

═══════════════════════════════════════════════════════
⚠️  CRITICAL ISSUES FOUND - Review required before apply

📋 Full report: http://localhost:8000:3000
```

## Exit Codes

The tool uses exit codes to integrate with scripts and CI/CD:

- `0` - No critical or high findings (safe to apply)
- `1` - High severity findings found (review recommended)
- `2` - Critical findings found (review required)

### Example: Block Apply on Critical Findings

```bash
#!/bin/bash
terraform plan -out=tfplan

if tf-analyze tfplan; then
    echo "Analysis passed, applying..."
    terraform apply tfplan
else
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 2 ]; then
        echo "CRITICAL findings - aborting apply"
        exit 1
    else
        echo "HIGH findings - proceed with caution"
        read -p "Continue with apply? (yes/no): " CONFIRM
        if [ "$CONFIRM" == "yes" ]; then
            terraform apply tfplan
        fi
    fi
fi
```

## Integration with Git Hooks

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Check if any .tf files changed
if git diff --cached --name-only | grep -q '\.tf$'; then
    echo "Terraform files changed - running plan analysis..."

    terraform plan -out=.tf-analyze-plan 2>&1 | grep -v "Refreshing state"

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        tf-analyze .tf-analyze-plan
        RESULT=$?
        rm -f .tf-analyze-plan

        if [ $RESULT -eq 2 ]; then
            echo "CRITICAL security findings - commit blocked"
            exit 1
        fi
    fi
fi
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

## Makefile Integration

Add to your Terraform project's `Makefile`:

```makefile
.PHONY: plan analyze apply

plan:
	terraform plan -out=tfplan

analyze: plan
	tf-analyze tfplan

apply: analyze
	terraform apply tfplan

safe-apply:
	@terraform plan -out=tfplan
	@if tf-analyze tfplan; then \
		terraform apply tfplan; \
	else \
		echo "Analysis failed - review findings before applying"; \
		exit 1; \
	fi
```

Usage:
```bash
make analyze    # Plan and analyze
make safe-apply # Only apply if analysis passes
```

## Troubleshooting

### "jq command not found"

Install jq:
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# RHEL/CentOS
sudo yum install jq
```

### "Failed to connect to API"

1. Check if the API is running:
   ```bash
   curl http://localhost:8000/health
   ```

2. If using remote API, ensure network connectivity:
   ```bash
   curl http://your-api-server:8000/health
   ```

3. Check firewall rules allow traffic on port 8000

### "Invalid response from API"

The API might be in mock mode or having issues. Check logs:
```bash
# If running locally with Docker
docker-compose logs backend
```

## Advanced Usage

### JSON Output (for scripting)

```bash
# Get full JSON response
terraform show -json tfplan | \
  curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @- | jq '.'

# Extract specific data
terraform show -json tfplan | \
  curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @- | jq '.risk_findings[] | select(.severity=="critical")'
```

### Save Report to File

```bash
tf-analyze tfplan | tee analysis-report.txt
```

### Filter by Severity

```bash
# Only show critical findings
terraform show -json tfplan | \
  curl -s -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d @- | \
  jq '.risk_findings[] | select(.severity=="critical")'
```

## Tips

1. **Run before every apply**: Make it a habit
   ```bash
   alias tf='terraform'
   alias tfa='terraform apply'
   alias tfp='terraform plan -out=tfplan && tf-analyze tfplan'
   ```

2. **Use with watch for live feedback**:
   ```bash
   watch -n 5 'terraform plan -out=tfplan && tf-analyze tfplan'
   ```

3. **Combine with terraform fmt**:
   ```bash
   terraform fmt && terraform plan -out=tfplan && tf-analyze tfplan
   ```

4. **Team adoption**: Add to team documentation and onboarding

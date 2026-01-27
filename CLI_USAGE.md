# CLI Usage Guide

Quick command-line tool for analyzing infrastructure and IAM risk during local development.

## Installation

### Option 1: Add to PATH (Recommended)

```bash
# Create local bin directory if it doesn't exist
mkdir -p ~/.local/bin

# Copy the script
cp scripts/riskprism ~/.local/bin/

# Ensure ~/.local/bin is in your PATH (add to .zshrc or .bashrc if needed)
export PATH="$HOME/.local/bin:$PATH"
```

### Option 2: Use Directly

```bash
# From the terraform-webapp directory
./scripts/riskprism path/to/tfplan
```

### Prerequisites

- `terraform` CLI installed
- `jq` installed (for JSON parsing)
  - macOS: `brew install jq`
  - Ubuntu/Debian: `sudo apt-get install jq`
  - RHEL/CentOS: `sudo yum install jq`
- API server running (local or remote)

## Usage

### Terraform Plan Analysis

```bash
# 1. Generate plan file
terraform plan -out=tfplan

# 2. Analyze the plan
riskprism tfplan

# 3. Analyze without saving to server (Privacy mode)
riskprism -n tfplan
```

### IAM Policy Analysis

You can also analyze standalone IAM policy JSON files. The tool automatically detects if the input is an IAM policy.

```bash
# Analyze a standalone IAM policy
riskprism policy.json
```

## Output

The tool provides a color-coded terminal summary. For IAM policies, the labels are adjusted to reflect policy statements instead of resource changes.

### Example (Terraform)
```
🔍 RiskPrism Analyzing...
Detected Terraform plan...

═══════════════════════════════════════════════════════
                  ANALYSIS SUMMARY
═══════════════════════════════════════════════════════

Resource Changes:
  Total: 5
  Creates:  3
  Updates:  1
  Deletes:  1
...
```

### Example (IAM)
```
🔍 RiskPrism Analyzing...
Detected IAM policy document...

═══════════════════════════════════════════════════════
                  ANALYSIS SUMMARY
═══════════════════════════════════════════════════════

Policy Statements:
  Total: 2
  Allow:  2
  Deny:   0

Security Findings: 1
  🔴 Critical: 1
...
```

The report link leads to a persistent results page featuring **Visual Diff Highlighting** (Old vs New values) and can be shared with your team via **RiskPrism**.

## Advanced Usage

### Auto-Detection
RiskPrism automatically detects the input type:
- If the file contains `"Version": "2012-10-17"` or `"Statement"`, it is treated as an **IAM Policy**.
- If it is a binary file or standard JSON without those keys, it is treated as a **Terraform Plan**.


## Exit Codes

The tool uses exit codes to integrate with scripts and CI/CD:

- `0` - No critical or high findings (safe to apply)
- `1` - High severity findings found (review recommended)
- `2` - Critical findings found (review required)

### Example: Block Apply on Critical Findings

```bash
#!/bin/bash
terraform plan -out=tfplan

if riskprism tfplan; then
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
        riskprism .tf-analyze-plan
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
	riskprism tfplan

apply: analyze
	terraform apply tfplan

safe-apply:
	@terraform plan -out=tfplan
	@if riskprism tfplan; then \
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
riskprism tfplan | tee analysis-report.txt
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

### Setup

Ensure you have mapped your `INTERNAL_ACCESS_CODE` if applicable:
```bash
export INTERNAL_ACCESS_CODE=your-secret-code
```

### Options

- `-n`, `--no-store`: Disable session storage on the server. The analysis will be performed, but no data will be saved in the database or cache.
- `-u`, `--api-url`: Specify a custom API URL (default: `http://localhost:8000`).

### Basic Usage

```bash
riskprism [options] <plan-or-policy-file> [api-url]
```

#### Examples

1.  **Analyze a binary plan file**:
    ```bash
    terraform plan -out=tfplan
    ./scripts/riskprism tfplan
    ```

2.  **Analyze a JSON plan file**:
    ```bash
    ./scripts/riskprism plan.json
    ```

3.  **Point to a remote API**:
    ```bash
    ./scripts/riskprism tfplan http://prod-analyzer:8000
    ```

## Tips

1. **Run before every apply**: Make it a habit
   ```bash
   alias tf='terraform'
   alias tfa='terraform apply'
   alias tfp='terraform plan -out=tfplan && ./scripts/riskprism tfplan'
   ```

2. **Use with watch for live feedback**:
   ```bash
   watch -n 5 'terraform plan -out=tfplan && ./scripts/riskprism tfplan'
   ```

3. **Combine with terraform fmt**:
   ```bash
   terraform fmt && terraform plan -out=tfplan && ./scripts/riskprism tfplan
   ```

4. **Team adoption**: Add to team documentation and onboarding

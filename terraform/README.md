# Terraform Deployment for Terraform Analyzer

This directory contains Terraform configuration to deploy the Terraform Analyzer application to AWS EC2.

## Architecture

- **EC2 Instance**: t4g.small (ARM Graviton) running Amazon Linux 2023
- **IAM Role**: Attached with Bedrock permissions for AI analysis
- **Security Group**: Allows inbound from VPC CIDR on ports 3000, 8000, and 22
- **SSH Key**: Auto-generated and stored in AWS Secrets Manager
- **Networking**: Deployed to private subnet, accessible via bastion host

## Prerequisites

1. Terraform installed (v1.0+)
2. AWS CLI configured with appropriate credentials
3. Existing VPC with private subnets
4. Bastion host or VPN access to reach private subnet

## Quick Start

### Option 1: Interactive Deployment (Recommended)

```bash
cd terraform
./deploy.sh
```

The script will prompt you for:
- VPC ID
- Private Subnet ID
- Git Repository URL (optional)
- Git Branch (default: main)
- Instance Type (default: t4g.small)
- SSH Key Name (default: terraform-analyzer-key)

### Option 2: Manual Deployment

```bash
cd terraform

# Initialize Terraform
terraform init

# Plan deployment
terraform plan \
  -var="vpc_id=vpc-xxxxxxxxx" \
  -var="subnet_id=subnet-xxxxxxxxx" \
  -out=tfplan

# Apply configuration
terraform apply tfplan
```

## Post-Deployment Steps

### 1. Retrieve SSH Private Key

The deployment automatically generates an SSH key pair and stores the private key in AWS Secrets Manager.

```bash
# Get the command from Terraform output
terraform output -raw retrieve_ssh_key_command

# Or manually retrieve:
aws secretsmanager get-secret-value \
  --secret-id <secret-id-from-output> \
  --query SecretString \
  --output text > terraform-analyzer-key.pem

chmod 400 terraform-analyzer-key.pem
```

### 2. SSH to Instance

```bash
# Through your bastion host
ssh -i terraform-analyzer-key.pem ec2-user@<private-ip>
```

### 3. Access the Application

Once deployed, access through your bastion/VPN:

- **Frontend**: `http://<private-ip>:3000`
- **Backend API**: `http://<private-ip>:8000`
- **Backend Health**: `http://<private-ip>:8000/health`

### 4. Configure Environment Variables (Optional)

If you need to switch from Bedrock to direct Anthropic API:

```bash
ssh -i terraform-analyzer-key.pem ec2-user@<private-ip>

cd /opt/terraform-analyzer

# Edit .env file
sudo nano .env

# Change LLM_PROVIDER to 'anthropic' and add your API key
# LLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=sk-ant-...

# Restart containers
docker-compose down
docker-compose up -d
```

### 5. If Using Placeholder Repository

If you didn't provide a git repository URL during deployment:

```bash
ssh -i terraform-analyzer-key.pem ec2-user@<private-ip>

cd /opt/terraform-analyzer
git clone <your-actual-repo-url> .

# Start the application
docker-compose up -d
```

## Terraform Outputs

After deployment, useful outputs include:

```bash
terraform output                           # Show all outputs
terraform output instance_private_ip       # Get private IP
terraform output frontend_url              # Get frontend URL
terraform output retrieve_ssh_key_command  # Get SSH key retrieval command
```

## Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `vpc_id` | VPC ID where instance will be deployed | - | Yes |
| `subnet_id` | Private subnet ID for the instance | - | Yes |
| `git_repo_url` | Git repository URL | `<INSERT GIT REPO>` | No |
| `git_branch` | Git branch to deploy | `main` | No |
| `instance_type` | EC2 instance type | `t4g.small` | No |
| `key_name` | SSH key pair name | `terraform-analyzer-key` | No |
| `app_name` | Application name for tagging | `terraform-analyzer` | No |
| `environment` | Environment name | `production` | No |

## IAM Permissions

The EC2 instance has an IAM role with the following permissions:

- **Bedrock**: `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`
- **Resource**: `arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-*`

## Security Considerations

- Instance deployed in private subnet (no public IP)
- Security group restricts inbound to VPC CIDR only
- SSH key auto-generated and stored in Secrets Manager
- Root volume encrypted
- IMDSv2 enforced (prevents SSRF attacks)

## Troubleshooting

### Check instance status

```bash
# View user data logs
ssh -i terraform-analyzer-key.pem ec2-user@<private-ip>
sudo tail -f /var/log/user-data.log
```

### Check Docker containers

```bash
ssh -i terraform-analyzer-key.pem ec2-user@<private-ip>
cd /opt/terraform-analyzer
docker-compose ps
docker-compose logs -f
```

### Restart application

```bash
ssh -i terraform-analyzer-key.pem ec2-user@<private-ip>
cd /opt/terraform-analyzer
docker-compose down
docker-compose up -d
```

## Cost Estimate

- **EC2 t4g.small**: ~$12/month (ARM Graviton)
- **EBS gp3 20GB**: ~$2/month
- **Bedrock usage**: Pay per token
- **Secrets Manager**: $0.40/month

**Total**: ~$15/month + Bedrock usage

## Cleanup

To destroy all resources:

```bash
cd terraform
terraform destroy
```

**Note**: The Secrets Manager secret has a 7-day recovery window by default.

## Updates

To update the application:

```bash
ssh -i terraform-analyzer-key.pem ec2-user@<private-ip>
cd /opt/terraform-analyzer

# Pull latest changes
git pull origin main

# Rebuild containers
docker-compose down
docker-compose up -d --build
```

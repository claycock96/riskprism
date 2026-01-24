#!/bin/bash
set -e

# Terraform deployment script for Terraform Analyzer

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Terraform Analyzer Deployment Script ===${NC}\n"

# Check if terraform is installed
if ! command -v terraform &> /dev/null; then
    echo -e "${RED}Error: Terraform is not installed${NC}"
    echo "Please install Terraform: https://www.terraform.io/downloads"
    exit 1
fi

# Prompt for required variables
echo -e "${YELLOW}Please provide the following information:${NC}\n"

read -p "VPC ID: " VPC_ID
if [ -z "$VPC_ID" ]; then
    echo -e "${RED}Error: VPC ID is required${NC}"
    exit 1
fi

read -p "Subnet ID (private subnet): " SUBNET_ID
if [ -z "$SUBNET_ID" ]; then
    echo -e "${RED}Error: Subnet ID is required${NC}"
    exit 1
fi

read -p "Git Repository URL [default: <INSERT GIT REPO>]: " GIT_REPO
GIT_REPO=${GIT_REPO:-"<INSERT GIT REPO>"}

read -p "Git Branch [default: main]: " GIT_BRANCH
GIT_BRANCH=${GIT_BRANCH:-"main"}

read -p "Instance Type [default: t4g.small]: " INSTANCE_TYPE
INSTANCE_TYPE=${INSTANCE_TYPE:-"t4g.small"}

read -p "SSH Key Name [default: terraform-analyzer-key]: " KEY_NAME
KEY_NAME=${KEY_NAME:-"terraform-analyzer-key"}

echo -e "\n${GREEN}Configuration Summary:${NC}"
echo "  VPC ID: $VPC_ID"
echo "  Subnet ID: $SUBNET_ID"
echo "  Git Repo: $GIT_REPO"
echo "  Git Branch: $GIT_BRANCH"
echo "  Instance Type: $INSTANCE_TYPE"
echo "  Key Name: $KEY_NAME"
echo ""

read -p "Proceed with deployment? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo -e "${YELLOW}Deployment cancelled${NC}"
    exit 0
fi

# Initialize Terraform
echo -e "\n${GREEN}Initializing Terraform...${NC}"
terraform init

# Plan
echo -e "\n${GREEN}Creating Terraform plan...${NC}"
terraform plan \
    -var="vpc_id=$VPC_ID" \
    -var="subnet_id=$SUBNET_ID" \
    -var="git_repo_url=$GIT_REPO" \
    -var="git_branch=$GIT_BRANCH" \
    -var="instance_type=$INSTANCE_TYPE" \
    -var="key_name=$KEY_NAME" \
    -out=tfplan

# Review plan
echo -e "\n${YELLOW}Please review the plan above.${NC}"
read -p "Do you want to apply this plan? (yes/no): " APPLY_CONFIRM
if [ "$APPLY_CONFIRM" != "yes" ]; then
    echo -e "${YELLOW}Apply cancelled. Cleaning up plan file.${NC}"
    rm -f tfplan
    exit 0
fi

# Apply
echo -e "\n${GREEN}Applying Terraform configuration...${NC}"
terraform apply tfplan

# Clean up plan file
rm -f tfplan

# Display outputs
echo -e "\n${GREEN}=== Deployment Complete ===${NC}\n"
terraform output

echo -e "\n${YELLOW}Next Steps:${NC}"
echo "1. Retrieve SSH private key from Secrets Manager:"
echo "   $(terraform output -raw retrieve_ssh_key_command)"
echo ""
echo "2. SSH into the instance using your bastion:"
echo "   $(terraform output -raw ssh_command)"
echo ""
echo "3. Access the application:"
echo "   Frontend: $(terraform output -raw frontend_url)"
echo "   Backend:  $(terraform output -raw backend_url)"
echo ""
echo "4. If using placeholder repo, clone your actual repository:"
echo "   ssh to instance, then: cd /opt/terraform-analyzer && git clone <your-repo> ."
echo "   Then run: docker-compose up -d"
echo ""
echo -e "${GREEN}Deployment script completed!${NC}"

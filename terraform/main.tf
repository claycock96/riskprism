terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Data source for VPC
data "aws_vpc" "selected" {
  id = var.vpc_id
}

# Data source for subnet
data "aws_subnet" "selected" {
  id = var.subnet_id
}

# Generate SSH key pair
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Store private key in Secrets Manager
resource "aws_secretsmanager_secret" "ssh_private_key" {
  name_prefix             = "${var.app_name}-ssh-key-"
  description             = "SSH private key for ${var.app_name} EC2 instance"
  recovery_window_in_days = 7

  tags = {
    Name        = "${var.app_name}-ssh-key"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_secretsmanager_secret_version" "ssh_private_key" {
  secret_id     = aws_secretsmanager_secret.ssh_private_key.id
  secret_string = tls_private_key.ssh_key.private_key_pem
}

# Create AWS key pair from generated public key
resource "aws_key_pair" "deployer" {
  key_name   = var.key_name
  public_key = tls_private_key.ssh_key.public_key_openssh

  tags = {
    Name        = var.key_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# IAM role for EC2 instance
resource "aws_iam_role" "ec2_role" {
  name_prefix = "${var.app_name}-ec2-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "${var.app_name}-ec2-role"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# IAM policy for Bedrock access
resource "aws_iam_role_policy" "bedrock_access" {
  name_prefix = "${var.app_name}-bedrock-policy-"
  role        = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-*"
      }
    ]
  })
}

# Instance profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name_prefix = "${var.app_name}-profile-"
  role        = aws_iam_role.ec2_role.name

  tags = {
    Name        = "${var.app_name}-instance-profile"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Security group
resource "aws_security_group" "app_sg" {
  name_prefix = "${var.app_name}-sg-"
  description = "Security group for ${var.app_name} application"
  vpc_id      = var.vpc_id

  # Allow inbound from VPC CIDR
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
    description = "Allow frontend access from VPC"
  }

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
    description = "Allow backend API access from VPC"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
    description = "Allow SSH from VPC"
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "${var.app_name}-sg"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# EC2 instance
resource "aws_instance" "app" {
  ami                    = data.aws_ami.amazon_linux_2023_arm.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  key_name               = aws_key_pair.deployer.key_name
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  user_data = templatefile("${path.module}/user_data.sh", {
    git_repo_url         = var.git_repo_url
    git_branch           = var.git_branch
    internal_access_code = var.internal_access_code
  })

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true

    tags = {
      Name = "${var.app_name}-root-volume"
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name        = var.app_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Data source for latest Amazon Linux 2023 ARM AMI
data "aws_ami" "amazon_linux_2023_arm" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-*-arm64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

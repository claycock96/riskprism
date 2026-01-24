variable "vpc_id" {
  description = "VPC ID where the EC2 instance will be deployed"
  type        = string
}

variable "subnet_id" {
  description = "Private subnet ID for the EC2 instance"
  type        = string
}

variable "key_name" {
  description = "Name of the SSH key pair"
  type        = string
  default     = "terraform-analyzer-key"
}

variable "internal_access_code" {
  description = "Security access code for the application"
  type        = string
  sensitive   = true
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t4g.small"
}

variable "git_repo_url" {
  description = "Git repository URL for the application"
  type        = string
  default     = "<INSERT GIT REPO>"
}

variable "git_branch" {
  description = "Git branch to deploy"
  type        = string
  default     = "main"
}

variable "app_name" {
  description = "Application name for tagging"
  type        = string
  default     = "terraform-analyzer"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.app.id
}

output "instance_private_ip" {
  description = "Private IP address of the EC2 instance"
  value       = aws_instance.app.private_ip
}

output "frontend_url" {
  description = "URL to access the frontend application"
  value       = "http://${aws_instance.app.private_ip}:3000"
}

output "backend_url" {
  description = "URL to access the backend API"
  value       = "http://${aws_instance.app.private_ip}:8000"
}

output "ssh_private_key_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the SSH private key"
  value       = aws_secretsmanager_secret.ssh_private_key.arn
}

output "ssh_command" {
  description = "SSH command to connect to the instance (retrieve key from Secrets Manager first)"
  value       = "ssh -i /path/to/downloaded-key.pem ec2-user@${aws_instance.app.private_ip}"
}

output "iam_role_arn" {
  description = "ARN of the IAM role attached to the instance"
  value       = aws_iam_role.ec2_role.arn
}

output "security_group_id" {
  description = "ID of the security group"
  value       = aws_security_group.app_sg.id
}

output "retrieve_ssh_key_command" {
  description = "AWS CLI command to retrieve the SSH private key"
  value       = "aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.ssh_private_key.id} --query SecretString --output text > terraform-analyzer-key.pem && chmod 400 terraform-analyzer-key.pem"
}

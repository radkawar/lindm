# SPDX-License-Identifier: Apache-2.0
output "region" { value = var.region }
output "server_instance_id" { value = aws_instance.server.id }
output "device_instance_id" { value = try(aws_instance.device[0].id, null) }
output "console_hostname" { value = aws_eip.console.public_dns }
output "device_hostname" { value = aws_eip.device.public_dns }
output "console_origin" { value = "https://${aws_eip.console.public_dns}:443" }
output "device_origin" { value = "https://${aws_eip.device.public_dns}:443" }
output "database_endpoint" { value = aws_db_instance.deployment.address }
output "database_secret_arn" { value = aws_db_instance.deployment.master_user_secret[0].secret_arn }
output "database_identifier" { value = aws_db_instance.deployment.identifier }
output "vpc_id" { value = aws_vpc.deployment.id }

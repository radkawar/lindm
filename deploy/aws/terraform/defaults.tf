# SPDX-License-Identifier: Apache-2.0
# AWS creates these with each VPC. Adopt them so all owned, taggable resources
# carry the deployment tags. The unused default security group stays closed.
resource "aws_default_security_group" "deployment" {
  vpc_id = aws_vpc.deployment.id
  tags   = { Name = "${var.name}-unused-default" }
}

# Database subnets use this local-only table. The public subnet has its explicit
# Internet route table; do not add an Internet route to the default table.
resource "aws_default_route_table" "deployment" {
  default_route_table_id = aws_vpc.deployment.default_route_table_id
  tags                   = { Name = "${var.name}-private-default" }
}

# Preserve the VPC's stateless default ACL. Least-privilege security groups apply
# the listener and database policy; established replies need no SG egress rule.
resource "aws_default_network_acl" "deployment" {
  default_network_acl_id = aws_vpc.deployment.default_network_acl_id
  subnet_ids             = concat([aws_subnet.public.id], [for subnet in aws_subnet.database : subnet.id])
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  tags = { Name = "${var.name}-default" }
}

# RunInstances does not inherit the instance tags on its implicit primary ENI.
resource "aws_ec2_tag" "proof_device_network" {
  for_each = var.create_proof_device ? {
    project = "lindm"
    purpose = "ci-proof"
    Name    = "${var.name}-proof-device"
  } : {}
  resource_id = aws_instance.device[0].primary_network_interface_id
  key         = each.key
  value       = each.value
}

# The single-AZ RDS service interface does not inherit its database's tags.
data "aws_network_interface" "database" {
  filter {
    name   = "vpc-id"
    values = [aws_vpc.deployment.id]
  }
  filter {
    name   = "group-id"
    values = [aws_security_group.database.id]
  }
  filter {
    name   = "description"
    values = ["RDSNetworkInterface"]
  }
  depends_on = [aws_db_instance.deployment]
}
resource "aws_ec2_tag" "database_network" {
  for_each = {
    project = "lindm"
    purpose = "ci-proof"
    Name    = "${var.name}-database"
  }
  resource_id = data.aws_network_interface.database.id
  key         = each.key
  value       = each.value
}

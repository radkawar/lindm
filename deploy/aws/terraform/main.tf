# SPDX-License-Identifier: Apache-2.0
resource "aws_vpc" "deployment" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}
resource "aws_internet_gateway" "deployment" {
  vpc_id = aws_vpc.deployment.id
  tags   = { Name = var.name }
}
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.deployment.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = var.availability_zones[0]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-public" }
}
resource "aws_subnet" "database" {
  count             = 2
  vpc_id            = aws_vpc.deployment.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 1)
  availability_zone = var.availability_zones[count.index]
  tags              = { Name = "${var.name}-database-${count.index}" }
}
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.deployment.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.deployment.id
  }
  tags = { Name = "${var.name}-public" }
}
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
resource "aws_security_group" "server" {
  name        = "${var.name}-server"
  description = "HTTPS only; operator access uses SSM, not SSH"
  vpc_id      = aws_vpc.deployment.id
  tags        = { Name = "${var.name}-server" }
}
resource "aws_vpc_security_group_ingress_rule" "https" {
  count             = var.public_ingress_enabled ? 1 : 0
  security_group_id = aws_security_group.server.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
resource "aws_security_group" "device" {
  name        = "${var.name}-device"
  description = "Proof agent; no inbound connections"
  vpc_id      = aws_vpc.deployment.id
  tags        = { Name = "${var.name}-device" }
}
resource "aws_security_group" "database" {
  name        = "${var.name}-database"
  description = "Private PostgreSQL reachable only by lindm server"
  vpc_id      = aws_vpc.deployment.id
  tags        = { Name = "${var.name}-database" }
}
resource "aws_vpc_security_group_ingress_rule" "postgres" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.server.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}
resource "aws_vpc_security_group_egress_rule" "server_postgres" {
  security_group_id            = aws_security_group.server.id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}
resource "aws_vpc_security_group_egress_rule" "https" {
  for_each          = { server = aws_security_group.server.id, device = aws_security_group.device.id }
  security_group_id = each.value
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
# Ubuntu's authenticated distribution repositories also use HTTP transports.
# APT verifies signed repository metadata and package hashes independently.
resource "aws_vpc_security_group_egress_rule" "apt" {
  for_each          = { server = aws_security_group.server.id, device = aws_security_group.device.id }
  security_group_id = each.value
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}
resource "aws_db_subnet_group" "deployment" {
  name       = var.name
  subnet_ids = aws_subnet.database[*].id
  tags       = { Name = var.name }
}
resource "aws_db_parameter_group" "deployment" {
  name   = var.name
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }
  parameter {
    name  = "rds.accepted_password_auth_method"
    value = "scram"
  }
  tags = { Name = var.name }
}
resource "aws_db_instance" "deployment" {
  identifier                  = var.name
  engine                      = "postgres"
  engine_version              = var.database_engine_version
  instance_class              = var.database_instance_class
  allocated_storage           = 20
  storage_type                = "gp3"
  storage_encrypted           = true
  username                    = "lindm_admin"
  manage_master_user_password = true
  db_name                     = "postgres"
  db_subnet_group_name        = aws_db_subnet_group.deployment.name
  vpc_security_group_ids      = [aws_security_group.database.id]
  parameter_group_name        = aws_db_parameter_group.deployment.name
  publicly_accessible         = false
  multi_az                    = false
  backup_retention_period     = 1
  auto_minor_version_upgrade  = false
  deletion_protection         = false
  skip_final_snapshot         = true
  delete_automated_backups    = true
  copy_tags_to_snapshot       = true
  tags                        = { Name = var.name }
  depends_on                  = [aws_default_network_acl.deployment]
}
resource "aws_iam_role" "instance" {
  for_each = toset(["server", "device"])
  name     = "${var.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = { Name = "${var.name}-${each.key}" }
}
resource "aws_iam_role_policy_attachment" "ssm" {
  for_each   = aws_iam_role.instance
  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_role_policy" "database_secret" {
  name = "database-bootstrap"
  role = aws_iam_role.instance["server"].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = aws_db_instance.deployment.master_user_secret[0].secret_arn }]
  })
}
resource "aws_iam_instance_profile" "instance" {
  for_each = aws_iam_role.instance
  name     = each.value.name
  role     = each.value.name
  tags     = { Name = each.value.name }
}
resource "aws_network_interface" "server" {
  subnet_id         = aws_subnet.public.id
  private_ips_count = 1
  security_groups   = [aws_security_group.server.id]
  tags              = { Name = "${var.name}-server" }
}
resource "aws_instance" "server" {
  ami                  = var.ami_id
  instance_type        = var.server_instance_type
  iam_instance_profile = aws_iam_instance_profile.instance["server"].name
  primary_network_interface {
    network_interface_id = aws_network_interface.server.id
  }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    volume_size           = 40
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
    tags                  = { project = "lindm", purpose = "ci-proof", Name = "${var.name}-server" }
  }
  user_data  = <<-USERDATA
    #!/bin/sh
    set -eu
    systemctl disable --now ssh.service ssh.socket || true
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3-psycopg python3-boto3 haproxy ca-certificates curl gpg iptables age
    cat > /etc/systemd/system/lindm-imds-guard.service <<'IMDSUNIT'
    [Unit]
    Description=Limit EC2 instance credentials to root processes
    After=network.target
    Before=lindmd.service
    [Service]
    Type=oneshot
    RemainAfterExit=yes
    ExecStart=/usr/sbin/iptables -w -I OUTPUT 1 -d 169.254.169.254/32 -m owner ! --uid-owner 0 -j REJECT
    ExecStop=/usr/sbin/iptables -w -D OUTPUT -d 169.254.169.254/32 -m owner ! --uid-owner 0 -j REJECT
    [Install]
    WantedBy=multi-user.target
    IMDSUNIT
    systemctl daemon-reload
    systemctl enable --now lindm-imds-guard.service
    systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service
  USERDATA
  tags       = { Name = "${var.name}-server" }
  depends_on = [aws_route_table_association.public, aws_default_network_acl.deployment, aws_iam_role_policy_attachment.ssm, aws_eip.console, aws_eip.device]
}
resource "aws_eip" "console" {
  domain                    = "vpc"
  network_interface         = aws_network_interface.server.id
  associate_with_private_ip = aws_network_interface.server.private_ip
  tags                      = { Name = "${var.name}-console" }
  depends_on                = [aws_internet_gateway.deployment]
}
resource "aws_eip" "device" {
  domain                    = "vpc"
  network_interface         = aws_network_interface.server.id
  associate_with_private_ip = one(setsubtract(aws_network_interface.server.private_ips, [aws_network_interface.server.private_ip]))
  tags                      = { Name = "${var.name}-device" }
  depends_on                = [aws_internet_gateway.deployment]
}
resource "aws_instance" "device" {
  count                       = var.create_proof_device ? 1 : 0
  ami                         = var.ami_id
  instance_type               = var.device_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.device.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.instance["device"].name
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
    tags                  = { project = "lindm", purpose = "ci-proof", Name = "${var.name}-proof-device" }
  }
  user_data  = <<-USERDATA
    #!/bin/sh
    set -eu
    systemctl disable --now ssh.service ssh.socket || true
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y age ca-certificates curl
    systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service
  USERDATA
  tags       = { Name = "${var.name}-proof-device" }
  depends_on = [aws_route_table_association.public, aws_default_network_acl.deployment, aws_iam_role_policy_attachment.ssm]
}

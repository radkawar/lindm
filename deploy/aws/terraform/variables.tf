# SPDX-License-Identifier: Apache-2.0
variable "region" {
  type    = string
  default = "us-east-1"
}
variable "aws_profile" {
  type    = string
  default = "default"
}
variable "name" {
  description = "Unique deployment prefix. All resources use this prefix."
  type        = string
  default     = "lindm-ci-proof"
  validation {
    # The provider's S3 bucket_prefix limit is 37; "-release-" uses nine.
    condition = (
      can(regex("^[a-z][a-z0-9-]{2,27}$", var.name)) &&
      !strcontains(var.name, "--") &&
      !endswith(var.name, "-") &&
      !startswith(var.name, "sg-")
    )
    error_message = "Use 3 to 28 lowercase letters, digits or hyphens, starting with a letter. Do not repeat or end with a hyphen, or start with sg-."
  }
}
variable "ami_id" {
  description = "Independently selected Canonical Ubuntu 24.04 amd64 AMI in this region."
  type        = string
}
variable "availability_zones" {
  description = "Two availability zones in the selected region for the private RDS subnet group."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
  validation {
    condition     = length(var.availability_zones) == 2 && var.availability_zones[0] != var.availability_zones[1]
    error_message = "Supply two distinct availability zones."
  }
}
variable "vpc_cidr" {
  type    = string
  default = "10.194.0.0/16"
}
variable "server_instance_type" {
  type    = string
  default = "t3.medium"
}
variable "device_instance_type" {
  type    = string
  default = "t3.small"
}
variable "create_proof_device" {
  description = "Create the second Ubuntu instance for actual console-command enrollment."
  type        = bool
  default     = true
}
variable "public_ingress_enabled" {
  description = "Set false and apply before fenced backup or restore. Both HTTPS origins share this rule."
  type        = bool
  default     = true
}
variable "database_instance_class" {
  type    = string
  default = "db.t4g.micro"
}
variable "database_engine_version" {
  type    = string
  default = "18.6"
}
variable "database_parameter_family" {
  type    = string
  default = "postgres18"
}
variable "allowed_account_id" {
  description = "Account guard. Change deliberately before using another account."
  type        = string
  default     = "050451401320"
}

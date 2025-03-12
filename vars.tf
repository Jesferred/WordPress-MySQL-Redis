variable "region" {
  default     = "eu-west-1"
  description = "region"
}

variable "common_tags" {
  type = map(any)
  default = {
    App       = "Test"
    CreatedBy = "Terraform"
  }
  description = "common tags to apply to all resources"
}

variable "vpc_cidr" {
  default     = "10.0.0.0/16"
  description = "vpc cidr"
}

variable "allow_ports_default" {
  description = "allow_ports"
  type        = list(any)
  default     = ["80", "443", "22"]
}

variable "allow_ports_ec2_rds" {
  description = "allow_ports ec2 rds"
  type        = list(any)
  default     = ["3306"]
}


variable "allow_ports_ec2_elasticache" {
  description = "allow_ports ec2 elasticache"
  type        = list(any)
  default     = ["6379"]
}

variable "allow_ports_all" {
  description = "allow all ports"
  type        = list(any)
  default     = ["-1"]

}

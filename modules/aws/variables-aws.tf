variable "aws" {
  description = "AWS provider customization"
  type        = any
  default     = {}
}

variable "aws-for-fluent-bit" {
  description = "Customize aws-for-fluent-bit helm chart, see `aws-fluent-bit.tf`"
  type        = any
  default     = {}
}

variable "aws-load-balancer-controller" {
  description = "Customize aws-load-balancer-controller chart, see `aws-load-balancer-controller.tf` for supported values"
  type        = any
  default     = {}
}

variable "aws-node-termination-handler" {
  description = "Customize aws-node-termination-handler chart, see `aws-node-termination-handler.tf`"
  type        = any
  default     = {}
}

variable "calico" {
  description = "Customize calico helm chart, see `calico.tf`"
  type        = any
  default     = {}
}

variable "eks" {
  description = "EKS cluster inputs"
  type        = any
  default     = {}
}

variable "tags" {
  description = "Map of tags for AWS resources"
  type        = map
  default     = {}
}

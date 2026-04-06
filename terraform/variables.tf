variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
  default     = "rg-sentinel-siem"
}

variable "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  type        = string
  default     = "law-sentinel-siem"
}

variable "log_analytics_sku" {
  description = "SKU for Log Analytics workspace"
  type        = string
  default     = "PerGB2018"
}

variable "log_analytics_retention_days" {
  description = "Retention period in days for Log Analytics"
  type        = number
  default     = 90
}

variable "alert_email" {
  description = "Email address for incident alert notifications"
  type        = string
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL for notifications"
  type        = string
  sensitive   = true
}

variable "nsg_name" {
  description = "Name of the NSG used for IP blocking playbook"
  type        = string
  default     = "nsg-sentinel-block"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "Azure-Sentinel-SIEM"
    Environment = "Production"
    ManagedBy   = "Terraform"
    Owner       = "Addison"
  }
}

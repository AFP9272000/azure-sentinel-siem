output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.sentinel.name
}

output "resource_group_id" {
  description = "ID of the resource group"
  value       = azurerm_resource_group.sentinel.id
}

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.sentinel.id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.sentinel.name
}

output "log_analytics_workspace_key" {
  description = "Primary shared key of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.sentinel.primary_shared_key
  sensitive   = true
}

output "sentinel_workspace_id" {
  description = "Sentinel onboarding workspace ID"
  value       = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
}

output "nsg_id" {
  description = "ID of the NSG for IP blocking"
  value       = azurerm_network_security_group.block.id
}

output "subscription_id" {
  description = "Current subscription ID"
  value       = data.azurerm_subscription.current.subscription_id
}

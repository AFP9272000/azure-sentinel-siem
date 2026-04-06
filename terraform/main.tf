# =============================================================================
# Azure Sentinel SIEM with Automated Response
# Terraform Configuration - Core Infrastructure
# =============================================================================

data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

# -----------------------------------------------------------------------------
# Resource Group
# -----------------------------------------------------------------------------
resource "azurerm_resource_group" "sentinel" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# -----------------------------------------------------------------------------
# Log Analytics Workspace (Sentinel backend)
# -----------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "sentinel" {
  name                = var.log_analytics_workspace_name
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  sku                 = var.log_analytics_sku
  retention_in_days   = var.log_analytics_retention_days
  tags                = var.tags
}

# -----------------------------------------------------------------------------
# Microsoft Sentinel (onboarding)
# -----------------------------------------------------------------------------
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id                 = azurerm_log_analytics_workspace.sentinel.id
  customer_managed_key_enabled = false
}

# -----------------------------------------------------------------------------
# Network Security Group (for IP blocking playbook)
# -----------------------------------------------------------------------------
resource "azurerm_network_security_group" "block" {
  name                = var.nsg_name
  location            = azurerm_resource_group.sentinel.location
  resource_group_name = azurerm_resource_group.sentinel.name
  tags                = var.tags
}

# -----------------------------------------------------------------------------
# Diagnostic Settings - Azure Activity Log to Log Analytics
# Uses PowerShell scripts to avoid shell escaping issues with local-exec
# -----------------------------------------------------------------------------
resource "null_resource" "activity_log_diagnostic" {
  provisioner "local-exec" {
    command     = "powershell -ExecutionPolicy Bypass -File ${path.module}/scripts/setup-activity-logs.ps1 -WorkspaceId '${azurerm_log_analytics_workspace.sentinel.id}' -Location '${var.location}'"
    interpreter = ["powershell", "-Command"]
  }

  depends_on = [azurerm_log_analytics_workspace.sentinel]
}

# -----------------------------------------------------------------------------
# Diagnostic Settings - Entra ID Audit Logs to Log Analytics
# -----------------------------------------------------------------------------
resource "null_resource" "entra_audit_log_diagnostic" {
  provisioner "local-exec" {
    command     = "powershell -ExecutionPolicy Bypass -File ${path.module}/scripts/setup-entra-logs.ps1 -WorkspaceId '${azurerm_log_analytics_workspace.sentinel.id}'"
    interpreter = ["powershell", "-Command"]
  }

  depends_on = [azurerm_log_analytics_workspace.sentinel]
}

# -----------------------------------------------------------------------------
# RBAC - Sentinel Responder role for automation
# -----------------------------------------------------------------------------
resource "azurerm_role_assignment" "sentinel_responder" {
  scope                = azurerm_resource_group.sentinel.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "sentinel_automation_contributor" {
  scope                = azurerm_resource_group.sentinel.id
  role_definition_name = "Microsoft Sentinel Automation Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

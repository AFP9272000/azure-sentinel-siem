// Sentinel Data Connectors
// Azure Activity and Entra ID log routing is handled via Terraform (main.tf)
// using diagnostic settings. This module enables additional Sentinel connectors.

param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// Data Connector: Microsoft Defender for Cloud
// Connects subscription-level security alerts
// Note: Requires Defender for Cloud plans to be enabled on the subscription

resource defenderConnector 'Microsoft.SecurityInsights/dataConnectors@2023-11-01' = {
  name: guid('connector-defender-cloud', workspace.id)
  scope: workspace
  kind: 'AzureSecurityCenter'
  properties: {
    subscriptionId: subscription().subscriptionId
    dataTypes: {
      alerts: {
        state: 'Enabled'
      }
    }
  }
}

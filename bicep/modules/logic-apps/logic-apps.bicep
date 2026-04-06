// Logic Apps Playbooks: Automated Response

param location string
@secure()
param alertEmail string
@secure()
param slackWebhookUrl string
param subscriptionId string
param resourceGroupName string
param nsgName string

// Sentinel API Connection (shared by all playbooks)

@description('API connection for Microsoft Sentinel')
resource sentinelConnection 'Microsoft.Web/connections@2016-06-01' = {
  name: 'azuresentinel-connection'
  location: location
  properties: {
    displayName: 'Azure Sentinel'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
  }
}

// Playbook 1: Email Alert

resource emailPlaybook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'Playbook-EmailAlert'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            body: {
              callback_url: '@listCallbackUrl()'
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Send_email: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'outlook\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/v2/Mail'
            body: {
              To: alertEmail
              Subject: 'Sentinel Alert: @{triggerBody()?[\'object\']?[\'properties\']?[\'title\']} - @{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}'
              Body: '<p><strong>SENTINEL INCIDENT ALERT</strong><br><br><strong>Title:</strong> @{triggerBody()?[\'object\']?[\'properties\']?[\'title\']}<br><strong>Severity:</strong> @{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}<br><strong>Status:</strong> @{triggerBody()?[\'object\']?[\'properties\']?[\'status\']?[\'value\']}<br><strong>Created:</strong> @{triggerBody()?[\'object\']?[\'properties\']?[\'createdTimeUtc\']}<br><br><strong>Description:</strong><br>@{triggerBody()?[\'object\']?[\'properties\']?[\'description\']}<br><br><strong>Incident Link:</strong><br>@{triggerBody()?[\'object\']?[\'properties\']?[\'incidentUrl\']}</p>'
              Importance: 'High'
            }
          }
        }
      }
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
    }
  }
}

// Playbook 2: Slack Notification

resource slackPlaybook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'Playbook-SlackNotification'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            body: {
              callback_url: '@listCallbackUrl()'
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Post_to_Slack: {
          type: 'Http'
          inputs: {
            method: 'POST'
            uri: slackWebhookUrl
            headers: {
              'Content-Type': 'application/json'
            }
            body: {
              text: 'SENTINEL INCIDENT\n\nTitle: @{triggerBody()?[\'object\']?[\'properties\']?[\'title\']}\nSeverity: @{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}\nStatus: @{triggerBody()?[\'object\']?[\'properties\']?[\'status\']?[\'value\']}\nDescription: @{triggerBody()?[\'object\']?[\'properties\']?[\'description\']}\n\nLink: @{triggerBody()?[\'object\']?[\'properties\']?[\'incidentUrl\']}'
            }
          }
        }
      }
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
    }
  }
}

// Playbook 3: Auto-Disable Compromised User

resource disableUserPlaybook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'Playbook-DisableUser'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            body: {
              callback_url: '@listCallbackUrl()'
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Get_Accounts: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/entities/account'
            body: {
              entities: '@triggerBody()?[\'object\']?[\'properties\']?[\'relatedEntities\']'
            }
          }
        }
        Disable_User: {
          type: 'Http'
          inputs: {
            method: 'PATCH'
            uri: 'https://graph.microsoft.com/v1.0/users/@{body(\'Get_Accounts\')?[\'Accounts\']?[0]?[\'AadUserId\']}'
            headers: {
              'Content-Type': 'application/json'
            }
            body: {
              accountEnabled: false
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: 'https://graph.microsoft.com'
            }
          }
          runAfter: {
            Get_Accounts: ['Succeeded']
          }
        }
      }
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
    }
  }
}

// Playbook 4: Auto-Block IP in NSG

resource blockIpPlaybook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'Playbook-BlockIP'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            body: {
              callback_url: '@listCallbackUrl()'
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Get_IPs: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/entities/ip'
            body: {
              entities: '@triggerBody()?[\'object\']?[\'properties\']?[\'relatedEntities\']'
            }
          }
        }
        Block_IP_in_NSG: {
          type: 'Http'
          inputs: {
            method: 'PUT'
            uri: 'https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}/providers/Microsoft.Network/networkSecurityGroups/${nsgName}/securityRules/Block-@{body(\'Get_IPs\')?[\'IPs\']?[0]?[\'Address\']}?api-version=2023-04-01'
            headers: {
              'Content-Type': 'application/json'
            }
            body: {
              properties: {
                protocol: '*'
                sourceAddressPrefix: '@{body(\'Get_IPs\')?[\'IPs\']?[0]?[\'Address\']}'
                destinationAddressPrefix: '*'
                access: 'Deny'
                priority: 200
                direction: 'Inbound'
                sourcePortRange: '*'
                destinationPortRange: '*'
              }
            }
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: 'https://management.azure.com'
            }
          }
          runAfter: {
            Get_IPs: ['Succeeded']
          }
        }
      }
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: sentinelConnection.name
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
        }
      }
    }
  }
}

// RBAC: Network Contributor for Block IP playbook

resource blockIpNetworkRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('block-ip-network-contributor', blockIpPlaybook.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7') // Network Contributor
    principalId: blockIpPlaybook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// RBAC: Sentinel Responder for all playbooks

resource emailSentinelRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('email-sentinel-responder', emailPlaybook.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150937-b8fe-4cfb-8069-0eaf05ecd056') // Sentinel Responder
    principalId: emailPlaybook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource slackSentinelRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('slack-sentinel-responder', slackPlaybook.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150937-b8fe-4cfb-8069-0eaf05ecd056')
    principalId: slackPlaybook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource disableUserSentinelRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('disable-user-sentinel-responder', disableUserPlaybook.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150937-b8fe-4cfb-8069-0eaf05ecd056')
    principalId: disableUserPlaybook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource blockIpSentinelRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('block-ip-sentinel-responder', blockIpPlaybook.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150937-b8fe-4cfb-8069-0eaf05ecd056')
    principalId: blockIpPlaybook.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs

output emailPlaybookId string = emailPlaybook.id
output slackPlaybookId string = slackPlaybook.id
output disableUserPlaybookId string = disableUserPlaybook.id
output blockIpPlaybookId string = blockIpPlaybook.id
output disableUserPrincipalId string = disableUserPlaybook.identity.principalId

// Sentinel Analytics Rules - Custom KQL Detection Rules
// 11 rules covering 8 MITRE ATT&CK tactics

param workspaceName string
param location string

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// Rule 1: Resource Deletion Spree (Impact - T1485)

resource rule1 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-resource-deletion-spree', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Resource Deletion Spree'
    description: '#INC_CORR# Detects when a user deletes 5 or more Azure resources within a 15-minute window, which may indicate a compromised account or malicious insider. MITRE: Impact/T1485'
    severity: 'High'
    enabled: true
    query: '''
      AzureActivity
      | where OperationNameValue endswith "DELETE"
      | where ActivityStatusValue == "Success"
      | summarize 
          DeleteCount = count(),
          ResourcesDeleted = make_set(Resource),
          OperationNames = make_set(OperationNameValue)
          by CallerIpAddress, Caller, bin(TimeGenerated, 15m)
      | where DeleteCount >= 5
      | extend 
          RiskScore = case(
              DeleteCount >= 20, 100,
              DeleteCount >= 10, 75,
              DeleteCount >= 5, 50,
              25
          ),
          MITRETactic = "Impact",
          MITRETechnique = "T1485"
    '''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['Impact']
    techniques: ['T1485']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      DeleteCount: 'DeleteCount'
      RiskScore: 'RiskScore'
      ResourcesDeleted: 'ResourcesDeleted'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Resource Deletion Spree - {{Caller}} deleted {{DeleteCount}} resources'
      alertDescriptionFormat: 'User {{Caller}} from IP {{CallerIpAddress}} deleted {{DeleteCount}} resources in 15 minutes. MITRE: Impact/T1485'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 2: RBAC Privilege Escalation (Privilege Escalation - T1078.004)

resource rule2 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-rbac-privilege-escalation', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'RBAC Privilege Escalation'
    description: '#INC_CORR# Detects assignment of high-privilege roles (Owner, Contributor, User Access Administrator). MITRE: PrivilegeEscalation/T1078.004'
    severity: 'High'
    enabled: true
    query: '''
      AzureActivity
      | where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
      | where ActivityStatusValue == "Success"
      | extend ParsedProps = parse_json(Properties)
      | extend RoleDefinitionId = tostring(ParsedProps.requestbody)
      | where RoleDefinitionId has_any ("Owner", "Contributor", "User Access Administrator")
      | extend
          RiskScore = case(
              RoleDefinitionId has "Owner", 100,
              RoleDefinitionId has "User Access Administrator", 90,
              RoleDefinitionId has "Contributor", 70,
              50
          ),
          MITRETactic = "PrivilegeEscalation",
          MITRETechnique = "T1078.004"
      | project TimeGenerated, Caller, CallerIpAddress, RoleDefinitionId, ResourceGroup, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT30M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['PrivilegeEscalation']
    techniques: ['T1078']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      RoleDefinitionId: 'RoleDefinitionId'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Privilege Escalation - {{Caller}} assigned high-privilege role'
      alertDescriptionFormat: 'User {{Caller}} from {{CallerIpAddress}} assigned a high-privilege role. MITRE: PrivilegeEscalation/T1078.004'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 3: NSG Rule Modification (Defense Evasion - T1562.007)

resource rule3 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-nsg-modification', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'NSG Rule Modification'
    description: '#INC_CORR# Detects modifications to Network Security Group rules. MITRE: DefenseEvasion/T1562.007'
    severity: 'Medium'
    enabled: true
    query: '''
      AzureActivity
      | where OperationNameValue in (
          "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
          "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE",
          "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE"
      )
      | where ActivityStatusValue == "Success"
      | extend
          RiskScore = case(
              OperationNameValue has "DELETE", 85,
              OperationNameValue has "SECURITYRULES/WRITE", 70,
              60
          ),
          MITRETactic = "DefenseEvasion",
          MITRETechnique = "T1562.007"
      | project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, Resource, ResourceGroup, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['DefenseEvasion']
    techniques: ['T1562']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      OperationName: 'OperationNameValue'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'NSG Modification - {{Caller}} modified firewall rules'
      alertDescriptionFormat: 'User {{Caller}} from {{CallerIpAddress}} modified NSG rules ({{OperationNameValue}}). MITRE: DefenseEvasion/T1562.007'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 4: Diagnostic Settings Tampering (Defense Evasion - T1562.008)

resource rule4 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-diagnostic-tampering', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Diagnostic Settings Tampering'
    description: '#INC_CORR# Detects deletion or modification of diagnostic settings, indicating an attacker may be covering their tracks. MITRE: DefenseEvasion/T1562.008'
    severity: 'High'
    enabled: true
    query: '''
      AzureActivity
      | where OperationNameValue in (
          "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
          "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE"
      )
      | where ActivityStatusValue == "Success"
      | extend
          RiskScore = case(
              OperationNameValue has "DELETE", 95,
              75
          ),
          ActionType = case(
              OperationNameValue has "DELETE", "Deleted diagnostic setting",
              "Modified diagnostic setting"
          ),
          MITRETactic = "DefenseEvasion",
          MITRETechnique = "T1562.008"
      | project TimeGenerated, Caller, CallerIpAddress, ActionType, Resource, ResourceGroup, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT10M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['DefenseEvasion']
    techniques: ['T1562']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      ActionType: 'ActionType'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Log Tampering - {{Caller}} {{ActionType}}'
      alertDescriptionFormat: 'User {{Caller}} from {{CallerIpAddress}} {{ActionType}}. May indicate an attacker covering tracks. MITRE: DefenseEvasion/T1562.008'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 5: Key Vault Suspicious Access (Credential Access - T1555)

resource rule5 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-keyvault-suspicious', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Key Vault Suspicious Access'
    description: '#INC_CORR# Detects suspicious Key Vault operations including deletion, access policy changes, and secret modifications. MITRE: CredentialAccess/T1555'
    severity: 'High'
    enabled: true
    query: '''
      AzureActivity
      | where OperationNameValue in (
          "MICROSOFT.KEYVAULT/VAULTS/DELETE",
          "MICROSOFT.KEYVAULT/VAULTS/WRITE",
          "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE",
          "MICROSOFT.KEYVAULT/VAULTS/SECRETS/WRITE"
      )
      | where ActivityStatusValue == "Success"
      | extend
          RiskScore = case(
              OperationNameValue has "DELETE", 100,
              OperationNameValue has "ACCESSPOLICIES", 85,
              OperationNameValue has "SECRETS", 80,
              60
          ),
          ActionType = case(
              OperationNameValue has "DELETE", "Key Vault Deleted",
              OperationNameValue has "ACCESSPOLICIES", "Access Policy Modified",
              OperationNameValue has "SECRETS", "Secret Modified",
              "Key Vault Modified"
          ),
          MITRETactic = "CredentialAccess",
          MITRETechnique = "T1555"
      | project TimeGenerated, Caller, CallerIpAddress, ActionType, Resource, ResourceGroup, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['CredentialAccess']
    techniques: ['T1555']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      ActionType: 'ActionType'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Key Vault Alert - {{Caller}} {{ActionType}}'
      alertDescriptionFormat: 'User {{Caller}} performed {{ActionType}} on {{Resource}}. MITRE: CredentialAccess/T1555'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 6: Policy Deletion or Exemption (Defense Evasion - T1562)

resource rule6 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-policy-tampering', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Policy Deletion or Exemption'
    description: '#INC_CORR# Detects deletion of policy definitions/assignments or creation of policy exemptions. MITRE: DefenseEvasion/T1562'
    severity: 'Medium'
    enabled: true
    query: '''
      AzureActivity
      | where OperationNameValue in (
          "MICROSOFT.AUTHORIZATION/POLICYDEFINITIONS/DELETE",
          "MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/DELETE",
          "MICROSOFT.AUTHORIZATION/POLICYEXEMPTIONS/WRITE",
          "MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/WRITE"
      )
      | where ActivityStatusValue == "Success"
      | extend
          RiskScore = case(
              OperationNameValue has "DELETE", 90,
              OperationNameValue has "EXEMPTIONS", 85,
              65
          ),
          ActionType = case(
              OperationNameValue has "POLICYDEFINITIONS/DELETE", "Policy Definition Deleted",
              OperationNameValue has "POLICYASSIGNMENTS/DELETE", "Policy Assignment Removed",
              OperationNameValue has "EXEMPTIONS", "Policy Exemption Created",
              "Policy Assignment Modified"
          ),
          MITRETactic = "DefenseEvasion",
          MITRETechnique = "T1562"
      | project TimeGenerated, Caller, CallerIpAddress, ActionType, Resource, ResourceGroup, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT30M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['DefenseEvasion']
    techniques: ['T1562']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      ActionType: 'ActionType'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Policy Tampering - {{Caller}} {{ActionType}}'
      alertDescriptionFormat: 'User {{Caller}} from {{CallerIpAddress}} performed {{ActionType}}. MITRE: DefenseEvasion/T1562'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 7: Storage Account Public Access Change (Exfiltration - T1537)

resource rule7 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-storage-exposure', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Storage Account Public Access Change'
    description: '#INC_CORR# Detects modifications to storage account public access settings. MITRE: Exfiltration/T1537'
    severity: 'High'
    enabled: true
    query: '''
      AzureActivity
      | where OperationNameValue in (
          "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
          "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE"
      )
      | where ActivityStatusValue == "Success"
      | extend ParsedProps = parse_json(Properties)
      | extend RequestBody = tostring(ParsedProps.requestbody)
      | where RequestBody has_any (
          "publicAccess",
          "allowBlobPublicAccess",
          "networkAcls",
          "defaultAction"
      )
      | extend
          RiskScore = case(
              RequestBody has "publicAccess", 90,
              RequestBody has "allowBlobPublicAccess", 90,
              RequestBody has "defaultAction", 75,
              60
          ),
          MITRETactic = "Exfiltration",
          MITRETechnique = "T1537"
      | project TimeGenerated, Caller, CallerIpAddress, RequestBody, Resource, ResourceGroup, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['Exfiltration']
    techniques: ['T1537']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Storage Exposure - {{Caller}} modified public access on {{Resource}}'
      alertDescriptionFormat: 'User {{Caller}} from {{CallerIpAddress}} modified storage access on {{Resource}}. MITRE: Exfiltration/T1537'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 8: Mass VM Deployment / Cryptomining (Execution - T1496)

resource rule8 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-mass-vm-deployment', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Mass VM Deployment - Cryptomining Signal'
    description: '#INC_CORR# Detects rapid deployment of 3+ VMs in a 30-minute window. MITRE: Execution/T1496'
    severity: 'High'
    enabled: true
    query: '''
      AzureActivity
      | where OperationNameValue has "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE"
      | where ActivityStatusValue == "Success"
      | summarize
          VMCount = count(),
          ResourcesCreated = make_set(Resource),
          Regions = make_set(ActivitySubstatusValue)
          by Caller, CallerIpAddress, bin(TimeGenerated, 30m)
      | where VMCount >= 3
      | extend
          RiskScore = case(
              VMCount >= 10, 100,
              VMCount >= 5, 85,
              VMCount >= 3, 70,
              50
          ),
          MITRETactic = "Execution",
          MITRETechnique = "T1496"
      | project TimeGenerated, Caller, CallerIpAddress, VMCount, ResourcesCreated, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT30M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['Impact']
    techniques: ['T1496']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      VMCount: 'VMCount'
      ResourcesCreated: 'ResourcesCreated'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Mass VM Deployment - {{Caller}} created {{VMCount}} VMs in 30 minutes'
      alertDescriptionFormat: 'User {{Caller}} from {{CallerIpAddress}} deployed {{VMCount}} VMs in 30 minutes. MITRE: Execution/T1496'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 9: Unusual Admin Operations from New IP (Initial Access - T1078)

resource rule9 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-new-ip-admin', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Unusual Admin Operations from New IP'
    description: '#INC_CORR# Detects administrative operations from IP addresses not seen in the past 14 days. MITRE: InitialAccess/T1078'
    severity: 'Medium'
    enabled: true
    query: '''
      let KnownAdminIPs = 
          AzureActivity
          | where TimeGenerated between (ago(14d) .. ago(1d))
          | where OperationNameValue has_any ("WRITE", "DELETE", "ACTION")
          | where ActivityStatusValue == "Success"
          | distinct CallerIpAddress;
      AzureActivity
      | where TimeGenerated > ago(1d)
      | where OperationNameValue has_any ("WRITE", "DELETE", "ACTION")
      | where ActivityStatusValue == "Success"
      | where CallerIpAddress !in (KnownAdminIPs)
      | where CallerIpAddress != ""
      | summarize
          OperationCount = count(),
          Operations = make_set(OperationNameValue),
          Resources = make_set(Resource)
          by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
      | where OperationCount >= 3
      | extend
          RiskScore = case(
              OperationCount >= 15, 95,
              OperationCount >= 10, 80,
              OperationCount >= 5, 65,
              50
          ),
          MITRETactic = "InitialAccess",
          MITRETechnique = "T1078"
      | project TimeGenerated, Caller, CallerIpAddress, OperationCount, Operations, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['InitialAccess']
    techniques: ['T1078']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'Caller' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'CallerIpAddress' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      OperationCount: 'OperationCount'
      Operations: 'Operations'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'New IP Admin Activity - {{Caller}} from unfamiliar IP {{CallerIpAddress}}'
      alertDescriptionFormat: 'User {{Caller}} performed {{OperationCount}} admin operations from IP {{CallerIpAddress}} not seen in 14 days. MITRE: InitialAccess/T1078'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 10: Service Principal Credential Added (Persistence - T1098.001)

resource rule10 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-sp-credential-added', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Service Principal Credential Added'
    description: '#INC_CORR# Detects when new credentials are added to a service principal or application. MITRE: Persistence/T1098.001'
    severity: 'High'
    enabled: true
    query: '''
      AuditLogs
      | where OperationName in (
          "Add service principal credentials",
          "Update application – Certificates and secrets management"
      )
      | where Result == "success"
      | extend
          InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
          InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
          TargetApp = tostring(TargetResources[0].displayName),
          TargetAppId = tostring(TargetResources[0].id)
      | extend
          RiskScore = case(
              OperationName has "service principal", 90,
              80
          ),
          MITRETactic = "Persistence",
          MITRETechnique = "T1098.001"
      | project TimeGenerated, InitiatedBy, InitiatedByIP, OperationName, TargetApp, TargetAppId, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT30M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['Persistence']
    techniques: ['T1098']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'InitiatedBy' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'InitiatedByIP' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      TargetApp: 'TargetApp'
      OperationName: 'OperationName'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'New Credential Added - {{InitiatedBy}} added credentials to {{TargetApp}}'
      alertDescriptionFormat: 'User {{InitiatedBy}} from {{InitiatedByIP}} added credentials to {{TargetApp}}. MITRE: Persistence/T1098.001'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

// Rule 11: User/Group Modification Spree (Persistence - T1098)

resource rule11 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  name: guid('rule-identity-modification-spree', workspace.id)
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'Identity Modification Spree'
    description: '#INC_CORR# Detects rapid user/group modifications (5+ changes in 30 minutes). MITRE: Persistence/T1098'
    severity: 'Medium'
    enabled: true
    query: '''
      AuditLogs
      | where OperationName has_any (
          "Add member to group",
          "Remove member from group",
          "Add user",
          "Delete user",
          "Update user",
          "Add owner to group",
          "Add member to role"
      )
      | where Result == "success"
      | extend
          InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
          InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
          TargetName = tostring(TargetResources[0].displayName)
      | summarize
          ModificationCount = count(),
          Operations = make_set(OperationName),
          Targets = make_set(TargetName)
          by InitiatedBy, InitiatedByIP, bin(TimeGenerated, 30m)
      | where ModificationCount >= 5
      | extend
          RiskScore = case(
              ModificationCount >= 20, 100,
              ModificationCount >= 10, 85,
              ModificationCount >= 5, 65,
              50
          ),
          MITRETactic = "Persistence",
          MITRETechnique = "T1098"
      | project TimeGenerated, InitiatedBy, InitiatedByIP, ModificationCount, Operations, Targets, RiskScore, MITRETactic, MITRETechnique
    '''
    queryFrequency: 'PT30M'
    queryPeriod: 'PT30M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: ['Persistence']
    techniques: ['T1098']
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          { identifier: 'FullName', columnName: 'InitiatedBy' }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          { identifier: 'Address', columnName: 'InitiatedByIP' }
        ]
      }
    ]
    customDetails: {
      RiskScore: 'RiskScore'
      ModificationCount: 'ModificationCount'
      Operations: 'Operations'
      Targets: 'Targets'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Identity Modification Spree - {{InitiatedBy}} made {{ModificationCount}} changes'
      alertDescriptionFormat: 'User {{InitiatedBy}} from {{InitiatedByIP}} made {{ModificationCount}} identity changes in 30 minutes. MITRE: Persistence/T1098'
    }
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
}

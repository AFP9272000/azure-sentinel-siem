// Sentinel Automation Rules - Connect Playbooks to Incidents

param workspaceName string
param emailPlaybookId string
param slackPlaybookId string
param disableUserPlaybookId string
param blockIpPlaybookId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// Automation Rule: Email Alert on All Incidents

resource autoRuleEmail 'Microsoft.SecurityInsights/automationRules@2023-11-01' = {
  name: guid('auto-rule-email', workspace.id)
  scope: workspace
  properties: {
    displayName: 'AutoRule-EmailAlert'
    order: 1
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: []
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: emailPlaybookId
          tenantId: tenant().tenantId
        }
      }
    ]
  }
}

// Automation Rule: Slack Notification on All Incidents

resource autoRuleSlack 'Microsoft.SecurityInsights/automationRules@2023-11-01' = {
  name: guid('auto-rule-slack', workspace.id)
  scope: workspace
  properties: {
    displayName: 'AutoRule-SlackNotification'
    order: 2
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: []
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: slackPlaybookId
          tenantId: tenant().tenantId
        }
      }
    ]
  }
}

// Automation Rule: Disable User on High Severity Only

resource autoRuleDisableUser 'Microsoft.SecurityInsights/automationRules@2023-11-01' = {
  name: guid('auto-rule-disable-user', workspace.id)
  scope: workspace
  properties: {
    displayName: 'AutoRule-DisableUser'
    order: 3
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentSeverity'
            operator: 'Equals'
            propertyValues: ['High']
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: disableUserPlaybookId
          tenantId: tenant().tenantId
        }
      }
    ]
  }
}

// Automation Rule: Block IP on High Severity Only

resource autoRuleBlockIp 'Microsoft.SecurityInsights/automationRules@2023-11-01' = {
  name: guid('auto-rule-block-ip', workspace.id)
  scope: workspace
  properties: {
    displayName: 'AutoRule-BlockIP'
    order: 4
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentSeverity'
            operator: 'Equals'
            propertyValues: ['High']
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: blockIpPlaybookId
          tenantId: tenant().tenantId
        }
      }
    ]
  }
}

// Azure Sentinel SIEM with Automated Response
// Bicep Configuration - Sentinel Components

targetScope = 'resourceGroup'

// Parameters

@description('Name of the Log Analytics workspace with Sentinel enabled')
param workspaceName string

@description('Azure region')
param location string = resourceGroup().location

@description('Email address for alert notifications')
@secure()
param alertEmail string

@description('Slack webhook URL for notifications')
@secure()
param slackWebhookUrl string

@description('Subscription ID for NSG blocking playbook')
param subscriptionId string = subscription().subscriptionId

@description('Resource group name')
param resourceGroupName string = resourceGroup().name

@description('NSG name for IP blocking')
param nsgName string = 'nsg-sentinel-block'

// Modules

module dataConnectors 'modules/data-connectors/data-connectors.bicep' = {
  name: 'deploy-data-connectors'
  params: {
    workspaceName: workspaceName
  }
}

module analyticsRules 'modules/analytics-rules/analytics-rules.bicep' = {
  name: 'deploy-analytics-rules'
  params: {
    workspaceName: workspaceName
  }
}

module logicApps 'modules/logic-apps/logic-apps.bicep' = {
  name: 'deploy-logic-apps'
  params: {
    location: location
    alertEmail: alertEmail
    slackWebhookUrl: slackWebhookUrl
    subscriptionId: subscriptionId
    resourceGroupName: resourceGroupName
    nsgName: nsgName
  }
}

module workbooks 'modules/workbooks/workbooks.bicep' = {
  name: 'deploy-workbooks'
  params: {
    workspaceName: workspaceName
    location: location
  }
}

module automationRules 'modules/automation-rules/automation-rules.bicep' = {
  name: 'deploy-automation-rules'
  params: {
    workspaceName: workspaceName
    emailPlaybookId: logicApps.outputs.emailPlaybookId
    slackPlaybookId: logicApps.outputs.slackPlaybookId
    disableUserPlaybookId: logicApps.outputs.disableUserPlaybookId
    blockIpPlaybookId: logicApps.outputs.blockIpPlaybookId
  }
}

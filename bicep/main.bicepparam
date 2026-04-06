using 'main.bicep'

param workspaceName = 'law-sentinel-siem'
param location = 'eastus'
param alertEmail = '<email@example.com>'
param slackWebhookUrl = '<slack-webhook-url>'
param nsgName = 'nsg-sentinel-block'

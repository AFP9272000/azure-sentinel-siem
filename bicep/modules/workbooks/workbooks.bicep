// Sentinel Workbooks - Security Dashboards

param workspaceName string
param location string

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// Security Dashboard Workbook

resource securityDashboard 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: guid('sentinel-security-dashboard', workspace.id)
  location: location
  kind: 'shared'
  properties: {
    displayName: 'Sentinel SIEM Security Dashboard'
    category: 'sentinel'
    sourceId: workspace.id
    serializedData: string({
      version: 'Notebook/1.0'
      items: [
        {
          type: 1
          content: {
            json: '# Sentinel SIEM Security Dashboard\n---'
          }
          name: 'header'
        }
        {
          type: 1
          content: {
            json: '## Incident Overview'
          }
          name: 'section1-header'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'SecurityIncident\n| summarize IncidentCount = count() by bin(CreatedTime, 1d), Severity\n| render timechart'
            size: 0
            title: 'Incident Volume Over Time'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'timechart'
          }
          name: 'incident-volume'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'SecurityIncident\n| summarize Count = count() by Title\n| top 10 by Count\n| render barchart'
            size: 0
            title: 'Top 10 Triggered Rules'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'barchart'
          }
          name: 'top-rules'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'SecurityIncident\n| summarize Count = count() by Severity\n| render piechart'
            size: 0
            title: 'Incidents by Severity'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'piechart'
          }
          name: 'severity-distribution'
        }
        {
          type: 1
          content: {
            json: '## MITRE ATT&CK Coverage'
          }
          name: 'section2-header'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'SecurityIncident\n| mv-expand Tactics = todynamic(AdditionalData).tactics\n| summarize IncidentCount = count() by tostring(Tactics)\n| order by IncidentCount desc\n| render barchart'
            size: 0
            title: 'MITRE ATT&CK Tactic Distribution'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'barchart'
          }
          name: 'mitre-heatmap'
        }
        {
          type: 1
          content: {
            json: '## Risk Score Analysis'
          }
          name: 'section3-header'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'SecurityIncident\n| extend RiskScore = toint(parse_json(AdditionalData).RiskScore)\n| where isnotnull(RiskScore)\n| summarize Count = count() by RiskScore\n| order by RiskScore asc\n| render columnchart'
            size: 0
            title: 'Risk Score Distribution'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'columnchart'
          }
          name: 'risk-score-dist'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'SecurityIncident\n| extend RiskScore = toint(parse_json(AdditionalData).RiskScore)\n| where isnotnull(RiskScore)\n| summarize AvgRiskScore = avg(RiskScore), MaxRiskScore = max(RiskScore) by bin(CreatedTime, 1d)\n| render timechart'
            size: 0
            title: 'Risk Score Trend'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'timechart'
          }
          name: 'risk-score-trend'
        }
        {
          type: 1
          content: {
            json: '## Response Metrics'
          }
          name: 'section4-header'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'SecurityIncident\n| where Status == "Closed"\n| extend TimeToClose = datetime_diff(\'minute\', ClosedTime, CreatedTime)\n| summarize AvgMinutesToClose = round(avg(TimeToClose), 1), MedianMinutesToClose = round(percentile(TimeToClose, 50), 1), MaxMinutesToClose = max(TimeToClose)'
            size: 0
            title: 'Mean Time to Close (Minutes)'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'table'
          }
          name: 'mttc'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'AzureDiagnostics\n| where ResourceProvider == "MICROSOFT.LOGIC"\n| where resource_workflowName_s has "Playbook"\n| summarize TotalRuns = count(), Succeeded = countif(status_s == "Succeeded"), Failed = countif(status_s == "Failed") by resource_workflowName_s\n| extend SuccessRate = round(100.0 * Succeeded / TotalRuns, 1)\n| project PlaybookName = resource_workflowName_s, TotalRuns, Succeeded, Failed, SuccessRate'
            size: 0
            title: 'Playbook Execution Results'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'table'
          }
          name: 'playbook-results'
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: 'SecurityIncident\n| summarize Opened = countif(Status == "New" or Status == "Active"), Closed = countif(Status == "Closed") by bin(CreatedTime, 1d)\n| render barchart'
            size: 0
            title: 'Incidents Opened vs Closed'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'barchart'
          }
          name: 'open-vs-closed'
        }
      ]
    })
  }
}

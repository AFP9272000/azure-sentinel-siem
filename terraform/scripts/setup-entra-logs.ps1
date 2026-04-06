param(
    [string]$WorkspaceId
)

$body = @{
    properties = @{
        workspaceId = $WorkspaceId
        logs = @(
            @{
                category = "AuditLogs"
                enabled = $true
            }
        )
    }
} | ConvertTo-Json -Depth 5 -Compress

az rest `
    --method PUT `
    --uri "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/sentinel-entra-logs?api-version=2017-04-01" `
    --body $body

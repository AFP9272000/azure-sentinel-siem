param(
    [string]$WorkspaceId,
    [string]$Location
)

az monitor diagnostic-settings subscription create `
    -n "sentinel-activity-logs" `
    --location $Location `
    --workspace $WorkspaceId `
    --logs "[{""category"":""Administrative"",""enabled"":true},{""category"":""Security"",""enabled"":true},{""category"":""ServiceHealth"",""enabled"":true},{""category"":""Alert"",""enabled"":true},{""category"":""Recommendation"",""enabled"":true},{""category"":""Policy"",""enabled"":true},{""category"":""Autoscale"",""enabled"":true},{""category"":""ResourceHealth"",""enabled"":true}]"

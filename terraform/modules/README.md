# Terraform Modules

## Architecture Decision

This project uses a **flat Terraform structure** for core infrastructure rather than
nested modules. The reasoning:

- **Core infrastructure is minimal:** Resource group, Log Analytics Workspace,
  Sentinel onboarding, NSG, diagnostic settings, and RBAC assignments. These are
  tightly coupled and don't benefit from module abstraction.

- **Sentinel-specific resources are in Bicep:** Analytics rules, Logic Apps,
  workbooks, automation rules, and data connectors are deployed via Bicep modules
  (`bicep/modules/`). This is intentional — these resources involve complex KQL
  queries and Logic App workflow JSON that are more naturally expressed in
  Bicep/ARM than in Terraform's HCL.

- **Dual-IaC pattern:** Terraform handles infrastructure orchestration and state
  management. Bicep handles Azure-native Sentinel components. This split plays to
  the strengths of each tool.

## When to introduce Terraform modules

If this project were to scale (e.g., multi-subscription, multi-workspace, or
multi-environment deployment), the following modules would make sense:

- `modules/sentinel-workspace/` — Workspace + Sentinel onboarding
- `modules/networking/` — NSG and related network security resources
- `modules/monitoring/` — Diagnostic settings and log routing
- `modules/rbac/` — Role assignments and managed identity configuration

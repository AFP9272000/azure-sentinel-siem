# Azure Sentinel SIEM with Automated Response

Enterprise-grade cloud-native SIEM that ingests security telemetry from multiple Azure sources into Microsoft Sentinel, correlates events using custom KQL analytics rules with MITRE ATT&CK mapping, scores risk severity, and triggers automated response playbooks, reducing mean time to respond (MTTR) from manual investigation to seconds-level automated remediation.

![Azure](https://img.shields.io/badge/Azure-Sentinel%20%7C%20Log%20Analytics%20%7C%20Logic%20Apps-0078D4)
![Detection](https://img.shields.io/badge/Detection-11%20Custom%20KQL%20Rules-blue)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-8%20Tactics%20%7C%2011%2B%20Techniques-red)
![IaC](https://img.shields.io/badge/IaC-Terraform%20%2B%20Bicep-purple)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions%20%2B%20Azure%20DevOps-green)
![Security](https://img.shields.io/badge/Security-Checkov%20%7C%20tfsec%20%7C%20Trivy-red)
![Auth](https://img.shields.io/badge/Auth-OIDC%20%7C%20Managed%20Identity-brightgreen)

## Overview

A fully automated security operations platform deployed on Microsoft Sentinel with dual IaC implementations (Terraform + Bicep) and dual CI/CD pipelines (GitHub Actions + Azure DevOps) — featuring custom threat detection, automated incident response, and executive-level security dashboards.

**Key Metrics:**
- Detects threats across **8 MITRE ATT&CK tactics** with **11 custom KQL analytics rules**
- Maps to **11+ MITRE ATT&CK techniques and sub-techniques** for standardized threat classification
- Automates incident response via **4 Logic Apps playbooks** (email, Slack, user disable, IP block)
- Achieves **seconds-level automated remediation** for high-severity incidents
- Implements **dynamic risk scoring (0-100)** on every detection rule for prioritized triage
- Enables **incident correlation** across rules to surface multi-stage attack patterns
- Achieves **zero stored credentials** via managed identity across all playbook authentication
- Passes **triple-layer security scanning** (Checkov, tfsec, Trivy) on every deployment
- Dual IaC: identical infrastructure deployable via **Terraform or Bicep**
- Dual CI/CD: full pipelines on both **GitHub Actions and Azure DevOps**

## Architecture

<img width="1171" height="731" alt="architecture sentinel drawio" src="https://github.com/user-attachments/assets/3fa55877-b40d-4a55-9004-38164c104c6a" />


## MITRE ATT&CK Coverage

| Tactic | Technique | Rule | Data Source | Severity |
|--------|-----------|------|-------------|----------|
| Initial Access | T1078.004 - Cloud Accounts | Unusual Admin from New IP | AzureActivity | Medium |
| Execution | T1496 - Resource Hijacking | Mass VM Deployment | AzureActivity | High |
| Persistence | T1098 - Account Manipulation | Identity Modification Spree | AuditLogs | Medium |
| Persistence | T1098.001 - Additional Cloud Credentials | Service Principal Credential Added | AuditLogs | High |
| Privilege Escalation | T1078.004 - Cloud Accounts | RBAC Privilege Escalation | AzureActivity | High |
| Defense Evasion | T1562.007 - Disable Cloud Firewall | NSG Rule Modification | AzureActivity | Medium |
| Defense Evasion | T1562.008 - Disable Cloud Logs | Diagnostic Settings Tampering | AzureActivity | High |
| Defense Evasion | T1562 - Impair Defenses | Policy Deletion or Exemption | AzureActivity | Medium |
| Credential Access | T1555 - Credentials from Password Stores | Key Vault Suspicious Access | AzureActivity | High |
| Exfiltration | T1537 - Transfer Data to Cloud Account | Storage Account Public Access | AzureActivity | High |
| Impact | T1485 - Data Destruction | Resource Deletion Spree | AzureActivity | High |

## Automated Response Playbooks

| Playbook | Trigger | Action | Authentication |
|----------|---------|--------|----------------|
| **Email Alert** | All incidents | Sends enriched incident details to SOC email | Managed Identity + OAuth |
| **Slack Notification** | All incidents | Posts incident summary to `#security-alerts` channel | Managed Identity + Webhook |
| **Auto-Disable User** | High severity only | Disables compromised user account via Microsoft Graph API | Managed Identity + Graph API |
| **Auto-Block IP** | High severity only | Adds malicious IP to NSG deny rule via Azure REST API | Managed Identity + ARM API |

## Security Dashboard (Sentinel Workbooks)

| Section | Visualizations |
|---------|---------------|
| **Incident Overview** | Volume over time (timechart), top 10 triggered rules (bar), severity distribution (pie) |
| **MITRE ATT&CK Coverage** | Tactic distribution heatmap showing detection coverage across the framework |
| **Risk Score Analysis** | Risk score histogram, average/max risk score trending over time |
| **Response Metrics** | Mean time to close, playbook execution success rate, incidents opened vs closed |

## Infrastructure as Code

This project demonstrates **dual IaC proficiency** with identical infrastructure deployable via either tool:

### Terraform
```
terraform/
├── main.tf                          # Resource group, workspace, Sentinel, NSG,
│                                    #   diagnostic settings, RBAC assignments
├── variables.tf                     # Input parameters with defaults
├── outputs.tf                       # Workspace IDs, NSG ID, subscription info
├── providers.tf                     # AzureRM + AzureAD providers
├── backend.tf                       # Remote state in Azure Storage
├── terraform.tfvars.example         # Example variable values
├── modules/
│   └── README.md                    # Architecture decision documentation
└── scripts/
    ├── setup-activity-logs.ps1      # Activity Log diagnostic settings
    └── setup-entra-logs.ps1         # Entra ID audit log diagnostic settings
```

**Backend:** Remote state in Azure Storage Account with blob encryption

**Design Decision:** Flat Terraform structure for core infrastructure; Sentinel-specific resources (KQL rules, Logic Apps, workbooks) deployed via Bicep where ARM templates are more expressive

### Bicep
```
bicep/
├── main.bicep                       # Module orchestration
├── main.bicepparam                  # Parameter file
└── modules/
    ├── analytics-rules/             # 11 custom KQL detection rules
    │   └── analytics-rules.bicep    #   with MITRE mappings, risk scoring,
    │                                #   entity mappings, incident correlation
    ├── logic-apps/                  # 4 automated response playbooks
    │   └── logic-apps.bicep         #   with managed identity + RBAC assignments
    ├── workbooks/                   # Security dashboard with 4 sections
    │   └── workbooks.bicep          #   (12 KQL visualizations)
    ├── automation-rules/            # Incident-to-playbook routing
    │   └── automation-rules.bicep   #   with severity-based conditions
    └── data-connectors/             # Defender for Cloud connector
        └── data-connectors.bicep
```

## CI/CD Pipelines

### GitHub Actions (`.github/workflows/ci-cd.yml`)

| Stage | Actions | Gate |
|-------|---------|------|
| **Security Scanning** | Checkov (Terraform + Bicep), tfsec, Trivy | Soft-fail with SARIF upload |
| **Terraform Deploy** | `init` → `validate` → `plan` → `apply` with OIDC auth | Plan on PR, apply on merge |
| **Bicep Deploy** | `az deployment group create` with OIDC auth | Runs after Terraform succeeds |

**Authentication:** GitHub OIDC → Azure AD federated credentials (zero secrets)

### Azure DevOps (`azure-pipelines/pipeline.yml`)

| Stage | Actions | Gate |
|-------|---------|------|
| **Security Scanning** | Checkov (Terraform + Bicep), tfsec, Trivy | Soft-fail with CLI output |
| **Terraform Deploy** | `init` → `plan` → `apply` with OIDC via service connection | Runs on main branch only |
| **Bicep Deploy** | `az deployment group create` via service connection | Runs after Terraform succeeds |

**Authentication:** Azure DevOps Workload Identity federation via service connection (zero secrets)

## Security Scanning Results

### Checkov (Terraform)
- **2 passed** / 0 failed
- Covers: Secure parameter handling, no hardcoded secrets

### Checkov (Bicep)
- **2 passed** / 0 failed
- Covers: SecureString parameters validated for no default values

### tfsec
- **0 findings** on Terraform configurations

### Trivy
- **0 CRITICAL** / 0 HIGH findings across all project files

## Post-Deployment Manual Steps

The following steps require interactive authorization or privileged API calls that cannot be automated via IaC:

1. **Email Playbook:** Authorize the Outlook API connection (requires interactive OAuth consent)
2. **Disable User Playbook:** Grant `User.ReadWrite.All` Microsoft Graph API permission to the Logic App managed identity via PowerShell/CLI
3. **Block IP Playbook:** Verify Network Contributor role assignment on the managed identity
4. **Sentinel Playbook Permissions:** Configure playbook permissions in Sentinel Settings → Playbook Permissions (required after each redeployment)

These limitations are inherent to Azure Logic Apps API connections and Microsoft Graph app role assignments — documented in [Microsoft's official guidance](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-deploy-azure-resource-manager-templates#authorize-oauth-connections).

## Deployment

### Prerequisites
- Azure subscription with Owner access
- Terraform >= 1.5.0
- Azure CLI with Bicep
- GitHub repo with OIDC configured (for GitHub Actions)
- Azure DevOps service connection (for Azure DevOps pipeline)

### Deploy with Terraform (core infrastructure)
```bash
cd terraform/
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

### Deploy with Bicep (Sentinel components)
```bash
cd bicep/
az deployment group create \
  --resource-group rg-sentinel-siem \
  --template-file main.bicep \
  --parameters main.bicepparam
```

### Deploy via CI/CD
Push to `main` branch to trigger automatic deployment through either GitHub Actions or Azure DevOps.

## Project Structure

```
azure-sentinel-siem/
├── .github/workflows/
│   └── ci-cd.yml                    # GitHub Actions pipeline (OIDC)
├── azure-pipelines/
│   └── pipeline.yml                 # Azure DevOps pipeline (Workload Identity)
├── terraform/                       # Core infrastructure (Terraform)
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── providers.tf
│   ├── backend.tf
│   ├── terraform.tfvars.example
│   ├── modules/
│   └── scripts/
├── bicep/                           # Sentinel components (Bicep)
│   ├── main.bicep
│   ├── main.bicepparam
│   └── modules/
│       ├── analytics-rules/
│       ├── logic-apps/
│       ├── workbooks/
│       ├── automation-rules/
│       └── data-connectors/
├── docs/
│   ├── mitre-coverage.md            # Full MITRE ATT&CK coverage matrix
│   └── screenshots/                 # Detection and response evidence
├── .gitignore
└── README.md
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Dual IaC (Terraform + Bicep)** | Terraform manages infrastructure orchestration and state; Bicep handles Azure-native Sentinel resources where ARM templates are more expressive for KQL rules and Logic App workflows |
| **Dual CI/CD (GitHub Actions + Azure DevOps)** | Demonstrates proficiency in both platforms; GitHub Actions uses OIDC for secretless authentication |
| **Dynamic Risk Scoring** | Every detection rule assigns a risk score (0-100) based on severity indicators, enabling prioritized SOC triage |
| **Incident Correlation** | Enabled across all rules so Sentinel groups related alerts into unified multi-stage attack stories |
| **Managed Identity everywhere** | All playbooks authenticate via system-assigned managed identity — zero stored credentials |
| **Slack over Teams** | Demonstrates third-party webhook integration rather than staying within the Microsoft ecosystem |
| **Console-first, then IaC** | Built everything manually first to learn the platform, then codified — matching real-world migration patterns |

## Skills Demonstrated

| Category | Technologies |
|----------|-------------|
| **SIEM & Security** | Microsoft Sentinel, KQL, MITRE ATT&CK, threat detection, incident response, SOAR |
| **Azure Services** | Log Analytics, Logic Apps, Entra ID, Defender for Cloud, NSG, Managed Identity |
| **IaC** | Terraform (remote state, null_resource, local-exec) + Bicep (modular, parameterized) |
| **CI/CD** | GitHub Actions (OIDC) + Azure DevOps (Workload Identity federation) |
| **Security Scanning** | Checkov, tfsec, Trivy (IaC + filesystem) |
| **APIs** | Microsoft Graph API, Azure REST API, Slack Webhooks |
| **Languages** | KQL, HCL, Bicep, PowerShell, YAML |
| **DevSecOps** | Shift-left scanning, pipeline security gates, SARIF reporting, zero-secret architecture |

## Related Projects

- [Azure Security Dashboard](https://github.com/AFP9272000/azure-security-dashboard) — SOC-style dashboard on AKS with Defender for Cloud, Log Analytics, and dual IaC/CI/CD
- [Security Event Aggregator](https://github.com/AFP9272000/security-event-aggregator) — Containerized microservices on ECS Fargate with MITRE ATT&CK mappings and risk scoring
- [CloudTrail Security Monitor](https://github.com/AFP9272000/cloudtrail-security-monitor) — AWS real-time security monitoring with Lambda, Security Hub, and EventBridge
- [Secure Juice Shop](https://github.com/AFP9272000/secure-vulnerable-website-juiceshop) — Enterprise DevSecOps pipeline with Checkov, tfsec, Trivy, SARIF

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Addison Pirlo** — [LinkedIn](https://www.linkedin.com/in/addison-pirlo-98b1a8297/) | [Email](mailto:addisonpirlo2@gmail.com)

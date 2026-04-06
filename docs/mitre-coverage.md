# MITRE ATT&CK Coverage Matrix

## Overview

This Sentinel SIEM deployment covers **8 MITRE ATT&CK tactics** across **11 custom
detection rules**, providing broad visibility into cloud-based attack techniques
targeting Azure environments.

## Coverage Map

### Initial Access (TA0001)
| Technique | Sub-technique | Rule | Data Source | Risk Score |
|---|---|---|---|---|
| T1078 - Valid Accounts | T1078.004 - Cloud Accounts | Unusual Admin from New IP | AzureActivity | 50-95 |

### Execution (TA0002)
| Technique | Sub-technique | Rule | Data Source | Risk Score |
|---|---|---|---|---|
| T1496 - Resource Hijacking | — | Mass VM Deployment | AzureActivity | 70-100 |

### Persistence (TA0003)
| Technique | Sub-technique | Rule | Data Source | Risk Score |
|---|---|---|---|---|
| T1098 - Account Manipulation | — | Identity Modification Spree | AuditLogs | 65-100 |
| T1098 - Account Manipulation | T1098.001 - Additional Cloud Credentials | Service Principal Credential Added | AuditLogs | 80-90 |

### Privilege Escalation (TA0004)
| Technique | Sub-technique | Rule | Data Source | Risk Score |
|---|---|---|---|---|
| T1078 - Valid Accounts | T1078.004 - Cloud Accounts | RBAC Privilege Escalation | AzureActivity | 50-100 |

### Defense Evasion (TA0005)
| Technique | Sub-technique | Rule | Data Source | Risk Score |
|---|---|---|---|---|
| T1562 - Impair Defenses | T1562.007 - Disable or Modify Cloud Firewall | NSG Rule Modification | AzureActivity | 60-85 |
| T1562 - Impair Defenses | T1562.008 - Disable Cloud Logs | Diagnostic Settings Tampering | AzureActivity | 75-95 |
| T1562 - Impair Defenses | — | Policy Deletion or Exemption | AzureActivity | 65-90 |

### Credential Access (TA0006)
| Technique | Sub-technique | Rule | Data Source | Risk Score |
|---|---|---|---|---|
| T1555 - Credentials from Password Stores | — | Key Vault Suspicious Access | AzureActivity | 60-100 |

### Exfiltration (TA0010)
| Technique | Sub-technique | Rule | Data Source | Risk Score |
|---|---|---|---|---|
| T1537 - Transfer Data to Cloud Account | — | Storage Account Public Access | AzureActivity | 60-90 |

### Impact (TA0040)
| Technique | Sub-technique | Rule | Data Source | Risk Score |
|---|---|---|---|---|
| T1485 - Data Destruction | — | Resource Deletion Spree | AzureActivity | 25-100 |

## Detection-to-Response Mapping

| Rule | Severity | Playbooks Triggered |
|---|---|---|
| Resource Deletion Spree | High | Email, Slack, Disable User, Block IP |
| RBAC Privilege Escalation | High | Email, Slack, Disable User, Block IP |
| NSG Rule Modification | Medium | Email, Slack |
| Diagnostic Settings Tampering | High | Email, Slack, Disable User, Block IP |
| Key Vault Suspicious Access | High | Email, Slack, Disable User, Block IP |
| Policy Deletion or Exemption | Medium | Email, Slack |
| Storage Account Public Access | High | Email, Slack, Disable User, Block IP |
| Mass VM Deployment | High | Email, Slack, Disable User, Block IP |
| Unusual Admin from New IP | Medium | Email, Slack |
| Service Principal Credential Added | High | Email, Slack, Disable User, Block IP |
| Identity Modification Spree | Medium | Email, Slack |

## Gaps and Future Coverage

Tactics **not currently covered** that could be added:

- **Reconnaissance (TA0043):** Could monitor for subscription enumeration via
  Azure Resource Graph queries
- **Resource Development (TA0042):** Could detect new resource provider
  registrations
- **Lateral Movement (TA0008):** Would require VM-level logs (Azure Monitor Agent)
  to detect east-west movement
- **Command and Control (TA0011):** Would require network flow analysis via NSG
  flow logs or Azure Firewall logs
- **Collection (TA0009):** Could add rules for mass storage blob downloads or
  database export operations

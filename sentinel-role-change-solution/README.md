# Sentinel Workbook Solution: Defender XDR Admin Role Changes

Deploy a Microsoft Sentinel workbook and supporting content to monitor Defender XDR admin role changes with Entra ID audit fallback.

## Deploy (Azure CLI) — recommended

This is the validated deployment path. Run from this folder:

```powershell
az account set --subscription <subscription-id>

az deployment group create `
  --resource-group <resource-group-name> `
  --template-file .\azuredeploy.json `
  --parameters workspaceName=<sentinel-workspace-name>
```

## One-click deploy

> **Note:** the button fetches `azuredeploy.json` from this repository's `main` branch over a public raw GitHub URL. If you fork or rename the repo, update the owner/repo path in the button URL below.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAngelSanchezFer%2Fsentinel-defender-rbac-monitor%2Fmain%2Fsentinel-role-change-solution%2Fazuredeploy.json)

## What this deploys

- Workbook: `Defender XDR Admin Role Change Monitoring`
- KQL functions (saved searches):
  - `fxdr_role_changes_normalized`
  - `fxdr_role_changes_high_risk`
  - `fxdr_role_change_actor_baseline`
- Scheduled analytics rules:
  - `Defender XDR High-Risk Role Assignment by Unapproved Actor`
  - `Defender XDR Role Assignment Outside Approved Maintenance Window`
- Sentinel watchlists:
  - `approved-defender-admins`
  - `approved-maintenance-window`

## Files

- `azuredeploy.json` - main ARM template
- `azuredeploy.parameters.json` - sample parameters
- `workbook/workbook.json` - workbook source definition used for template maintenance
- `kql/functions/*.kql` - KQL source for normalization and detections
- `analytics/*.json` - detection logic source files
- `watchlists/*.csv` - watchlist scaffolding content

## Prerequisites

- Existing Log Analytics workspace with Microsoft Sentinel enabled
- Permissions to deploy:
  - `Microsoft.Resources/deployments/*`
  - `Microsoft.OperationalInsights/workspaces/*`
  - `Microsoft.SecurityInsights/*`
  - `Microsoft.Insights/workbooks/*`

## Post-deployment

1. Open Sentinel > Workbooks > `Defender XDR Admin Role Change Monitoring`.
2. Validate watchlist content and replace sample rows with production data.
3. Tune analytics rule query frequency/severity for your SOC process.


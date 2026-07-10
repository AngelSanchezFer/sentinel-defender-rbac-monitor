# Sentinel + Defender RBAC Monitor

Tools and a deployable Microsoft Sentinel solution for monitoring **admin role
changes** across Microsoft Defender XDR (Unified RBAC), Microsoft 365 delegated
permission grants, and Entra ID directory roles.

> Personal project, shared publicly. **Not an official Microsoft product.**
> Provided as-is with no warranty or support. See [DISCLAIMER.md](DISCLAIMER.md).

## What's inside

| Component | Description |
|---|---|
| [`sentinel-role-change-solution/`](sentinel-role-change-solution/) | One-click deployable Microsoft Sentinel solution: workbook, KQL functions, scheduled analytics rules, and watchlists that monitor Defender XDR / Entra / URBAC admin role changes. |
| [`rbac-audit/`](rbac-audit/) | PowerShell scripts to audit Defender XDR Unified RBAC + Entra directory-role permission changes from the M365 unified audit log and the Entra ID audit log. |
| [`docs/`](docs/defender-rbac-design.md) | Design guidance for Defender RBAC change monitoring. |

## Coverage

The Sentinel normalization function unifies three distinct sources into one schema:

- **Entra ID** directory-role changes (`AuditLogs`, `RoleManagement`)
- **Microsoft 365** delegated permission grants / app consent (`CloudAppEvents`)
- **Defender XDR Unified RBAC (URBAC)** custom role & assignment changes (`CloudAppEvents`, `Workload == "URBAC"`)

On top of that it provides high-risk role detection, permanent (non-PIM) grant
flagging, external / guest account detection, per-actor sign-in posture (MFA /
risk), a configurable time range, and click-through drill-downs in the workbook.

## Quick start

### Deploy the Sentinel solution
One-click **Deploy to Azure**, or via Azure CLI — see
[sentinel-role-change-solution/README.md](sentinel-role-change-solution/README.md).

### Audit RBAC changes with PowerShell
```powershell
cd rbac-audit
# Who has admin access right now + recent changes
.\Get-AdminAccessReport.ps1 -Days 30 -IncludeEntraRoles
```

## Prerequisites

- An existing Log Analytics workspace with Microsoft Sentinel enabled (for the
  Sentinel solution).
- PowerShell 5.1+ or 7+, plus the `ExchangeOnlineManagement` and
  `Microsoft.Graph` modules (for the audit scripts).
- Appropriate read permissions in the target tenant
  (`AuditLog.Read.All`, `Directory.Read.All`, View-Only Audit Logs).

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

# Get-DefenderRbacChanges

Audits **Defender XDR Unified RBAC** and **Entra ID directory-role** permission
changes over a configurable look-back window. Pulls from two authoritative audit
stores and (optionally) exports results to CSV for an evidence trail.

## What it captures

| Source | Audit store | Tool path |
|---|---|---|
| Defender XDR Unified RBAC changes (role add/edit/delete, Unified RBAC activation toggle) | M365 unified audit log | Exchange Online `Search-UnifiedAuditLog` |
| Entra directory-role changes for Defender-relevant roles | Entra ID audit log | Microsoft Graph `GET /auditLogs/directoryAudits` |

Defender-relevant directory roles tracked client-side: Security Administrator,
Security Operator, Security Reader, Global Administrator, Global Reader,
Compliance Administrator, Compliance Data Administrator.

## New Scripts (v2.1+)

### Get-AdminAccessReport.ps1 ⭐ (RECOMMENDED)

**What it does**: Shows who currently has admin access across Defender/Purview/Entra/Azure, plus recent changes.

```powershell
# Current admin access + changes in last 30 days
.\Get-AdminAccessReport.ps1 -Days 30 -IncludeEntraRoles

# Export to CSV
.\Get-AdminAccessReport.ps1 -Days 30 -IncludeEntraRoles -OutCsv AdminAccess.csv
```

**Use this when**: You want a clear answer to "Who has admin-level access RIGHT NOW?" and you want to see recent changes.

---

### Diagnose-DefenderRbacAudit.ps1

**What it does**: Extracts raw audit JSON and identifies field-name mismatches (why Role/Principal columns are empty).

```powershell
# Generate DefenderXDR-RawAudit_*.json with full audit structure
.\Diagnose-DefenderRbacAudit.ps1 -Days 7
```

**Use this when**: Role/Principal columns are empty and you need to debug field-extraction issues.

---

## TROUBLESHOOTING

**Q: User assignment not showing in audit data?**  
**A**: See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for a three-step fix.

**Q: Role or Principal columns are empty?**  
**A**: Run `Diagnose-DefenderRbacAudit.ps1` to identify actual field names in your tenant's audit JSON, then update the field-lookup list in the script.

---

## Prerequisites

- PowerShell 5.1+ or 7+
- **For the Exchange section:** `ExchangeOnlineManagement` module; an account with
  access to the unified audit log (e.g., a role with **View-Only Audit Logs** /
  **Audit Logs**).
- **For the Entra section:** `Microsoft.Graph.Authentication` + `Microsoft.Graph.Reports`
  modules; delegated scopes `AuditLog.Read.All` and `Directory.Read.All`.

> **Note on the dual-connector design:** `ExchangeOnlineManagement` and
> `Microsoft.Graph` load incompatible `Microsoft.Identity.Client` (MSAL) assembly
> versions, which .NET will not co-load in a single process. When both sources are
> requested together, the script automatically runs the Graph section in a clean
> child process to avoid the conflict.

## Parameters

### Get-DefenderRbacChanges.ps1

| Parameter | Default | Description |
|---|---|---|
| `-Days` | `7` | Look-back window in days. |
| `-OutCsv` | _(none)_ | Path to export the Exchange/Unified-RBAC results. Console-only if omitted. |
| `-UserPrincipalName` | _(none)_ | Filter Exchange results to a specific actor UPN. |
| `-ResultSize` | `5000` | Max records to pull from the unified audit log. |
| `-IncludeEntraRoles` | _(off)_ | Also query the Entra ID audit log for directory-role changes. |
| `-IncludeGroupChanges` | _(off)_ | Also pull group membership changes (security groups that hold roles). |
| `-SkipExchange` | _(off)_ | Skip the Exchange section (Graph-only run). |
| `-EntraOutCsv` | _(none)_ | Path to export the Entra directory-role results. Console-only if omitted. |
| `-GroupOutCsv` | _(none)_ | Path to export the group membership results. |
| `-IncludeRaw` | _(off)_ | Include raw AuditData JSON in the CSV (for debugging). |
| `-InstallMissingModules` | _(off)_ | Auto-install prerequisite modules if missing. |

### Get-AdminAccessReport.ps1

| Parameter | Default | Description |
|---|---|---|
| `-Days` | `30` | Look-back window for recent changes (in days). |
| `-IncludeEntraRoles` | `$true` | Query current Entra directory-role assignments. |
| `-IncludeDefenderRoles` | _(off)_ | Query current Defender XDR custom role assignments. |
| `-IncludeGroupMembership` | _(off)_ | Include group membership data. |
| `-OutCsv` | _(none)_ | Path to export the consolidated report. |
| `-InstallMissingModules` | _(off)_ | Auto-install prerequisite modules if missing. |

## Usage

```powershell
# ========== QUICK START ==========

# Option 1: Get current admin access (RECOMMENDED)
.\Get-AdminAccessReport.ps1 -Days 30 -IncludeEntraRoles

# Option 2: Get historical role changes (last 7 days)
.\Get-DefenderRbacChanges.ps1

# Option 3: Get both sources, last 30 days, export to CSV
.\Get-DefenderRbacChanges.ps1 -IncludeEntraRoles -Days 30 `
    -OutCsv      .\DefenderRbac-Unified.csv `
    -EntraOutCsv .\DefenderRbac-Entra.csv `
    -InstallMissingModules

# Option 4: Debug empty Role/Principal fields
.\Diagnose-DefenderRbacAudit.ps1 -Days 7
```

## Output

Console by default. When export paths are supplied:

**Get-DefenderRbacChanges.ps1** produces:
- `DefenderXDR-RBAC-Changes_*.csv` — Unified RBAC changes
- `EntraDirectoryRole-Changes_*.csv` — Entra role assignment changes
- `GroupMembership-Changes_*.csv` — (optional) Group membership changes

**Get-AdminAccessReport.ps1** produces:
- `AdminAccessReport_*.csv` — Consolidated view of current admins + recent changes

A result of **0 rows is legitimate** — it means no matching changes occurred in the window (common on a quiet tenant), not a failure.

## Notes

- Defender XDR Unified RBAC auditing is on by default; changes log to the M365
  unified audit log automatically.
- Reading **email content** inside an alert requires the **Email & collaboration
  content (read)** permission under Defender XDR Unified RBAC (or the legacy
  **Preview** role) — *not* Compliance Data Administrator. Security Admin alone
  sees metadata/headers only.

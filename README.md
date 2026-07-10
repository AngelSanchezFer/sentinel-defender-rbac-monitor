# Sentinel Defender RBAC Monitor

A deployable Microsoft Sentinel solution for monitoring **admin role changes**
across Microsoft Defender XDR (Unified RBAC), Microsoft 365 delegated permission
grants, and Entra ID directory roles.

> Personal project, shared publicly. **Not an official Microsoft product.**
> Provided as-is with no warranty or support. See [DISCLAIMER.md](DISCLAIMER.md).

## What's inside

| Component | Description |
|---|---|
| [`sentinel-role-change-solution/`](sentinel-role-change-solution/) | One-click deployable Microsoft Sentinel solution: workbook, KQL functions, scheduled analytics rules, and watchlists that monitor Defender XDR / Entra / URBAC admin role changes. |
| [`docs/`](docs/defender-rbac-design.md) | Design guidance for Defender XDR RBAC. |

## Coverage

The Sentinel normalization function unifies three distinct sources into one schema:

- **Entra ID** directory-role changes (`AuditLogs`, `RoleManagement`)
- **Microsoft 365** delegated permission grants / app consent (`CloudAppEvents`)
- **Defender XDR Unified RBAC (URBAC)** custom role & assignment changes (`CloudAppEvents`, `Workload == "URBAC"`)

On top of that it provides high-risk role detection, permanent (non-PIM) grant
flagging, external / guest account detection, per-actor sign-in posture (MFA /
risk), a configurable time range, and click-through drill-downs in the workbook.

## Quick start

One-click **Deploy to Azure**, or via Azure CLI — see
[sentinel-role-change-solution/README.md](sentinel-role-change-solution/README.md).

## Prerequisites

- An existing Log Analytics workspace with Microsoft Sentinel enabled.
- Permissions to deploy Sentinel content: saved searches (functions),
  watchlists, scheduled analytics rules, and workbooks.

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)

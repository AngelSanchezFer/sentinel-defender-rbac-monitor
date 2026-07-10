# Defender XDR RBAC — design guidance

A least-privilege framework for designing Microsoft Defender XDR Unified RBAC
permissions.

## The three building blocks

1. **Permissions** — granular capabilities (e.g., read alerts, manage settings,
   read email & collaboration content).
2. **Roles** — named bundles of permissions.
3. **Assignments** — roles granted to identities (users/groups) scoped to a data
   source / workload.

## Design sequence

1. Inventory the personas who touch Defender XDR (SOC analyst, threat hunter,
   compliance reviewer, admin).
2. Map each persona to the **minimum** permissions they need.
3. Bundle those into roles; prefer a small number of well-scoped roles over many
   overlapping ones.
4. Assign via **Entra security groups**, not individual users, for manageability.
5. Layer **PIM** (Privileged Identity Management) for just-in-time elevation on
   high-impact roles.

## Starter role model

| Role | Purpose | Key permissions |
|---|---|---|
| **SOC Analyst** | Triage + investigate alerts/incidents | Read alerts, read email & collaboration content, manage investigations |
| **Threat Hunter** | Advanced hunting, read-only | Read security data, run hunting queries |
| **Compliance Reviewer** | Review content for compliance | Read email & collaboration content |
| **Security Admin** | Configure settings + RBAC | Manage security settings, manage RBAC |

## Common gotcha: reading alert email content

A user with **Security Administrator** can see alert metadata and headers but
**cannot read the email body** inside an alert. Reading content requires:

- **Email & collaboration content (read)** under Defender XDR Unified RBAC, **or**
- the legacy **Preview** role.

It is **not** granted by Compliance Data Administrator.

## Unified RBAC activation

Activating Defender XDR Unified RBAC is a deliberate toggle and changes how
permissions resolve across workloads. The activation event
(`URbacAuthorizationStatusChanged`) is logged to the M365 unified audit log.
Plan the migration from legacy/workload roles carefully and validate analyst
access after the switch.

## Governance

- **Entra groups** for assignment → fewer moving parts, easier reviews.
- **PIM** for just-in-time elevation + access reviews on privileged roles.
- **Audit** RBAC changes routinely — see
  [`Get-DefenderRbacChanges.ps1`](../rbac-audit/) for an automated pull.

---

_Personal guidance, not official Microsoft documentation. Validate against
[Microsoft Learn](https://learn.microsoft.com/) for your environment._

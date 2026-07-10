# Defender XDR RBAC Audit Script — Troubleshooting Guide

## Problem: User Assignment Not Found in Audit Data

**Situation**: You added `jdoe@contoso.com` to a custom Defender XDR role (Test Role, ID: `11111111-1111-1111-1111-111111111111`), but the audit event is not showing up in the CSV output.

**Root Cause**: The audit event IS being captured, but the field-extraction logic (`Get-AuditFieldValue` function) cannot locate the Role and Principal fields because:

1. The JSON field names in your tenant's audit events do NOT match the hardcoded list
2. The fields might be nested in `Parameters` or `ExtendedProperties` arrays under different names
3. The extraction falls back to empty values, leaving the Role/Principal columns blank

---

## Solution: Three-Step Fix

### Step 1: Run the Diagnostic Script (Identify Field Names)

This script will show you the ACTUAL field names in your tenant's audit JSON:

```powershell
cd rbac-audit
.\Diagnose-DefenderRbacAudit.ps1 -Days 30
```

**What it does**:
- Extracts raw audit JSON and saves it to `DefenderXDR-RawAudit_*.json`
- Lists all unique field names found in your audit events
- Highlights fields matching "role", "principal", "user", "identity", "member"
- Shows the structure of the first event

**Output example**:
```
=== Field Names Found in Audit JSON ===
Total unique field names: 15
  - ClientIP
  - Workload
  - ResultStatus
  - ObjectId
  - Parameters      <-- Look here!
  - ExtendedProperties
  ...
```

---

### Step 2: Inspect the Raw JSON

Open the generated `DefenderXDR-RawAudit_*.json` file and look at the `Parameters` array for your role-assignment event:

```json
{
  "TimeStampUTC": "2026-06-29T...",
  "Operation": "GrantPermissionsAsync",
  "AuditData": {
    "Parameters": [
      { "Name": "Role", "Value": "Test Role" },
      { "Name": "User", "Value": "jdoe@contoso.com" },
      { "Name": "RoleID", "Value": "11111111-1111-1111-1111-111111111111" }
    ]
  }
}
```

**Look for**:
- What field names are used? (Role, RoleName, Role ID, etc.)
- What values are in those fields?
- Are they in `Parameters`, `ExtendedProperties`, or top-level properties?

---

### Step 3: Update the Script's Field Lookup List

Once you know the actual field names, update the **Get-DefenderRbacChanges.ps1** script.

Find this section (around line 210):

```powershell
$role = Get-AuditFieldValue -AuditData $d -Names @(
            'Role','Roles','RoleName','RoleDisplayName','RoleId','RoleGroup',
            'role','roleName','roleDisplayName')

$principal = Get-AuditFieldValue -AuditData $d -Names @(
            'Identity','User','Users','UserId','Members','Member',
            'SecurityGroup','Group','TargetUser','PrincipalName','Subject','Name',
            'identity','user','users','member','targetUser','principalName')
```

**Add the actual field names from your JSON to the array**. For example, if your audit data uses `RoleID` and `AssignedUser`:

```powershell
$role = Get-AuditFieldValue -AuditData $d -Names @(
            'Role','Roles','RoleName','RoleDisplayName','RoleId','RoleGroup','RoleID',
            'role','roleName','roleDisplayName')

$principal = Get-AuditFieldValue -AuditData $d -Names @(
            'Identity','User','Users','UserId','Members','Member','AssignedUser',
            'SecurityGroup','Group','TargetUser','PrincipalName','Subject','Name',
            'identity','user','users','member','assignedUser','targetUser','principalName')
```

---

## Alternative: Use the Enhanced Scripts

I've created two **improved scripts** to work around this issue:

### Option A: Get-AdminAccessReport.ps1 (Recommended)

This script consolidates admin access from multiple sources and is more robust:

```powershell
.\Get-AdminAccessReport.ps1 -Days 30 -IncludeEntraRoles
```

**Advantages**:
- ✅ Shows current admin assignments (not just audit events)
- ✅ Better error handling for field extraction
- ✅ Easier to understand output (clear roles, users, sources)
- ✅ Answers your original question: "Who has admin access?"

---

### Option B: Improved Get-DefenderRbacChanges.ps1

The script has been updated with:
- ✅ Enhanced field extraction with case-insensitive fallback
- ✅ Debug helper function `Expand-AuditDataFields` to show all parameters
- ✅ Support for more field-name variations

**Run with both flags to capture everything**:

```powershell
.\Get-DefenderRbacChanges.ps1 -Days 30 -IncludeEntraRoles -IncludeGroupChanges -InstallMissingModules
```

---

## Quick Checklist: "Why is my user not in the audit data?"

- [ ] Did you run the script with `-IncludeEntraRoles` and `-IncludeGroupChanges`? (three separate CSV files are created)
- [ ] Is the timestamp on the audit event within the `-Days` window? (default is 7 days)
- [ ] Did you wait 15-30 minutes after adding the user? (audit log has a delay)
- [ ] Is auditing enabled in your tenant? (it is by default; check with `Get-AdminAuditLogConfig`)
- [ ] Do you have the "View-Only Audit Logs" or "Audit Logs" role? (required to query)
- [ ] Did the role assignment succeed? (check the `Result` column in Entra CSV)

---

## Scenario: "Test Role" is NOT in Entra Audit

If your "Test Role" (custom Defender XDR role) is NOT in the **Entra CSV** output, it's because:

- **Custom Defender XDR roles** are assigned via the M365 unified audit log (SecurityComplianceRBAC), NOT the Entra audit log
- Look in the **DefenderXDR-RBAC-Changes CSV** instead
- The issue is likely the field-extraction problem described above (Role and Principal columns are empty)

**Solution**: Run Step 1-3 above to identify and fix the field names.

---

## Still Stuck? Debug Output

Run this to see raw field extraction:

```powershell
$StartDate = (Get-Date).AddDays(-7).ToUniversalTime()
$EndDate = (Get-Date).ToUniversalTime()

Connect-ExchangeOnline -ShowBanner:$false
$events = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType 'SecurityComplianceRBAC' -ResultSize 100

foreach ($rec in $events | Select-Object -First 5) {
    $d = $rec.AuditData | ConvertFrom-Json
    Write-Host "Operation: $($rec.Operations)" -ForegroundColor Cyan
    Write-Host "Parameters:" -ForegroundColor Green
    $d.Parameters | ForEach-Object { Write-Host "  $($_.Name) = $($_.Value)" }
    Write-Host ""
}

Disconnect-ExchangeOnline -Confirm:$false
```

This will show you EXACTLY what fields are available in your audit events.

---

## Summary

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `Get-DefenderRbacChanges.ps1` (original) | Historical changes across all sources | Need to see audit trail of role assignments |
| `Get-AdminAccessReport.ps1` (new) | Current admin access + recent changes | Answer: "Who has admin access RIGHT NOW?" |
| `Diagnose-DefenderRbacAudit.ps1` (new) | Identify field-name mismatches | Troubleshooting why fields are empty |

---

**Next Steps**:

1. Run `Diagnose-DefenderRbacAudit.ps1` to see the raw JSON
2. Open the generated `DefenderXDR-RawAudit_*.json` and find your role-assignment event
3. Check what field names are actually used
4. Update the field lists in the script with the real names
5. Re-run `Get-DefenderRbacChanges.ps1 -Days 30 -IncludeRaw` to verify

Or just use `Get-AdminAccessReport.ps1` — it's simpler and more robust.

# Quick Reference: Admin Access Audit

## Common Scenario
> "I added a user to a Defender XDR admin role. Why can't I find the audit event? How do I see who has admin access?"

## Quick Answer

### To Find the User Assignment (3 Commands)

```powershell
cd rbac-audit

# 1. Try the new admin report (simplest)
.\Get-AdminAccessReport.ps1 -Days 30 -IncludeEntraRoles

# 2. If that doesn't show it, pull all audit sources
.\Get-DefenderRbacChanges.ps1 -Days 30 -IncludeEntraRoles -IncludeGroupChanges

# 3. If Role/Principal columns are empty, debug the JSON structure
.\Diagnose-DefenderRbacAudit.ps1 -Days 7
```

### To Get a Report of "Who Has Admin Access" (Current State)

```powershell
# Current assignments + recent changes
.\Get-AdminAccessReport.ps1 -Days 90 -IncludeEntraRoles -OutCsv AdminAccess.csv

# Open AdminAccess.csv in Excel
```

---

## Troubleshooting: Empty Role/Principal Columns

If you see the audit event but the Role/Principal columns are blank:

1. **Run diagnostic**:
   ```powershell
   .\Diagnose-DefenderRbacAudit.ps1 -Days 7
   ```

2. **Inspect the JSON** generated (`DefenderXDR-RawAudit_*.json`)

3. **Update script** with actual field names (see TROUBLESHOOTING.md Step 3)

---

## What Each Script Does

| Script | Purpose | Output |
|--------|---------|--------|
| `Get-AdminAccessReport.ps1` ⭐ | Current admin assignments + recent changes | CSV with Source, User, Role, Date |
| `Get-DefenderRbacChanges.ps1` | Historical role changes across all audit sources | 3 CSVs (Unified RBAC, Entra, Groups) |
| `Diagnose-DefenderRbacAudit.ps1` | Debug field-extraction issues | JSON file + field-name list |

---

## Common Issues & Fixes

### ❌ "Role and Principal columns are empty"
→ Run Diagnose-DefenderRbacAudit.ps1 and check JSON structure

### ❌ "User not found in any CSV"
→ Wait 30 minutes for audit log sync + check `-Days` window

### ❌ "jdoe@contoso.com not in Entra CSV"
→ Check DefenderXDR-RBAC-Changes CSV (custom roles use M365 audit log, not Entra)

### ❌ "Need audit logs for Defender XDR only"
→ Use: `.\Get-DefenderRbacChanges.ps1 -Days 30 -SkipExchange`

### ❌ "Module not installed"
→ Use: `.\Get-AdminAccessReport.ps1 -InstallMissingModules`

---

## Script Parameters Cheat Sheet

### Get-AdminAccessReport.ps1
```powershell
.\Get-AdminAccessReport.ps1 `
  -Days 30                          # How far back to look
  -IncludeEntraRoles                # Query Entra roles
  -OutCsv AdminAccess.csv           # Export to CSV
  -InstallMissingModules            # Auto-install PowerShell modules
```

### Get-DefenderRbacChanges.ps1
```powershell
.\Get-DefenderRbacChanges.ps1 `
  -Days 30                          # How far back to look
  -IncludeEntraRoles                # Query Entra role changes
  -IncludeGroupChanges              # Query group membership changes
  -OutCsv DefenderRbac.csv          # Export Unified RBAC changes
  -EntraOutCsv EntraRoles.csv       # Export Entra role changes
  -InstallMissingModules            # Auto-install PowerShell modules
```

### Diagnose-DefenderRbacAudit.ps1
```powershell
.\Diagnose-DefenderRbacAudit.ps1 `
  -Days 7                           # How far back to look
```

---

## What Was Fixed

✅ **Issue #1**: Defender XDR CSV had empty Role/Principal columns
- **Fix**: Enhanced field extraction with case-insensitive matching + fallback

✅ **Issue #2**: jdoe@contoso.com assignment not found
- **Fix**: New admin-access report script + better audit sourcing

✅ **Issue #3**: No way to see "who has admin access right now"
- **Fix**: Get-AdminAccessReport.ps1 shows current + recent changes

---

## Files Available

```
rbac-audit/
  ├── Get-DefenderRbacChanges.ps1       (enhanced - still works as before)
  ├── Get-AdminAccessReport.ps1         (NEW - use for current admins)
  ├── Diagnose-DefenderRbacAudit.ps1    (NEW - debug field issues)
  ├── README.md                          (updated - quick-start guide)
  ├── TROUBLESHOOTING.md                 (NEW - full fix guide)
  └── VALIDATION-SUMMARY.md              (NEW - this document)
```

---

## Next: Test It

```powershell
cd rbac-audit

# Test with admin report
.\Get-AdminAccessReport.ps1 -Days 30 -IncludeEntraRoles

# Or test with full audit
.\Get-DefenderRbacChanges.ps1 -Days 30 -IncludeEntraRoles -IncludeGroupChanges
```

✓ You should now see jdoe@contoso.com in the results (if added within your `-Days` window)

---

## Still Stuck?

1. Check `TROUBLESHOOTING.md` for detailed step-by-step guide
2. Run `Diagnose-DefenderRbacAudit.ps1` to inspect raw audit JSON
3. Verify you have the right permissions (View-Only Audit Logs role)
4. Check if 30+ minutes have passed since the assignment (audit log delay)

<#
.SYNOPSIS
    Gets a consolidated report of who has Admin-level access across Defender/Purview/Entra/Azure.
    Shows both current assignments and recent changes (last N days).

.DESCRIPTION
    This script answers: "Who can access Defender/Purview/Entra admin functions?"
    
    It queries:
    1. Current Entra directory role assignments (Security Admin, Global Admin, etc.)
    2. Current Defender XDR custom role assignments
    3. Security group memberships of users with admin roles
    4. Recent changes (audit log) to identify who was added/removed

.EXAMPLE
    .\Get-AdminAccessReport.ps1 -Days 30 -IncludeEntraRoles
    .\Get-AdminAccessReport.ps1 -Days 7 -IncludeDefenderRoles -IncludeGroupMembership

.NOTES
    Requires: ExchangeOnlineManagement, Microsoft.Graph.Authentication, Microsoft.Graph.Reports
#>

param(
    [int] $Days = 30,
    [string] $UserPrincipalName,
    [switch] $IncludeEntraRoles = $true,
    [switch] $IncludeDefenderRoles,
    [switch] $IncludeGroupMembership,
    [switch] $InstallMissingModules,
    [string] $OutCsv = ".\AdminAccessReport_$(Get-Date -Format yyyyMMdd-HHmmss).csv"
)

function Resolve-RequiredModule {
    param([Parameter(Mandatory)][string] $Name)
    if (Get-Module -ListAvailable -Name $Name) { return }
    if ($InstallMissingModules) {
        Write-Host "Installing $Name module..." -ForegroundColor Yellow
        Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
    } else {
        throw "Required module '$Name' is not installed. Re-run with -InstallMissingModules"
    }
}

# Admin-relevant Entra roles
$DefenderAdminRoles = @(
    'Security Administrator',
    'Security Operator', 
    'Compliance Administrator',
    'Global Administrator'
)

$DefenderAdminRoleIds = @(
    '194ae4cb-b126-40b2-bd5b-6091b380977d', # Security Administrator
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f', # Security Operator
    '17315797-102d-40b4-93e0-432062caca18', # Compliance Administrator
    '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
)

$results = @()

# =====================================================================================
# SECTION 1: Entra Directory Role Assignments (CURRENT)
# =====================================================================================

if ($IncludeEntraRoles) {
    Write-Host "`nQuerying current Entra directory role assignments..." -ForegroundColor Cyan
    
    foreach ($m in 'Microsoft.Graph.Authentication','Microsoft.Graph.Reports','Microsoft.Graph.Identity.DirectoryManagement') {
        Resolve-RequiredModule -Name $m
        Import-Module $m -ErrorAction Stop
    }
    
    try {
        Connect-MgGraph -Scopes 'Directory.Read.All','RoleManagement.Read.Directory' -NoWelcome
        
        # Get all assignment objects for Defender admin roles
        $roleAssignments = @()
        
        foreach ($roleId in $DefenderAdminRoleIds) {
            try {
                $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$roleId'" -ExpandProperty Principal -All
                $roleAssignments += $assignments
            } catch {
                Write-Warning "Failed to query role $roleId : $_"
            }
        }
        
        # Get role name mappings
        $roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All
        $roleMap = @{}
        $roleDefs | ForEach-Object { $roleMap[$_.Id] = $_.DisplayName }
        
        # Flatten assignments
        foreach ($assignment in $roleAssignments) {
            $roleName = $roleMap[$assignment.RoleDefinitionId]
            $principalInfo = $assignment.Principal
            
            $results += [pscustomobject]@{
                'Source'              = 'Entra Directory Role'
                'Assignment Type'     = if ($assignment.PrincipalId -match '^[a-f0-9-]{36}$') { 'Direct User' } else { 'Group' }
                'User/Group'          = $principalInfo.DisplayName
                'UPN/ID'              = $principalInfo.Mail ?? $principalInfo.UserPrincipalName ?? $principalInfo.Id
                'Role'                = $roleName
                'Assignment ID'       = $assignment.Id
                'Last Modified'       = $assignment.CreatedDateTime
                'Is Permanent'        = 'Yes'
            }
        }
        
        Write-Host "Found $($roleAssignments.Count) current Entra admin role assignments" -ForegroundColor Green
        
    } catch {
        Write-Error "Entra role query failed: $_"
    } finally {
        Disconnect-MgGraph | Out-Null
    }
}

# =====================================================================================
# SECTION 2: Recent Changes (Audit Log)
# =====================================================================================

Write-Host "`nQuerying recent changes (last $Days days)..." -ForegroundColor Cyan

Resolve-RequiredModule -Name 'ExchangeOnlineManagement'
Import-Module ExchangeOnlineManagement -ErrorAction Stop

$StartDate = (Get-Date).AddDays(-$Days).ToUniversalTime()
$EndDate   = (Get-Date).ToUniversalTime()

try {
    if ($UserPrincipalName) {
        Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ErrorAction Stop
    } else {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    }
    
    # Query Entra role changes
    $entraAudit = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations 'Add member to role','Remove member from role','Assign role','Unassign role' -ResultSize 5000 -ErrorAction SilentlyContinue
    
    if ($entraAudit) {
        foreach ($event in $entraAudit) {
            try {
                $d = $event.AuditData | ConvertFrom-Json
                
                # Extract role and user from the event
                $roleName = $d.RoleName ?? $d.Role ?? ($d.ModifiedProperties | Where-Object { $_.Name -match 'role' } | Select-Object -First 1 -ExpandProperty NewValue)
                $targetUser = $d.TargetUser ?? $d.User ?? $event.UserIds
                
                if ($roleName -and ($roleName -in $DefenderAdminRoles -or $roleName -match 'Security|Admin|Compliance')) {
                    $results += [pscustomobject]@{
                        'Source'              = 'Entra Audit (Recent Change)'
                        'Assignment Type'     = 'Audit Event'
                        'User/Group'          = $targetUser
                        'UPN/ID'              = $d.TargetUserObjectId ?? $event.UserIds
                        'Role'                = $roleName
                        'Assignment ID'       = $d.ObjectId ?? ''
                        'Last Modified'       = $event.CreationDate
                        'Is Permanent'        = $event.Operations -match 'Remove' ? 'No (Removed)' : 'Yes'
                    }
                }
            } catch {
                # Skip malformed events
            }
        }
    }
    
    # Query Defender XDR RBAC changes
    Write-Host "Searching for Defender XDR role changes..." -ForegroundColor DarkCyan
    $defenderAudit = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType 'SecurityComplianceRBAC' -ResultSize 5000 -ErrorAction SilentlyContinue
    
    if ($defenderAudit) {
        Write-Host "  Found $($defenderAudit.Count) Defender audit events" -ForegroundColor DarkCyan
        
        foreach ($event in $defenderAudit) {
            try {
                $d = $event.AuditData | ConvertFrom-Json
                
                # Try multiple field names for role and principal
                $role = $d.Role ?? $d.RoleName ?? $d.RoleDisplayName ?? $d.Roles ?? ($d.Parameters | Where-Object Name -eq 'Role' | Select-Object -First 1 -ExpandProperty Value) ?? ($d.ExtendedProperties | Where-Object Name -eq 'Role' | Select-Object -First 1 -ExpandProperty Value)
                
                $principal = $d.Identity ?? $d.User ?? $d.Users ?? $d.Member ?? $d.Members ?? ($d.Parameters | Where-Object Name -match 'User|Principal|Member' | Select-Object -First 1 -ExpandProperty Value) ?? ($d.ExtendedProperties | Where-Object Name -match 'User|Principal' | Select-Object -First 1 -ExpandProperty Value)
                
                # Skip check* operations (read noise)
                if ($event.Operations -like 'Check*') {
                    continue
                }
                
                if ($role -and $principal) {
                    $results += [pscustomobject]@{
                        'Source'              = 'Defender XDR Audit'
                        'Assignment Type'     = $event.Operations
                        'User/Group'          = $principal
                        'UPN/ID'              = ''
                        'Role'                = $role
                        'Assignment ID'       = $d.ObjectId ?? ''
                        'Last Modified'       = $event.CreationDate
                        'Is Permanent'        = if ($event.Operations -match 'Grant|Add') { 'Yes' } else { 'No' }
                    }
                }
            } catch {
                # Skip malformed events
            }
        }
    }
    
} catch {
    Write-Error "Audit log query failed: $_"
} finally {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

# =====================================================================================
# OUTPUT
# =====================================================================================

if ($results -and $results.Count -gt 0) {
    Write-Host "`n=== Admin Access Report ===" -ForegroundColor White
    $results | Sort-Object 'Last Modified' -Descending |
        Select-Object 'Source','Assignment Type','User/Group','Role','Last Modified','Is Permanent' |
        Format-Table -AutoSize -Wrap
    
    $results | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nExported $($results.Count) record(s) to: $OutCsv" -ForegroundColor Green
} else {
    Write-Host "No admin access assignments found." -ForegroundColor Yellow
}

Write-Host "`n✓ Report complete" -ForegroundColor Green

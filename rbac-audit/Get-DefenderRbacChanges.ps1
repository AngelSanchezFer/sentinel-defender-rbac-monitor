<#
.SYNOPSIS
    Pulls all Microsoft Defender XDR permission/role changes from the last 7 days
    across BOTH sources of truth:
      1. Defender XDR Unified RBAC  -> M365 unified audit log (Exchange Online)
      2. Entra directory-role assignments (Security Administrator, Security
         Operator, etc.) -> Entra ID audit log (Microsoft Graph directoryAudits)

.DESCRIPTION
    Defender access is granted two different ways and each lands in a different
    audit store:

      * Defender XDR Unified RBAC role create/edit/delete events and the Unified
        RBAC activation toggle are written to the M365 unified audit log. This
        script connects to Exchange Online and runs Search-UnifiedAuditLog.

      * Entra directory roles that grant Defender access (Security Administrator,
        Security Operator, Security Reader, Global Reader, Global Administrator)
        are assigned/removed in Entra ID. Those changes live in the Entra audit
        log and are read via Microsoft Graph (GET /auditLogs/directoryAudits,
        category = RoleManagement). The -IncludeEntraRoles switch pulls these.

    Both result sets are flattened to readable columns and exported to CSV.

.PERMISSIONS
    Unified audit log (Exchange Online):
        "View-Only Audit Logs" or "Audit Logs" role (default in the Compliance
        Management / Organization Management role groups) — separate from Security Admin.
    Graph directoryAudits (-IncludeEntraRoles):
        Delegated scope AuditLog.Read.All (+ Directory.Read.All to resolve names).
        Reader-equivalent: Global Reader / Security Reader / Reports Reader.

.NOTES
    Requires: ExchangeOnlineManagement module.
    -IncludeEntraRoles also requires: Microsoft.Graph.Authentication + Microsoft.Graph.Reports.
    Auditing is on by default for both stores — no enablement needed.

.EXAMPLE
    .\Get-DefenderRbacChanges.ps1
    .\Get-DefenderRbacChanges.ps1 -Days 30 -IncludeEntraRoles
    .\Get-DefenderRbacChanges.ps1 -IncludeEntraRoles -SkipExchange   # Entra-only run
    .\Get-DefenderRbacChanges.ps1 -InstallMissingModules            # auto-install prerequisites
#>

[CmdletBinding()]
param(
    [int]    $Days = 7,
    [string] $OutCsv = ".\DefenderXDR-RBAC-Changes_$(Get-Date -Format yyyyMMdd-HHmmss).csv",
    [string] $UserPrincipalName,                 # optional: pre-fill the sign-in identity
    [int]    $ResultSize = 5000,
    [switch] $IncludeEntraRoles,                 # also pull Entra directory-role changes via Graph
    [switch] $IncludeGroupChanges,               # also pull GroupManagement add/remove-member events (group-backed Defender grants)
    [switch] $SkipExchange,                      # skip the unified-audit-log search (Entra-only run)
    [string] $EntraOutCsv = ".\EntraDirectoryRole-Changes_$(Get-Date -Format yyyyMMdd-HHmmss).csv",
    [string] $GroupOutCsv = ".\GroupMembership-Changes_$(Get-Date -Format yyyyMMdd-HHmmss).csv",
    [switch] $InstallMissingModules,             # opt-in: install prerequisite modules if absent
    [switch] $IncludeRaw,                        # include the raw JSON AuditData column in the CSV
    [switch] $GraphChildProcess                  # internal: set when re-invoked in a clean child process
)

# --- Defender XDR / Purview Unified RBAC audit shape (verified against live tenant emit) ---
# Discovery against a live tenant showed that Defender/Purview unified-RBAC activity surfaces
# under the unified audit-log RecordType 'SecurityComplianceRBAC' — NOT the speculative
# 'MicrosoftDefenderXDR'/'MicrosoftDefenderExperts' enum members (this tenant never emitted
# them, and an unsupported enum throws under -ErrorAction Stop). Rather than enumerate every
# change-operation literal (they vary by workload + cmdlet version, and the old list used
# Exchange cmdlet names like Add-RbacRole that are never emitted here), we pull the whole
# RecordType and drop read/evaluation noise client-side.
$RbacRecordType = 'SecurityComplianceRBAC'

# Read/evaluation operations under SecurityComplianceRBAC that are NOT permission changes
# (pure authorization checks). The audit log emits MULTIPLE check variants — observed so far:
# 'CheckUsersInRoles' and 'CheckUserInRolesWithScopes' — so we exclude by PATTERN rather than
# an exact allow-list (which was whack-a-mole and let new variants leak through). Every
# 'Check*' evaluation is read noise; real changes use verbs like Grant/Revoke/Add/Remove/Set.
$RbacReadNoisePatterns = @(
    'Check*'        # CheckUsersInRoles, CheckUserInRolesWithScopes, and future check variants
)
# Exact-match read ops that don't fit a clean prefix pattern (extend as the tenant reveals more).
$RbacReadNoiseOperations = @()

# Privileged DATA-access operation (email preview/download from inside an alert). This is
# not a permission *change*, but it is security-relevant, so we surface it separately rather
# than letting it masquerade as a role edit.
$DataAccessOperations = @(
    'AdminMailAccess'
)

# --- Prerequisite-module helper ---
# Installs a required module only when -InstallMissingModules is supplied; otherwise
# fails fast with actionable guidance instead of silently mutating the machine.
function Resolve-RequiredModule {
    param([Parameter(Mandatory)][string] $Name)
    if (Get-Module -ListAvailable -Name $Name) { return }
    if ($InstallMissingModules) {
        Write-Host "Installing $Name module..." -ForegroundColor Yellow
        Install-Module $Name -Scope CurrentUser -Force -ErrorAction Stop
    } else {
        throw "Required module '$Name' is not installed. Re-run with -InstallMissingModules, or install it manually: Install-Module $Name -Scope CurrentUser"
    }
}

# --- Defensive AuditData field extraction (SecurityComplianceRBAC) ---
# Unlike Entra-shaped events, SecurityComplianceRBAC records (e.g. GrantPermissionsAsync,
# role create/edit) don't populate ObjectId/ModifiedProperties. The role + principal live
# inside the AuditData under a Parameters array ({Name,Value} pairs), an ExtendedProperties
# array, or occasionally a top-level property — and the exact key varies by operation +
# workload + cmdlet version. Rather than guess one name, probe a candidate list across all
# three shapes and return the first non-empty hit. Returns $null when nothing matches, in
# which case the caller simply leaves the column blank (Entra-shaped rows fall through here).
function Get-AuditFieldValue {
    param($AuditData, [string[]] $Names)
    if (-not $AuditData) { return $null }
    
    # FIRST: Check Parameters array (the most common location for Defender RBAC data)
    $params = $AuditData.Parameters
    if ($params) {
        foreach ($n in $Names) {
            $hit = $params | Where-Object { $_.Name -eq $n -and $_.Value } | Select-Object -First 1
            if ($hit) { return $hit.Value }
        }
    }
    
    # SECOND: Check ExtendedProperties array
    $extended = $AuditData.ExtendedProperties
    if ($extended) {
        foreach ($n in $Names) {
            $hit = $extended | Where-Object { $_.Name -eq $n -and $_.Value } | Select-Object -First 1
            if ($hit) { return $hit.Value }
        }
    }
    
    # THIRD: Check top-level properties
    foreach ($n in $Names) {
        $prop = $AuditData.PSObject.Properties[$n]
        if ($prop -and $prop.Value) { return $prop.Value }
    }
    
    # FOURTH: Fallback — search ALL properties for a case-insensitive match
    # This catches variations like 'Identity', 'identity', 'IDENTITY'
    foreach ($n in $Names) {
        $prop = $AuditData.PSObject.Properties | 
            Where-Object { $_.Name -like $n -or $_.Name -eq $n } | 
            Select-Object -First 1
        if ($prop -and $prop.Value) { 
            return $prop.Value 
        }
    }
    
    return $null
}

# --- Enhanced debugging helper for field extraction ---
function Expand-AuditDataFields {
    param($AuditData, [string] $Operation)
    # For debugging: returns all Parameters + ExtendedProperties as flat key-value
    $result = @{}
    
    if ($AuditData.Parameters) {
        foreach ($p in $AuditData.Parameters) {
            $result[$p.Name] = $p.Value
        }
    }
    if ($AuditData.ExtendedProperties) {
        foreach ($p in $AuditData.ExtendedProperties) {
            $result[$p.Name] = $p.Value
        }
    }
    
    return $result
}

$StartDate = (Get-Date).AddDays(-$Days).ToUniversalTime()
$EndDate   = (Get-Date).ToUniversalTime()

# =====================================================================================
# SECTION 1 — Defender XDR Unified RBAC changes (M365 unified audit log via Exchange Online)
# =====================================================================================
if (-not $SkipExchange) {

    # --- Connect to Exchange Online (modern auth / MFA) ---
    Resolve-RequiredModule -Name 'ExchangeOnlineManagement'
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $exchangeConnected = $false
    try {
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
        if ($UserPrincipalName) {
            Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ErrorAction Stop
        } else {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
        $exchangeConnected = $true

        Write-Host "Searching unified audit log: $StartDate -> $EndDate (UTC)" -ForegroundColor Cyan

        # Wrap each Search-UnifiedAuditLog call so an unsupported -RecordType / -Operations
        # value (which now throws under -ErrorAction Stop) degrades to a warning instead of
        # killing the whole section. This is what previously left Section 1 empty/dead.
        function Invoke-SafeAuditSearch {
            param([Parameter(Mandatory)][hashtable] $Params, [Parameter(Mandatory)][string] $Label)
            try {
                return Search-UnifiedAuditLog @Params -ErrorAction Stop
            } catch {
                Write-Warning "Audit search '$Label' failed (likely an unsupported value in this tenant/cmdlet version): $($_.Exception.Message)"
                return @()
            }
        }

        # --- Primary search: the VERIFIED RecordType for Defender XDR / Purview Unified RBAC. ---
        # Pull the whole record type, then drop read/evaluation noise client-side rather than
        # guessing every change-operation literal.
        $rbacRaw = Invoke-SafeAuditSearch -Label $RbacRecordType -Params @{
            StartDate  = $StartDate
            EndDate    = $EndDate
            RecordType = $RbacRecordType
            ResultSize = $ResultSize
        }
        $records = @($rbacRaw) | Where-Object {
            $op = $_.Operations
            ($op -notin $RbacReadNoiseOperations) -and
            -not ($RbacReadNoisePatterns | Where-Object { $op -like $_ })
        }

        # --- Data-access catch: privileged alert-content access (email preview/download). ---
        $dataAccess = Invoke-SafeAuditSearch -Label 'AdminMailAccess' -Params @{
            StartDate  = $StartDate
            EndDate    = $EndDate
            Operations = $DataAccessOperations
            ResultSize = $ResultSize
        }

        # Search-UnifiedAuditLog silently truncates at -ResultSize. Warn so the operator
        # knows to narrow -Days or raise -ResultSize rather than trust a partial picture.
        if (@($rbacRaw).Count -ge $ResultSize) {
            Write-Warning "Unified-audit RBAC search hit the -ResultSize cap ($ResultSize). Results may be truncated."
        }

        $all = @($records) + @($dataAccess) | Sort-Object Identity -Unique

        if (-not $all -or $all.Count -eq 0) {
            Write-Host "No Defender XDR Unified RBAC changes found in the last $Days day(s)." -ForegroundColor Green
        }
        else {
            # --- Flatten the JSON AuditData payload into readable columns ---
            $results = foreach ($rec in $all) {
                $d = $null
                try { $d = $rec.AuditData | ConvertFrom-Json } catch {}
                # SecurityComplianceRBAC events hide the role + principal inside AuditData
                # (Parameters / ExtendedProperties) instead of the Entra-shaped columns, so
                # probe defensively. Entra-shaped events return $null here and keep relying on
                # ObjectId / ModifiedProps below.
                $role = Get-AuditFieldValue -AuditData $d -Names @(
                            'Role','Roles','RoleName','RoleDisplayName','RoleId','RoleGroup',
                            'role','roleName','roleDisplayName')
                
                $principal = Get-AuditFieldValue -AuditData $d -Names @(
                            'Identity','User','Users','UserId','Members','Member',
                            'SecurityGroup','Group','TargetUser','PrincipalName','Subject','Name',
                            'identity','user','users','member','targetUser','principalName')
                
                # Additional fallback: if role or principal is still empty, check the first
                # Parameters/ExtendedProperties entry for likely candidates
                if (-not $role -or -not $principal) {
                    $allFields = Expand-AuditDataFields -AuditData $d
                    if (-not $role) {
                        $role = $allFields['Role'] ?? $allFields['RoleName'] ?? $allFields['role'] ?? $allFields['roleName']
                    }
                    if (-not $principal) {
                        $principal = $allFields['Identity'] ?? $allFields['Member'] ?? $allFields['identity'] ?? $allFields['member']
                    }
                }
                
                $obj = [pscustomobject]@{
                    TimeStampUTC = $rec.CreationDate
                    User         = $rec.UserIds
                    Operation    = $rec.Operations
                    Role         = $role
                    Principal    = $principal
                    Workload     = $d.Workload
                    ObjectId     = $d.ObjectId
                    ResultStatus = $d.ResultStatus
                    ClientIP     = $d.ClientIP
                    ModifiedProps= ($d.ModifiedProperties | ForEach-Object {
                                        "$($_.Name): '$($_.OldValue)' -> '$($_.NewValue)'"
                                    }) -join ' | '
                }
                if ($IncludeRaw) {
                    $obj | Add-Member -NotePropertyName RawAuditData -NotePropertyValue $rec.AuditData
                }
                $obj
            }

            $results = $results | Sort-Object TimeStampUTC -Descending

            Write-Host "`n=== Defender XDR Unified RBAC changes ===" -ForegroundColor White
            $results | Select-Object TimeStampUTC,User,Operation,Role,Principal,Workload,ObjectId,ResultStatus,ClientIP,ModifiedProps |
                Format-Table -AutoSize -Wrap

            $results | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
            Write-Host "Exported $($results.Count) Unified-RBAC record(s) to: $OutCsv" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Unified audit log section failed: $($_.Exception.Message)"
    }
    finally {
        if ($exchangeConnected) { Disconnect-ExchangeOnline -Confirm:$false }
    }
}

# =====================================================================================
# SECTION 2 — Entra directory-role assignment changes (Entra audit log via Microsoft Graph)
# =====================================================================================
# Defender access is ALSO granted through Entra directory roles. Those assignment
# add/remove events live in the Entra ID audit log, NOT the M365 unified audit log,
# and are read via Graph: GET /auditLogs/directoryAudits (category = RoleManagement).
if ($IncludeEntraRoles -or $IncludeGroupChanges) {

    # Microsoft.Graph.Authentication and ExchangeOnlineManagement load CONFLICTING
    # versions of Microsoft.Identity.Client (MSAL) into the same process, which breaks
    # Connect-MgGraph with: "Method not found ... BaseAbstractApplicationBuilder.WithLogging".
    # If Exchange Online already loaded in this process, delegate the Graph section to a
    # clean child PowerShell process so it gets a fresh assembly context.
    if (-not $SkipExchange -and -not $GraphChildProcess -and (Get-Module ExchangeOnlineManagement)) {
        Write-Host "`nExchange Online is loaded in this process; running the Graph section in a clean child process to avoid an MSAL assembly conflict..." -ForegroundColor Yellow
        # Re-launch with the SAME PowerShell edition that started us (5.1 or 7+) so this
        # works cross-edition rather than hard-coding powershell.exe.
        $psHost = (Get-Process -Id $PID).Path
        $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $PSCommandPath,
                     '-SkipExchange','-Days', $Days,
                     '-EntraOutCsv', $EntraOutCsv, '-GraphChildProcess')
        if ($IncludeEntraRoles)     { $argList += '-IncludeEntraRoles' }
        if ($IncludeGroupChanges)   { $argList += @('-IncludeGroupChanges','-GroupOutCsv', $GroupOutCsv) }
        if ($UserPrincipalName)     { $argList += @('-UserPrincipalName', $UserPrincipalName) }
        if ($IncludeRaw)            { $argList += '-IncludeRaw' }
        if ($InstallMissingModules) { $argList += '-InstallMissingModules' }
        & $psHost @argList
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Graph child process exited with code $LASTEXITCODE."
        }
        return
    }

    Write-Host "`nConnecting to Microsoft Graph (directoryAudits)..." -ForegroundColor Cyan

    foreach ($m in 'Microsoft.Graph.Authentication','Microsoft.Graph.Reports') {
        Resolve-RequiredModule -Name $m
        Import-Module $m -ErrorAction Stop
    }

    # Delegated auth. Reader-equivalent role required (Global Reader / Security Reader /
    # Reports Reader). For unattended runs, swap this for app-only:
    #   Connect-MgGraph -ClientId <appId> -TenantId <tenant> -CertificateThumbprint <thumb>
    # with the AuditLog.Read.All *application* permission granted + admin-consented.
    $graphConnected = $false
    try {
        Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All' -NoWelcome
        $graphConnected = $true

    # Graph wants the timestamp as an ISO 8601 / Zulu string. Shared by both gated blocks.
    $StartIso = $StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $EndIso   = $EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

    # ----- Entra directory-role changes (RoleManagement category) -----
    if ($IncludeEntraRoles) {

    # Directory roles that grant (or heavily influence) Defender XDR access.
    $DefenderRoles = @(
        'Security Administrator','Security Operator','Security Reader',
        'Global Administrator','Global Reader','Compliance Administrator',
        'Compliance Data Administrator'
    )

    # Built-in role template GUIDs — stable across tenants and localization, unlike the
    # English display names above. Matching on these catches renamed/localized roles.
    $DefenderRoleTemplateIds = @(
        '194ae4cb-b126-40b2-bd5b-6091b380977d', # Security Administrator
        '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f', # Security Operator
        '5d6b6bb7-de71-4623-b4af-96380a352509', # Security Reader
        '62e90394-69f5-4237-9190-012177145e10', # Global Administrator
        'f2ef992c-3afb-46b9-b7cf-a126ee74c451', # Global Reader
        '17315797-102d-40b4-93e0-432062caca18', # Compliance Administrator
        'e6d1a23a-da11-4be4-9570-befc86d067a7'  # Compliance Data Administrator
    )

    # Server-side filter: RoleManagement category within the window.
    # (Role name filtering is done client-side because the role name lives inside
    #  targetResources, which $filter can't reach reliably across tenants.)
    $filter = "category eq 'RoleManagement' and activityDateTime ge $StartIso and activityDateTime le $EndIso"

    Write-Host "Querying Entra directoryAudits $StartIso -> $EndIso (UTC)..." -ForegroundColor Cyan
    $entra = Get-MgAuditLogDirectoryAudit -Filter $filter -All -ErrorAction Stop

    # Keep only events that touch a Defender-relevant directory role (by name OR template id).
    $entra = $entra | Where-Object {
        $roleNames = @($_.TargetResources |
            ForEach-Object { $_.ModifiedProperties |
                Where-Object { $_.DisplayName -in 'Role.DisplayName','Role.TemplateId','RoleName' } |
                ForEach-Object { ($_.NewValue, $_.OldValue) } } )
        $blob = ($_.TargetResources.DisplayName + ' ' + ($roleNames -join ' '))
        ($DefenderRoles           | Where-Object { $blob -match [regex]::Escape($_) }) -or
        ($DefenderRoleTemplateIds  | Where-Object { $blob -match [regex]::Escape($_) })
    }

    if (-not $entra -or $entra.Count -eq 0) {
        Write-Host "No Entra directory-role changes for Defender-relevant roles in the last $Days day(s)." -ForegroundColor Green
    }
    else {
        $entraResults = foreach ($e in $entra) {
            # Resolve the role name from targetResources/modifiedProperties.
            $roleName = ($e.TargetResources |
                ForEach-Object { $_.ModifiedProperties } |
                Where-Object { $_.DisplayName -in 'Role.DisplayName','RoleName' } |
                ForEach-Object { ($_.NewValue, $_.OldValue) } |
                ForEach-Object { $_ -replace '^"|"$','' } |
                Where-Object { $_ } | Select-Object -First 1)
            if (-not $roleName) {
                $roleName = ($e.TargetResources | Where-Object { $_.Type -eq 'Role' } |
                             Select-Object -First 1 -ExpandProperty DisplayName)
            }

            # Who the change was applied TO (the user/SP being granted/removed).
            $targetUser = ($e.TargetResources |
                Where-Object { $_.Type -in 'User','ServicePrincipal','Group' } |
                Select-Object -First 1 -ExpandProperty UserPrincipalName)
            if (-not $targetUser) {
                $targetUser = ($e.TargetResources |
                    Where-Object { $_.Type -in 'User','ServicePrincipal','Group' } |
                    Select-Object -First 1 -ExpandProperty DisplayName)
            }

            [pscustomobject]@{
                TimeStampUTC = $e.ActivityDateTime
                Activity     = $e.ActivityDisplayName            # e.g. "Add member to role"
                Role         = $roleName
                TargetUser   = $targetUser
                InitiatedBy  = if ($e.InitiatedBy.User.UserPrincipalName) {
                                   $e.InitiatedBy.User.UserPrincipalName
                               } else { $e.InitiatedBy.App.DisplayName }
                Result       = $e.Result                         # success / failure
                Category     = $e.Category
                CorrelationId= $e.CorrelationId
            }
        }

        $entraResults = $entraResults | Sort-Object TimeStampUTC -Descending

        Write-Host "`n=== Entra directory-role changes (Defender-relevant) ===" -ForegroundColor White
        $entraResults | Select-Object TimeStampUTC,Activity,Role,TargetUser,InitiatedBy,Result |
            Format-Table -AutoSize -Wrap

        $entraResults | Export-Csv -Path $EntraOutCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Exported $($entraResults.Count) Entra directory-role record(s) to: $EntraOutCsv" -ForegroundColor Green
    }

    }  # end if ($IncludeEntraRoles)

    # ----- Group-backed role grants (GroupManagement category) -----
    # Defender roles assigned to a security group mean the real privilege grant is a
    # group-membership change. We can't map each group to a role assignment from the
    # audit log alone, so we report ALL member add/remove and let the reviewer triage
    # against their Defender role-assignable groups.
    if ($IncludeGroupChanges) {
        $groupFilter = "category eq 'GroupManagement' and activityDateTime ge $StartIso and activityDateTime le $EndIso"

        Write-Host "Querying Entra directoryAudits (GroupManagement) $StartIso -> $EndIso (UTC)..." -ForegroundColor Cyan
        $groupAudit = Get-MgAuditLogDirectoryAudit -Filter $groupFilter -All -ErrorAction Stop

        # Keep only membership add/remove (drop group create/update/settings noise).
        $groupAudit = $groupAudit | Where-Object { $_.ActivityDisplayName -match 'member' }

        if (-not $groupAudit -or $groupAudit.Count -eq 0) {
            Write-Host "No group membership changes in the last $Days day(s)." -ForegroundColor Green
        }
        else {
            $groupResults = foreach ($g in $groupAudit) {
                # The group whose membership changed.
                $groupName = ($g.TargetResources |
                    Where-Object { $_.Type -eq 'Group' } |
                    Select-Object -First 1 -ExpandProperty DisplayName)

                # The member added/removed (prefer UPN, fall back to display name).
                $member = ($g.TargetResources |
                    Where-Object { $_.Type -in 'User','ServicePrincipal' } |
                    Select-Object -First 1 -ExpandProperty UserPrincipalName)
                if (-not $member) {
                    $member = ($g.TargetResources |
                        Where-Object { $_.Type -in 'User','ServicePrincipal' } |
                        Select-Object -First 1 -ExpandProperty DisplayName)
                }

                [pscustomobject]@{
                    TimeStampUTC = $g.ActivityDateTime
                    Activity     = $g.ActivityDisplayName        # e.g. "Add member to group"
                    Group        = $groupName
                    Member       = $member
                    InitiatedBy  = if ($g.InitiatedBy.User.UserPrincipalName) {
                                       $g.InitiatedBy.User.UserPrincipalName
                                   } else { $g.InitiatedBy.App.DisplayName }
                    Result       = $g.Result
                    Category     = $g.Category
                    CorrelationId= $g.CorrelationId
                }
            }

            $groupResults = $groupResults | Sort-Object TimeStampUTC -Descending

            Write-Host "`n=== Group membership changes (review against Defender role-assignable groups) ===" -ForegroundColor White
            $groupResults | Select-Object TimeStampUTC,Activity,Group,Member,InitiatedBy,Result |
                Format-Table -AutoSize -Wrap
            Write-Host "NOTE: These are ALL group membership changes. Cross-reference against groups that hold Defender/Entra role assignments to find group-backed privilege grants." -ForegroundColor DarkYellow

            $groupResults | Export-Csv -Path $GroupOutCsv -NoTypeInformation -Encoding UTF8
            Write-Host "Exported $($groupResults.Count) group membership record(s) to: $GroupOutCsv" -ForegroundColor Green
        }
    }

    }
    catch {
        Write-Error "Entra directoryAudits section failed: $($_.Exception.Message)"
    }
    finally {
        if ($graphConnected) { Disconnect-MgGraph | Out-Null }
    }
}

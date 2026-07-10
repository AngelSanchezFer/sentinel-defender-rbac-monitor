<#
.SYNOPSIS
    Diagnostic script to extract raw audit JSON and identify field-name mismatches.
    
.DESCRIPTION
    This script pulls audit events and saves the raw JSON AuditData so we can inspect
    what field names are actually present in your tenant's audit events.
    
.EXAMPLE
    .\Diagnose-DefenderRbacAudit.ps1 -Days 7
#>

param(
    [int] $Days = 7,
    [string] $UserPrincipalName
)

# Prerequisites
function Resolve-RequiredModule {
    param([Parameter(Mandatory)][string] $Name)
    if (Get-Module -ListAvailable -Name $Name) { return }
    throw "Required module '$Name' is not installed. Install it: Install-Module $Name -Scope CurrentUser"
}

Resolve-RequiredModule -Name 'ExchangeOnlineManagement'
Import-Module ExchangeOnlineManagement -ErrorAction Stop

$StartDate = (Get-Date).AddDays(-$Days).ToUniversalTime()
$EndDate   = (Get-Date).ToUniversalTime()

Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
if ($UserPrincipalName) {
    Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ErrorAction Stop
} else {
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
}

try {
    Write-Host "Searching unified audit log for SecurityComplianceRBAC events: $StartDate -> $EndDate (UTC)" -ForegroundColor Cyan
    
    $allEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType 'SecurityComplianceRBAC' -ResultSize 5000 -ErrorAction Stop
    
    if (-not $allEvents -or $allEvents.Count -eq 0) {
        Write-Host "No SecurityComplianceRBAC events found in the last $Days day(s)." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Found $($allEvents.Count) audit event(s). Extracting and saving raw JSON..." -ForegroundColor Green
    
    # Save raw JSON to a file for inspection
    $jsonOutput = @()
    foreach ($event in $allEvents) {
        try {
            $auditData = $event.AuditData | ConvertFrom-Json
            $jsonOutput += @{
                TimeStampUTC = $event.CreationDate
                Operation    = $event.Operations
                UserIds      = $event.UserIds
                AuditData    = $auditData
            }
        } catch {
            Write-Warning "Failed to parse JSON for event at $($event.CreationDate): $_"
        }
    }
    
    # Save to JSON file
    $jsonFile = ".\DefenderXDR-RawAudit_$(Get-Date -Format yyyyMMdd-HHmmss).json"
    $jsonOutput | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFile -Encoding UTF8
    Write-Host "Saved raw audit JSON to: $jsonFile" -ForegroundColor Green
    
    # Extract and display field names
    Write-Host "`n=== Field Names Found in Audit JSON ===" -ForegroundColor White
    $allFieldNames = @()
    foreach ($event in $jsonOutput) {
        $auditData = $event.AuditData
        $allFieldNames += @($auditData.PSObject.Properties | Select-Object -ExpandProperty Name)
    }
    
    $uniqueFields = $allFieldNames | Sort-Object -Unique
    Write-Host "Total unique field names: $($uniqueFields.Count)" -ForegroundColor Cyan
    $uniqueFields | ForEach-Object { Write-Host "  - $_" }
    
    # Look for fields that might contain role or principal info
    Write-Host "`n=== Potential Role/Principal Fields ===" -ForegroundColor White
    $roleFields = $uniqueFields | Where-Object { $_ -match 'role|principal|user|identity|member|group' }
    if ($roleFields) {
        Write-Host "Fields matching 'role|principal|user|identity|member|group':" -ForegroundColor Yellow
        $roleFields | ForEach-Object { Write-Host "  ✓ $_" -ForegroundColor Green }
    } else {
        Write-Host "No obvious role/principal fields found." -ForegroundColor Yellow
    }
    
    # Show the structure of the first few events
    Write-Host "`n=== First Event Structure ===" -ForegroundColor White
    if ($jsonOutput[0]) {
        Write-Host "Operation: $($jsonOutput[0].Operation)" -ForegroundColor Cyan
        Write-Host "User: $($jsonOutput[0].UserIds)" -ForegroundColor Cyan
        Write-Host "`nAuditData fields:" -ForegroundColor Cyan
        $jsonOutput[0].AuditData.PSObject.Properties | ForEach-Object {
            $value = $_.Value
            if ($value -is [array]) {
                Write-Host "  $($_.Name): [Array with $($value.Count) items]"
            } elseif ($value -is [object] -and $value.GetType().Name -eq 'PSCustomObject') {
                Write-Host "  $($_.Name): [Object]"
            } else {
                Write-Host "  $($_.Name): $value"
            }
        }
    }
    
    Write-Host "`n✓ Open $jsonFile in a text editor to review the full structure." -ForegroundColor Green
    
} finally {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

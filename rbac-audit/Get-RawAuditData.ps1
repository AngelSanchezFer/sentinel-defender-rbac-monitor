<#
.SYNOPSIS
    Extract and display raw audit JSON to diagnose field-name mismatches.
    Shows the ACTUAL field names in your tenant's audit events.

.EXAMPLE
    .\Get-RawAuditData.ps1 -Days 7 -Top 10
#>

param(
    [int] $Days = 7,
    [int] $Top = 5,
    [string] $UserPrincipalName
)

function Resolve-RequiredModule {
    param([Parameter(Mandatory)][string] $Name)
    if (Get-Module -ListAvailable -Name $Name) { return }
    throw "Required module '$Name' is not installed. Install: Install-Module $Name -Scope CurrentUser"
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
    Write-Host "Searching SecurityComplianceRBAC events: $StartDate -> $EndDate (UTC)" -ForegroundColor Cyan
    
    $allEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType 'SecurityComplianceRBAC' -ResultSize 500 -ErrorAction Stop
    
    if (-not $allEvents -or $allEvents.Count -eq 0) {
        Write-Host "No SecurityComplianceRBAC events found in the last $Days day(s)." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Found $($allEvents.Count) audit event(s). Showing first $Top event(s)...`n" -ForegroundColor Green
    
    # Show first N events with full structure
    foreach ($i in 0..([Math]::Min($Top - 1, $allEvents.Count - 1))) {
        $event = $allEvents[$i]
        $auditData = $null
        
        try { 
            $auditData = $event.AuditData | ConvertFrom-Json 
        } catch {
            Write-Host "Failed to parse JSON for event $i" -ForegroundColor Yellow
            continue
        }
        
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "EVENT #$($i + 1)" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        Write-Host "`n[Top-level properties]"
        Write-Host "  CreationDate: $($event.CreationDate)"
        Write-Host "  UserIds:      $($event.UserIds)"
        Write-Host "  Operations:   $($event.Operations)"
        Write-Host "  RecordType:   $($event.RecordType)"
        
        Write-Host "`n[AuditData properties]"
        $auditData.PSObject.Properties | ForEach-Object {
            $value = $_.Value
            $displayValue = if ($value -is [array]) { 
                "[Array: $($value.Count) items]" 
            } elseif ($value -is [object] -and $value.GetType().Name -eq 'PSCustomObject') { 
                "[Object]" 
            } else { 
                $value 
            }
            Write-Host "  $($_.Name): $displayValue"
        }
        
        # Show Parameters details
        if ($auditData.Parameters) {
            Write-Host "`n[Parameters array]"
            $auditData.Parameters | ForEach-Object {
                Write-Host "    Name:  $($_.Name)"
                Write-Host "    Value: $($_.Value)"
                Write-Host ""
            }
        }
        
        # Show ExtendedProperties details
        if ($auditData.ExtendedProperties) {
            Write-Host "`n[ExtendedProperties array]"
            $auditData.ExtendedProperties | ForEach-Object {
                Write-Host "    Name:  $($_.Name)"
                Write-Host "    Value: $($_.Value)"
                Write-Host ""
            }
        }
        
        Write-Host ""
    }
    
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "✓ Above shows the ACTUAL structure of your audit events."
    Write-Host "  Look for field names containing 'role', 'user', 'member', 'identity'" -ForegroundColor Green
    
} catch {
    Write-Error "Query failed: $_"
} finally {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

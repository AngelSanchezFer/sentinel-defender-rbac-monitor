<#
.SYNOPSIS
    Find actual role CHANGE operations (not just read checks).
    Helps identify when users/roles are actually assigned.

.EXAMPLE
    .\Find-RoleAssignmentOperations.ps1 -Days 30
#>

param(
    [int] $Days = 30
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
Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop

try {
    Write-Host "Searching SecurityComplianceRBAC events (ignoring Check* operations)..." -ForegroundColor Cyan
    
    $allEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType 'SecurityComplianceRBAC' -ResultSize 500 -ErrorAction Stop
    
    # Filter OUT Check* operations (read noise)
    $changeEvents = $allEvents | Where-Object { $_.Operations -notlike 'Check*' }
    
    Write-Host "Total events: $($allEvents.Count)" -ForegroundColor Yellow
    Write-Host "Change events (not Check*): $($changeEvents.Count)" -ForegroundColor Green
    
    if ($changeEvents.Count -eq 0) {
        Write-Host "`n⚠️  NO ACTUAL ROLE CHANGE OPERATIONS FOUND in the last $Days days!" -ForegroundColor Yellow
        Write-Host "`nThis means:" -ForegroundColor Yellow
        Write-Host "  1. No role assignments have been recorded yet"
        Write-Host "  2. Role assignments may be happening via Entra roles (not Defender XDR)"
        Write-Host "  3. Check if auditing is enabled for role assignments"
        Write-Host "`nAll events found are READ CHECKS, not changes:" -ForegroundColor Yellow
        
        $allEvents | Select-Object CreationDate, Operations | Sort-Object CreationDate -Unique | Format-Table -AutoSize
        return
    }
    
    Write-Host "`n✓ Found $($changeEvents.Count) actual change event(s):`n" -ForegroundColor Green
    
    foreach ($event in $changeEvents | Sort-Object CreationDate -Descending) {
        $auditData = $null
        try { $auditData = $event.AuditData | ConvertFrom-Json } catch {}
        
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Date: $($event.CreationDate)" -ForegroundColor Cyan
        Write-Host "Operation: $($event.Operations)" -ForegroundColor Cyan
        Write-Host "User: $($event.UserIds)" -ForegroundColor Cyan
        
        if ($auditData) {
            Write-Host "`nAuditData properties:"
            $auditData.PSObject.Properties | ForEach-Object {
                $value = $_.Value
                if ($value -is [array]) { 
                    Write-Host "  $($_.Name): [Array with $($value.Count) items]"
                } elseif ($value -is [object] -and $value.GetType().Name -eq 'PSCustomObject') { 
                    Write-Host "  $($_.Name): [Object]"
                } else { 
                    Write-Host "  $($_.Name): $value"
                }
            }
            
            # Show Parameters if present
            if ($auditData.Parameters) {
                Write-Host "`n[Parameters]:"
                $auditData.Parameters | ForEach-Object {
                    Write-Host "    $($_.Name) = $($_.Value)"
                }
            }
        }
        Write-Host ""
    }
    
} finally {
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}

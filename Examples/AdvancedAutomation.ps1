# Advanced Automation Examples
# ===========================

# Example 1: Batch processing multiple domains
$domains = @("contoso.com", "fabrikam.com", "adventure-works.com")

foreach ($domain in $domains) {
    Write-Host "Processing $domain..." -ForegroundColor Cyan
    
    try {
        $result = Invoke-AzureOsintAdvanced -Domain $domain -OutputFile "$domain-batch-results.json" -NoAutoOpen -PassThru
        
        # Log summary
        $summary = @{
            Domain         = $domain
            TenantId       = $result.Results.TenantInfo.TenantId
            ValidUsers     = $result.Results.UserEnumeration.ValidUsers.Count
            Subdomains     = $result.Results.NetworkIntelligence.Subdomains.Count
            AzureResources = $result.Results.ExtendedAzureResources.StorageAccounts.Count
            ScanDuration   = $result.Results.ScanDuration
        }
        
        Write-Host "✅ $domain completed: $($summary.ValidUsers) users, $($summary.Subdomains) subdomains" -ForegroundColor Green
        
        # Export summary to CSV for reporting
        $summary | Export-Csv -Path "batch-summary.csv" -Append -NoTypeInformation
    }
    catch {
        Write-Host "❌ $domain failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Rate limiting - be respectful
    Start-Sleep -Seconds 30
}

# Example 2: Scheduled reconnaissance with alerting
function Start-ScheduledRecon {
    param(
        [string]$Domain,
        [string]$AlertThreshold = 10  # Alert if more than 10 users found
    )
    
    $result = Invoke-AzureOsintAdvanced -Domain $Domain -OutputFile "scheduled-$Domain-$(Get-Date -Format 'yyyyMMdd').json" -NoAutoOpen -PassThru
    
    $userCount = $result.Results.UserEnumeration.ValidUsers.Count
    
    if ($userCount -gt $AlertThreshold) {
        # Send alert (customize as needed)
        Write-Warning "ALERT: $Domain has $userCount valid users (threshold: $AlertThreshold)"
        
        # Example: Send email, webhook, or Teams notification
        # Send-MailMessage -To "security@company.com" -Subject "OSINT Alert: $Domain" -Body "Found $userCount users"
    }
    
    return $result
}

# Example 3: Integration with threat intelligence feeds
function Compare-WithThreatIntel {
    param([hashtable]$Results)
    
    $suspiciousIndicators = @()
    
    # Check for common attack indicators
    if ($Results.UserEnumeration.ValidUsers.Count -gt 50) {
        $suspiciousIndicators += "Large user base detected ($($Results.UserEnumeration.ValidUsers.Count) users)"
    }
    
    if ($Results.SecurityPosture.ConditionalAccessPolicies -eq $false) {
        $suspiciousIndicators += "No Conditional Access policies detected"
    }
    
    if ($Results.AuthenticationAnalysis.PasswordAuth -eq $true -and $Results.AuthenticationAnalysis.MFARequired -eq $false) {
        $suspiciousIndicators += "Password authentication without MFA"
    }
    
    return $suspiciousIndicators
}

Write-Host "Advanced automation examples loaded. Use Start-ScheduledRecon or Compare-WithThreatIntel functions." -ForegroundColor Yellow
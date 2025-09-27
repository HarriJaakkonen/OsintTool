# Custom Report Generation Examples
# =================================

# Example 1: Generate custom HTML report with additional analysis
function New-CustomOSINTReport {
    param(
        [hashtable]$Results,
        [string]$OutputPath = "custom-report.html"
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Custom OSINT Report - $($Results.Domain)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #0078d4; color: white; padding: 20px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #0078d4; }
        .risk-high { border-left-color: #d13438; }
        .risk-medium { border-left-color: #ff8c00; }
        .risk-low { border-left-color: #107c10; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Azure OSINT Report</h1>
        <h2>Domain: $($Results.Domain)</h2>
        <p>Generated: $(Get-Date)</p>
    </div>
    
    <div class="section">
        <h3>Executive Summary</h3>
        <p><strong>Tenant ID:</strong> $($Results.TenantInfo.TenantId)</p>
        <p><strong>Namespace Type:</strong> $($Results.TenantInfo.NamespaceType)</p>
        <p><strong>Users Found:</strong> $($Results.UserEnumeration.ValidUsers.Count)</p>
        <p><strong>Subdomains Found:</strong> $($Results.NetworkIntelligence.Subdomains.Count)</p>
    </div>
    
    <div class="section risk-high">
        <h3>Security Concerns</h3>
        <ul>
"@
    
    # Add security concerns based on findings
    if ($Results.UserEnumeration.ValidUsers.Count -gt 20) {
        $html += "<li>Large number of exposed user accounts ($($Results.UserEnumeration.ValidUsers.Count))</li>"
    }
    
    if ($Results.SecurityPosture.ConditionalAccessPolicies -eq $false) {
        $html += "<li>No Conditional Access policies detected</li>"
    }
    
    $html += @"
        </ul>
    </div>
    
    <div class="section">
        <h3>Valid User Accounts</h3>
        <table>
            <tr><th>Username</th><th>Method</th><th>Confidence</th></tr>
"@
    
    foreach ($user in $Results.UserEnumeration.ValidUsers) {
        $html += "<tr><td>$($user.Username)</td><td>$($user.Method)</td><td>$($user.Confidence)</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
    
    <div class="section">
        <h3>Discovered Subdomains</h3>
        <table>
            <tr><th>Subdomain</th><th>IP Addresses</th></tr>
"@
    
    foreach ($subdomain in $Results.NetworkIntelligence.Subdomains) {
        $ips = $subdomain.IPAddresses -join ", "
        $html += "<tr><td>$($subdomain.Subdomain)</td><td>$ips</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Custom report saved to: $OutputPath" -ForegroundColor Green
}

# Example 2: Export to JSON for SIEM integration
function Export-ForSIEM {
    param(
        [hashtable]$Results,
        [string]$OutputPath = "siem-export.json"
    )
    
    $siemData = @{
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        source = "AzureOSINTAdvanced"
        domain = $Results.Domain
        tenant_id = $Results.TenantInfo.TenantId
        events = @()
    }
    
    # Add user enumeration events
    foreach ($user in $Results.UserEnumeration.ValidUsers) {
        $siemData.events += @{
            event_type = "user_enumerated"
            username = $user.Username
            method = $user.Method
            confidence = $user.Confidence
            severity = "medium"
        }
    }
    
    # Add subdomain discovery events
    foreach ($subdomain in $Results.NetworkIntelligence.Subdomains) {
        $siemData.events += @{
            event_type = "subdomain_discovered"
            subdomain = $subdomain.Subdomain
            ip_addresses = $subdomain.IPAddresses
            severity = "low"
        }
    }
    
    $siemData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "SIEM export saved to: $OutputPath" -ForegroundColor Green
}

# Example usage:
# $results = Invoke-AzureOsintAdvanced -Domain "contoso.com" -PassThru -NoAutoOpen
# New-CustomOSINTReport -Results $results.Results -OutputPath "contoso-custom.html"
# Export-ForSIEM -Results $results.Results -OutputPath "contoso-siem.json"

Write-Host "Custom reporting functions loaded. Use New-CustomOSINTReport or Export-ForSIEM." -ForegroundColor Yellow
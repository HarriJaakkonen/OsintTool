# Basic Azure OSINT Advanced Usage Examples
# ============================================

# Example 1: Basic reconnaissance of a domain
Import-Module "$PSScriptRoot\..\AzureOsintAdvanced\AzureOsintAdvanced.psd1" -Force

# Simple domain reconnaissance
$results = Invoke-AzureOsintAdvanced -Domain "contoso.com" -OutputFile "contoso-results.json" -NoAutoOpen -PassThru

# Access the results
Write-Host "Tenant ID: $($results.Results.TenantInfo.TenantId)"
Write-Host "Found $($results.Results.UserEnumeration.ValidUsers.Count) valid users"
Write-Host "Found $($results.Results.NetworkIntelligence.Subdomains.Count) subdomains"

# Example 2: Reconnaissance with organization name for social media enrichment
$results2 = Invoke-AzureOsintAdvanced -Domain "microsoft.com" -OrganizationName "Microsoft Corporation" -OutputFile "microsoft-results.json" -NoAutoOpen -PassThru

# Example 3: Using specific tenant ID when domain discovery is ambiguous
$results3 = Invoke-AzureOsintAdvanced -Domain "contoso.com" -TenantId "12345678-1234-1234-1234-123456789012" -OutputFile "contoso-tenant-results.json" -NoAutoOpen -PassThru

# Example 4: Interactive mode (prompts for domain if not provided)
# Invoke-AzureOsintAdvanced -Interactive -OutputFile "interactive-results.json"

Write-Host "Examples completed successfully!"
# Azure AD OSINT Tool - Usage Examples
# This script demonstrates various usage patterns for the OSINT tools

param(
    [Parameter(Mandatory = $true)]
    [string]$TargetDomain,
    
    [string]$OutputDirectory = ".\OSINT-Results",
    
    [switch]$RunAdvanced,
    
    [switch]$GenerateReport
)

# Ensure output directory exists
if (!(Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

Write-Host "=== Azure AD/Entra ID OSINT Analysis ===" -ForegroundColor Cyan
Write-Host "Target Domain: $TargetDomain" -ForegroundColor Yellow
Write-Host "Output Directory: $OutputDirectory" -ForegroundColor Yellow
Write-Host ""

# Basic OSINT reconnaissance
Write-Host "[1/3] Running Basic OSINT Reconnaissance..." -ForegroundColor Green

try {
    $basicResults = & ".\Azure-OSINT-Tool.ps1" -Domain $TargetDomain -OutputFormat JSON -OutputFile "$OutputDirectory\basic-results.json" -Verbose
    
    if ($basicResults) {
        Write-Host "✓ Basic reconnaissance completed successfully" -ForegroundColor Green
        
        # Parse results for quick summary
        $results = Get-Content "$OutputDirectory\basic-results.json" | ConvertFrom-Json
        
        Write-Host "  - Tenant ID: $($results.TenantInfo.TenantId)" -ForegroundColor White
        Write-Host "  - Users Found: $($results.UserEnum.Count)" -ForegroundColor White
        Write-Host "  - Services Detected: $(($results.ServiceEnum.PSObject.Properties | Where-Object { $_.Value -eq $true }).Count)" -ForegroundColor White
        Write-Host "  - DNS Records: $($results.DNSRecon.Records.Count)" -ForegroundColor White
        Write-Host "  - Cloud Assets: $($results.CloudAssets.Count)" -ForegroundColor White
        
    } else {
        Write-Warning "Basic reconnaissance may have encountered issues"
    }
} catch {
    Write-Error "Failed to run basic reconnaissance: $($_.Exception.Message)"
}

# Advanced OSINT (if requested)
if ($RunAdvanced) {
    Write-Host "`n[2/3] Running Advanced OSINT Techniques..." -ForegroundColor Green
    
    try {
        # Load the advanced module
        . ".\Azure-OSINT-Advanced.ps1"
        
        # Extract organization name from domain (simple heuristic)
        $orgName = ($TargetDomain -split '\.')[0]
        $orgName = (Get-Culture).TextInfo.ToTitleCase($orgName)
        
        # Run advanced reconnaissance
        $advancedResults = Start-AdvancedReconnaissance -Domain $TargetDomain -OrganizationName $orgName
        
        # Export results
        Export-AdvancedResults -Results $advancedResults -OutputPath "$OutputDirectory\advanced-results.json"
        
        Write-Host "✓ Advanced reconnaissance completed successfully" -ForegroundColor Green
        Write-Host "  - Certificate Transparency: $($advancedResults.CertificateTransparency.Certificates.Count) certificates found" -ForegroundColor White
        Write-Host "  - Social Media: $($advancedResults.SocialMediaFootprint.Profiles.Count) profiles discovered" -ForegroundColor White
        Write-Host "  - Azure Resources: $($advancedResults.AzureResourceEnum.Resources.Count) resources enumerated" -ForegroundColor White
        
    } catch {
        Write-Error "Failed to run advanced reconnaissance: $($_.Exception.Message)"
    }
}

# Generate HTML report (if requested)
if ($GenerateReport) {
    Write-Host "`n[3/3] Generating Comprehensive Report..." -ForegroundColor Green
    
    try {
        # Run basic tool with HTML output
        & ".\Azure-OSINT-Tool.ps1" -Domain $TargetDomain -OutputFormat HTML -OutputFile "$OutputDirectory\report.html"
        
        Write-Host "✓ HTML report generated: $OutputDirectory\report.html" -ForegroundColor Green
        
        # Open report in default browser
        $reportPath = Join-Path $OutputDirectory "report.html"
        if (Test-Path $reportPath) {
            Write-Host "Opening report in default browser..." -ForegroundColor Yellow
            Start-Process $reportPath
        }
        
    } catch {
        Write-Error "Failed to generate HTML report: $($_.Exception.Message)"
    }
}

Write-Host "`n=== OSINT Analysis Complete ===" -ForegroundColor Cyan
Write-Host "Results saved to: $OutputDirectory" -ForegroundColor Yellow

# Summary of files created
Write-Host "`nFiles Created:" -ForegroundColor White
Get-ChildItem $OutputDirectory | ForEach-Object {
    $size = if ($_.Length -gt 1KB) { "{0:N1} KB" -f ($_.Length / 1KB) } else { "$($_.Length) bytes" }
    Write-Host "  - $($_.Name) ($size)" -ForegroundColor Gray
}

# Basic security reminder
Write-Host "`nSecurity Reminder:" -ForegroundColor Red
Write-Host "- Only perform reconnaissance on domains you own or have explicit permission to test" -ForegroundColor Yellow
Write-Host "- This tool is for authorized security testing and research purposes only" -ForegroundColor Yellow
Write-Host "- Respect rate limits and avoid aggressive scanning" -ForegroundColor Yellow

<#
.SYNOPSIS
    Demonstrates comprehensive usage of the Azure AD OSINT tools

.DESCRIPTION
    This example script shows how to use both the basic and advanced OSINT tools
    to perform comprehensive reconnaissance of Azure AD/Entra ID environments.

.PARAMETER TargetDomain
    The target domain to analyze (e.g., "contoso.com", "company.onmicrosoft.com")

.PARAMETER OutputDirectory
    Directory to save results (default: .\OSINT-Results)

.PARAMETER RunAdvanced
    Include advanced OSINT techniques (certificate transparency, social media, etc.)

.PARAMETER GenerateReport
    Generate an HTML report and open in browser

.EXAMPLE
    # Basic reconnaissance only
    .\OSINT-Example.ps1 -TargetDomain "contoso.com"

.EXAMPLE
    # Full reconnaissance with advanced techniques and HTML report
    .\OSINT-Example.ps1 -TargetDomain "company.onmicrosoft.com" -RunAdvanced -GenerateReport

.EXAMPLE
    # Custom output directory
    .\OSINT-Example.ps1 -TargetDomain "target.com" -OutputDirectory "C:\Security\Results" -RunAdvanced

.NOTES
    Requires the Azure-OSINT-Tool.ps1 and Azure-OSINT-Advanced.ps1 files in the same directory
    Ensure you have proper authorization before conducting reconnaissance activities
#>
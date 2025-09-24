#Requires -Version 7.0
<#
.SYNOPSIS
Advanced Azure AD/Entra ID OSINT Reconnaissance Module

.DESCRIPTION
Extended OSINT capabilities including certificate transparency logs, social media reconnaissance,
breach data correlation, and advanced enumeration techniques for Azure AD/Entra ID environments.

.NOTES
This module extends the basic Azure-OSINT-Tool.ps1 with advanced reconnaissance capabilities.
Use responsibly and ensure you have proper authorization before conducting reconnaissance.
#>

# Advanced OSINT Functions

function Get-CertificateTransparency {
    param(
        [string]$Domain
    )
    
    Write-OSINTLog "Searching Certificate Transparency logs for domain: $Domain" "INFO" Cyan
    
    $certificates = @()
    
    # Search crt.sh for certificate transparency logs
    try {
        $crtShUrl = "https://crt.sh/?q=%25.$Domain&output=json"
        $response = Invoke-WebRequestSafe -Uri $crtShUrl
        
        if ($response) {
            $crtData = $response.Content | ConvertFrom-Json
            
            foreach ($cert in $crtData | Select-Object -First 20) { # Limit results
                $certInfo = @{
                    CommonName = $cert.common_name
                    Issuer = $cert.issuer_name
                    NotBefore = $cert.not_before
                    NotAfter = $cert.not_after
                    SerialNumber = $cert.serial_number
                    SubdomainsFound = @()
                }
                
                # Extract subdomains from certificate
                if ($cert.name_value) {
                    $subdomains = $cert.name_value -split "`n" | Where-Object { $_ -like "*.$Domain" }
                    $certInfo.SubdomainsFound = $subdomains
                }
                
                $certificates += $certInfo
                Write-OSINTLog "Certificate found: $($cert.common_name)" "INFO" Green
            }
        }
    }
    catch {
        Write-OSINTLog "Certificate Transparency search failed: $($_.Exception.Message)" "ERROR" Red
    }
    
    return $certificates
}

function Get-SocialMediaFootprint {
    param(
        [string]$Domain,
        [string]$OrganizationName
    )
    
    Write-OSINTLog "Searching social media footprint for: $Domain" "INFO" Cyan
    
    $socialMedia = @{
        LinkedIn = @()
        Twitter = @()
        GitHub = @()
        Facebook = @()
        Instagram = @()
    }
    
    $companyName = $OrganizationName ?? $Domain.Split('.')[0]
    
    # LinkedIn Company Search
    try {
        $linkedInUrl = "https://www.linkedin.com/company/$companyName"
        $response = Invoke-WebRequestSafe -Uri $linkedInUrl
        
        if ($response -and $response.StatusCode -eq 200) {
            $socialMedia.LinkedIn += @{
                Url = $linkedInUrl
                Status = "Found"
                Platform = "LinkedIn"
            }
            Write-OSINTLog "LinkedIn company page found: $linkedInUrl" "INFO" Green
        }
    }
    catch {
        Write-OSINTLog "LinkedIn search failed: $($_.Exception.Message)" "ERROR" Red
    }
    
    # GitHub Organization Search
    try {
        $gitHubUrl = "https://api.github.com/orgs/$companyName"
        $response = Invoke-WebRequestSafe -Uri $gitHubUrl
        
        if ($response -and $response.StatusCode -eq 200) {
            $orgData = $response.Content | ConvertFrom-Json
            $socialMedia.GitHub += @{
                Url = $orgData.html_url
                Name = $orgData.name
                Description = $orgData.description
                PublicRepos = $orgData.public_repos
                Followers = $orgData.followers
                Status = "Found"
                Platform = "GitHub"
            }
            Write-OSINTLog "GitHub organization found: $($orgData.html_url)" "INFO" Green
        }
    }
    catch {
        # Organization might not exist
    }
    
    # Search for GitHub repositories related to domain
    try {
        $repoSearchUrl = "https://api.github.com/search/repositories?q=$Domain+in:readme"
        $response = Invoke-WebRequestSafe -Uri $repoSearchUrl
        
        if ($response) {
            $searchData = $response.Content | ConvertFrom-Json
            
            foreach ($repo in $searchData.items | Select-Object -First 5) {
                $socialMedia.GitHub += @{
                    Url = $repo.html_url
                    Name = $repo.full_name
                    Description = $repo.description
                    Stars = $repo.stargazers_count
                    Language = $repo.language
                    Type = "Repository"
                    Status = "Found"
                    Platform = "GitHub"
                }
                Write-OSINTLog "Related GitHub repository: $($repo.full_name)" "INFO" Green
            }
        }
    }
    catch {
        Write-OSINTLog "GitHub repository search failed: $($_.Exception.Message)" "ERROR" Red
    }
    
    return $socialMedia
}

function Get-BreachData {
    param(
        [string]$Domain,
        [string[]]$EmailAddresses
    )
    
    Write-OSINTLog "Checking breach databases for domain: $Domain" "INFO" Cyan
    
    $breachInfo = @{
        DomainBreaches = @()
        EmailBreaches = @()
    }
    
    # Note: This is a placeholder for breach database integration
    # In practice, you would integrate with services like:
    # - HaveIBeenPwned API (requires API key)
    # - DeHashed API
    # - BreachDirectory API
    # - Custom breach databases
    
    # Example placeholder implementation
    $knownBreaches = @(
        @{ Name = "LinkedIn"; Date = "2012"; Records = "167M"; Type = "Professional" },
        @{ Name = "Adobe"; Date = "2013"; Records = "153M"; Type = "Creative" },
        @{ Name = "Equifax"; Date = "2017"; Records = "147M"; Type = "Financial" }
    )
    
    # Add reference breach data to results
    $breachInfo.ReferenceBreaches = $knownBreaches
    $breachInfo.Note = "Placeholder implementation - integrate with HaveIBeenPwned, DeHashed, or other breach databases"
    
    Write-OSINTLog "Breach data check completed (placeholder implementation)" "INFO" Yellow
    Write-OSINTLog "In production, integrate with breach databases like HaveIBeenPwned" "INFO" Yellow
    
    return $breachInfo
}

function Get-EmailPatterns {
    param(
        [string]$Domain,
        [string[]]$KnownUsers
    )
    
    Write-OSINTLog "Analyzing email patterns for domain: $Domain" "INFO" Cyan
    
    $emailPatterns = @()
    
    # Common email patterns
    $patterns = @(
        "{first}.{last}@{domain}",
        "{first}{last}@{domain}",
        "{f}{last}@{domain}",
        "{first}{l}@{domain}",
        "{first}@{domain}",
        "{last}@{domain}",
        "{first}_{last}@{domain}",
        "{first}-{last}@{domain}"
    )
    
    # Test patterns with common names
    $testNames = @(
        @{ First = "john"; Last = "doe" },
        @{ First = "jane"; Last = "smith" },
        @{ First = "admin"; Last = "user" },
        @{ First = "test"; Last = "account" }
    )
    
    foreach ($pattern in $patterns) {
        foreach ($testName in $testNames) {
            $email = $pattern.Replace("{first}", $testName.First).Replace("{last}", $testName.Last).Replace("{f}", $testName.First[0]).Replace("{l}", $testName.Last[0]).Replace("{domain}", $Domain)
            
            # In a real implementation, you would test these email addresses
            # For now, just record the patterns
            $emailPatterns += @{
                Pattern = $pattern
                Example = $email
                Confidence = "Unknown"
            }
        }
    }
    
    Write-OSINTLog "Email pattern analysis completed. Found $($patterns.Count) patterns" "INFO" Green
    return $emailPatterns
}

function Get-AzureResourceEnumeration {
    param(
        [string]$Domain,
        [string]$TenantId
    )
    
    Write-OSINTLog "Enumerating Azure resources for domain: $Domain" "INFO" Cyan
    
    $azureResources = @{
        StorageAccounts = @()
        WebApps = @()
        KeyVaults = @()
        Databases = @()
        CDNEndpoints = @()
    }
    
    $baseName = $Domain.Split('.')[0]
    $variations = @(
        $baseName,
        "$baseName-prod",
        "$baseName-dev", 
        "$baseName-test",
        "$baseName-staging",
        "$baseName-backup",
        "$baseName-data",
        "$baseName-api",
        "$baseName-web",
        "$baseName-app"
    )
    
    # Test Azure Storage Accounts
    foreach ($variation in $variations) {
        try {
            $storageUrl = "https://$variation.blob.core.windows.net"
            $response = Invoke-WebRequestSafe -Uri $storageUrl -TimeoutSec 5
            
            if ($response) {
                $azureResources.StorageAccounts += @{
                    Name = $variation
                    Url = $storageUrl
                    Type = "Blob Storage"
                    Status = "Accessible"
                }
                Write-OSINTLog "Azure Storage found: $storageUrl" "INFO" Green
                
                # Try to enumerate containers
                try {
                    $containerUrl = "$storageUrl/?comp=list"
                    $containerResponse = Invoke-WebRequestSafe -Uri $containerUrl -TimeoutSec 5
                    if ($containerResponse) {
                        Write-OSINTLog "Storage containers may be listable: $containerUrl" "INFO" Yellow
                    }
                }
                catch { }
            }
        }
        catch { }
    }
    
    # Test Azure Web Apps
    foreach ($variation in $variations) {
        try {
            $webAppUrl = "https://$variation.azurewebsites.net"
            $response = Invoke-WebRequestSafe -Uri $webAppUrl -TimeoutSec 5
            
            if ($response -and $response.StatusCode -eq 200) {
                $azureResources.WebApps += @{
                    Name = $variation
                    Url = $webAppUrl
                    Type = "Web App"
                    Status = "Accessible"
                    Headers = $response.Headers
                }
                Write-OSINTLog "Azure Web App found: $webAppUrl" "INFO" Green
            }
        }
        catch { }
    }
    
    # Test Key Vault naming patterns
    foreach ($variation in $variations) {
        try {
            $keyVaultUrl = "https://$variation.vault.azure.net"
            $response = Invoke-WebRequestSafe -Uri $keyVaultUrl -TimeoutSec 5
            
            if ($response) {
                $azureResources.KeyVaults += @{
                    Name = $variation
                    Url = $keyVaultUrl
                    Type = "Key Vault"
                    Status = "Exists"
                }
                Write-OSINTLog "Key Vault found: $keyVaultUrl" "INFO" Green
            }
        }
        catch { }
    }
    
    # Test SQL Database patterns
    foreach ($variation in $variations) {
        try {
            $sqlUrl = "https://$variation.database.windows.net"
            $response = Invoke-WebRequestSafe -Uri $sqlUrl -TimeoutSec 5
            
            if ($response) {
                $azureResources.Databases += @{
                    Name = $variation
                    Url = $sqlUrl
                    Type = "SQL Database"
                    Status = "Exists"
                }
                Write-OSINTLog "SQL Database server found: $sqlUrl" "INFO" Green
            }
        }
        catch { }
    }
    
    Write-OSINTLog "Azure resource enumeration completed" "INFO" Cyan
    return $azureResources
}

function Get-OfficeDocumentMetadata {
    param(
        [string]$Domain
    )
    
    Write-OSINTLog "Searching for Office documents with metadata for domain: $Domain" "INFO" Cyan
    
    $documents = @()
    
    # Google dorking for Office documents
    $fileTypes = @("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx")
    
    foreach ($fileType in $fileTypes) {
        try {
            # Note: In practice, you would use Google Custom Search API or similar
            # This is a placeholder for document discovery
            $searchQuery = "site:$Domain filetype:$fileType"
            
            Write-OSINTLog "Would search for: $searchQuery" "INFO" Yellow
            
            # Placeholder result
            $documents += @{
                FileType = $fileType
                SearchQuery = $searchQuery
                Status = "Placeholder"
            }
        }
        catch {
            Write-OSINTLog "Document search failed for $fileType : $($_.Exception.Message)" "ERROR" Red
        }
    }
    
    Write-OSINTLog "Document metadata search completed (placeholder implementation)" "INFO" Yellow
    return $documents
}

function Start-AdvancedReconnaissance {
    param(
        [string]$Domain,
        [string]$TenantId = $null,
        [string]$OrganizationName = $null
    )
    
    Write-Host "`n==== Advanced Azure OSINT Reconnaissance ====" -ForegroundColor Cyan
    Write-Host "Target: $Domain" -ForegroundColor White
    
    $advancedResults = @{
        Domain = $Domain
        TenantId = $TenantId
        Certificates = @()
        SocialMedia = @{}
        BreachData = @{}
        EmailPatterns = @()
        AzureResources = @{}
        Documents = @()
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    }
    
    # Certificate Transparency
    Write-Host "`n[1/6] Certificate Transparency Logs" -ForegroundColor Yellow
    $advancedResults.Certificates = Get-CertificateTransparency -Domain $Domain
    
    # Social Media Footprint
    Write-Host "`n[2/6] Social Media Footprint" -ForegroundColor Yellow
    $advancedResults.SocialMedia = Get-SocialMediaFootprint -Domain $Domain -OrganizationName $OrganizationName
    
    # Breach Data
    Write-Host "`n[3/6] Breach Data Analysis" -ForegroundColor Yellow
    $advancedResults.BreachData = Get-BreachData -Domain $Domain
    
    # Email Patterns
    Write-Host "`n[4/6] Email Pattern Analysis" -ForegroundColor Yellow
    $advancedResults.EmailPatterns = Get-EmailPatterns -Domain $Domain
    
    # Azure Resource Enumeration
    Write-Host "`n[5/6] Azure Resource Enumeration" -ForegroundColor Yellow
    $advancedResults.AzureResources = Get-AzureResourceEnumeration -Domain $Domain -TenantId $TenantId
    
    # Document Metadata
    Write-Host "`n[6/6] Office Document Metadata" -ForegroundColor Yellow
    $advancedResults.Documents = Get-OfficeDocumentMetadata -Domain $Domain
    
    Write-Host "`nAdvanced reconnaissance completed!" -ForegroundColor Green
    
    # Display summary
    Write-Host "`n---- Advanced Results Summary ----" -ForegroundColor Cyan
    Write-Host "Certificates found: $($advancedResults.Certificates.Count)" -ForegroundColor Gray
    Write-Host "GitHub repositories: $($advancedResults.SocialMedia.GitHub.Count)" -ForegroundColor Gray
    Write-Host "Azure Storage Accounts: $($advancedResults.AzureResources.StorageAccounts.Count)" -ForegroundColor Gray
    Write-Host "Azure Web Apps: $($advancedResults.AzureResources.WebApps.Count)" -ForegroundColor Gray
    Write-Host "Key Vaults: $($advancedResults.AzureResources.KeyVaults.Count)" -ForegroundColor Gray
    
    return $advancedResults
}

# Export advanced results
function Export-AdvancedResults {
    param(
        [hashtable]$Results,
        [string]$OutputPath = "advanced-osint-results.json"
    )
    
    $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Advanced results exported to: $OutputPath" -ForegroundColor Green
}

# Example usage:
# $advancedResults = Start-AdvancedReconnaissance -Domain "contoso.com" -OrganizationName "Contoso"
# Export-AdvancedResults -Results $advancedResults -OutputPath "contoso-advanced.json"
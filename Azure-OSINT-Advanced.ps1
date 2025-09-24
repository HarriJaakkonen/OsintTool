#Requires -Version 7.0
<#
.SYNOPSIS
Advanced Azure AD/Entra ID OSINT Reconnaissance Module

.DESCRIPTION
Extended OSINT capabilities including certificate transparency logs, social media reconnaissance,
breach data correlation, and advanced enumeration techniques for Azure AD/Entra ID environments.

.PARAMETER Domain
The target domain to investigate (e.g., contoso.com)

.PARAMETER TenantId
Optional: Specific tenant ID to investigate

.PARAMETER OrganizationName
Optional: Organization name for social media searches

.PARAMETER OutputFile
Output file path for results (default: advanced-osint-results.json)

.PARAMETER Help
Show help information

.EXAMPLE
.\Azure-OSINT-Advanced.ps1 -Domain "contoso.com"

.EXAMPLE
.\Azure-OSINT-Advanced.ps1 -Domain "contoso.com" -OrganizationName "Contoso Corp"

.NOTES
This module extends the basic Azure-OSINT-Tool.ps1 with advanced reconnaissance capabilities.
Use responsibly and ensure you have proper authorization before conducting reconnaissance.
#>

# Parameter definition for command-line usage
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Domain,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$OrganizationName,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFile = "advanced-osint-results.json",
    
    [Parameter(Mandatory = $false)]
    [switch]$Help
)

# =============================================================================
# HELPER FUNCTIONS - Enhanced Error Handling & Visual Feedback
# =============================================================================

# Global error tracking
$script:ErrorCount = 0
$script:VerboseErrors = $false  # Set to $true to see detailed error messages

function Write-OSINTLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [switch]$NoTimestamp
    )
    
    if (-not $NoTimestamp) {
        $timestamp = Get-Date -Format "HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
    } else {
        $logMessage = $Message
    }
    Write-Host $logMessage -ForegroundColor $Color
}

function Write-OSINTError {
    param(
        [string]$Operation,
        [string]$Target = "",
        [string]$Reason = "",
        [switch]$Silent
    )
    
    $script:ErrorCount++
    
    if (-not $Silent) {
        if ($script:VerboseErrors) {
            Write-OSINTLog "❌ $Operation failed: $Target - $Reason" "ERROR" Red
        } else {
            # Just show a simple indicator for failed operations
            Write-Host "❌" -ForegroundColor Red -NoNewline
        }
    }
}

function Write-OSINTSuccess {
    param(
        [string]$Message,
        [switch]$Inline
    )
    
    if ($Inline) {
        Write-Host "✅" -ForegroundColor Green -NoNewline
    } else {
        Write-OSINTLog "✅ $Message" "SUCCESS" Green
    }
}

function Write-OSINTProgress {
    param(
        [string]$Operation,
        [int]$Current = 0,
        [int]$Total = 0,
        [switch]$Complete
    )
    
    if ($Complete) {
        Write-Host "✅ $Operation completed" -ForegroundColor Green
    } elseif ($Total -gt 0) {
        Write-Host "🔄 $Operation ($Current/$Total)..." -ForegroundColor Cyan
    } else {
        Write-Host "🔄 $Operation..." -ForegroundColor Cyan
    }
}

function Invoke-WebRequestSafe {
    param(
        [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Method = "GET",
        [int]$TimeoutSec = 10,
        [switch]$SuppressErrors
    )
    
    try {
        $defaultHeaders = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        $allHeaders = $defaultHeaders + $Headers
        
        $response = Invoke-WebRequest -Uri $Uri -Headers $allHeaders -Method $Method -TimeoutSec $TimeoutSec -ErrorAction Stop
        return $response
    }
    catch {
        if (-not $SuppressErrors) {
            $hostname = ([System.Uri]$Uri).Host
            $shortReason = switch -Regex ($_.Exception.Message) {
                "timeout|timed out" { "Timeout" }
                "404|Not Found" { "Not Found" }
                "401|Unauthorized" { "Unauthorized" }
                "403|Forbidden" { "Forbidden" }
                "500|Internal Server Error" { "Server Error" }
                "No such host|could not be resolved" { "DNS Error" }
                "SSL|TLS" { "SSL Error" }
                default { "Connection Failed" }
            }
            Write-OSINTError -Operation "Web Request" -Target $hostname -Reason $shortReason -Silent
        }
        return $null
    }
}

# Visual feedback for bulk operations
function Start-OSINTBulkOperation {
    param(
        [string]$OperationName,
        [int]$ItemCount
    )
    
    Write-OSINTProgress -Operation $OperationName -Total $ItemCount
    Write-Host "  Progress: " -ForegroundColor Gray -NoNewline
}

function Update-OSINTBulkProgress {
    param(
        [bool]$Success
    )
    
    if ($Success) {
        Write-Host "✅" -ForegroundColor Green -NoNewline
    } else {
        Write-Host "❌" -ForegroundColor Red -NoNewline
    }
}

function Complete-OSINTBulkOperation {
    param(
        [string]$OperationName,
        [int]$SuccessCount,
        [int]$TotalCount
    )
    
    Write-Host ""  # New line after progress indicators
    $failCount = $TotalCount - $SuccessCount
    
    if ($SuccessCount -gt 0) {
        Write-OSINTLog "✅ $OperationName completed: $SuccessCount found, $failCount failed" "SUCCESS" Green
    } else {
        Write-OSINTLog "⚠️  $OperationName completed: No results found ($failCount attempts)" "WARNING" Yellow
    }
}

# =============================================================================
# ADVANCED OSINT FUNCTIONS - Enhanced with AADInternals-like capabilities
# =============================================================================

# Visual formatting functions
function Write-OSINTBanner {
    param([string]$Title, [string]$Subtitle = "")
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host " $Title".PadRight(76) -ForegroundColor White -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    if ($Subtitle) {
        Write-Host "║" -ForegroundColor Cyan -NoNewline
        Write-Host " $Subtitle".PadRight(76) -ForegroundColor Gray -NoNewline
        Write-Host "║" -ForegroundColor Cyan
    }
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Write-OSINTSection {
    param([string]$Title, [string]$Icon = "►")
    Write-Host ""
    Write-Host "$Icon $Title" -ForegroundColor Yellow
    Write-Host "─" * ($Title.Length + 3) -ForegroundColor DarkYellow
}

function Write-OSINTProperty {
    param([string]$Property, [string]$Value, [ConsoleColor]$Color = [ConsoleColor]::White)
    $paddedProperty = $Property.PadRight(25)
    Write-Host "  $paddedProperty : " -ForegroundColor Gray -NoNewline
    Write-Host $Value -ForegroundColor $Color
}

function Write-OSINTList {
    param([string[]]$Items, [string]$Prefix = "  •")
    foreach ($item in $Items) {
        Write-Host "$Prefix $item" -ForegroundColor Cyan
    }
}

# Enhanced Tenant Information Discovery (AADInternals-like)
function Get-EntraIDTenantInfo {
    param([string]$Domain)
    
    Write-OSINTSection "Entra ID Tenant Discovery" "🔍"
    
    $tenantInfo = @{
        Domain              = $Domain
        TenantId            = $null
        TenantName          = $null
        TenantType          = $null
        TenantRegion        = $null
        AuthenticationUrl   = $null
        FederationMetadata  = $null
        OpenIdConfiguration = $null
        TenantBrandingUrls  = @()
        ManagedDomains      = @()
        FederatedDomains    = @()
        NameSpaceType       = $null
        Federation          = $null
        CloudInstance       = $null
        PreferredUserName   = $null
        TenantRegionalScope = $null
        Endpoints           = @{}
        Capabilities        = @()
    }
    
    # Method 1: OpenID Connect Discovery Endpoint
    Write-OSINTProgress "OpenID Connect Discovery"
    try {
        $openIdUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid_configuration"
        $response = Invoke-WebRequestSafe -Uri $openIdUrl -SuppressErrors
        
        if ($response) {
            $openIdConfig = $response.Content | ConvertFrom-Json
            $tenantInfo.OpenIdConfiguration = $openIdConfig
            $tenantInfo.TenantId = ($openIdConfig.issuer -split '/')[-2]
            $tenantInfo.AuthenticationUrl = $openIdConfig.authorization_endpoint
            $tenantInfo.CloudInstance = ($openIdConfig.issuer -split '/')[2]
            
            # Extract endpoints
            $tenantInfo.Endpoints = @{
                Authorization = $openIdConfig.authorization_endpoint
                Token         = $openIdConfig.token_endpoint
                UserInfo      = $openIdConfig.userinfo_endpoint
                EndSession    = $openIdConfig.end_session_endpoint
                JwksUri       = $openIdConfig.jwks_uri
                Issuer        = $openIdConfig.issuer
            }
            
            Write-OSINTSuccess "OpenID Connect Discovery"
            Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
            Write-OSINTProperty "Cloud Instance" $tenantInfo.CloudInstance Green
        } else {
            Write-OSINTError "OpenID Connect Discovery" $Domain "Configuration not accessible" -Silent
        }
    }
    catch {
        Write-OSINTError "OpenID Connect Discovery" $Domain $_.Exception.Message
    }
    
    # Method 2: Microsoft Graph Discovery
    Write-OSINTProgress "Microsoft Graph Discovery"
    try {
        $graphUrl = "https://graph.microsoft.com/v1.0/domains/$Domain"
        $response = Invoke-WebRequestSafe -Uri $graphUrl -SuppressErrors
        if ($response -and $response.StatusCode -eq 401) {
            Write-OSINTSuccess "Microsoft Graph Discovery"
            Write-OSINTProperty "Graph API" "Domain exists (401 Unauthorized)" Yellow
        } else {
            Write-OSINTError "Microsoft Graph Discovery" $Domain "Domain not found" -Silent
        }
    }
    catch { 
        Write-OSINTError "Microsoft Graph Discovery" $Domain $_.Exception.Message
    }
    
    # Method 3: Federation Metadata Discovery
    Write-OSINTProgress "Federation Metadata Discovery"
    try {
        $federationUrl = "https://login.microsoftonline.com/$Domain/FederationMetadata/2007-06/FederationMetadata.xml"
        $federationResponse = Invoke-WebRequestSafe -Uri $federationUrl -SuppressErrors
        
        if ($federationResponse) {
            $tenantInfo.FederationMetadata = $federationResponse.Content
            
            # Parse XML to extract detailed tenant info
            $xml = [xml]$federationResponse.Content
            $entityDescriptor = $xml.EntityDescriptor
            
            if ($entityDescriptor) {
                $tenantInfo.TenantName = $entityDescriptor.entityID
                Write-OSINTSuccess "Federation Metadata Discovery"
                Write-OSINTProperty "Federation Entity ID" $entityDescriptor.entityID Green
                
                # Extract signing certificates
                $certificates = $xml.SelectNodes("//ds:X509Certificate", @{ds = "http://www.w3.org/2000/09/xmldsig#" })
                Write-OSINTProperty "Signing Certificates" $certificates.Count Green
            }
        } else {
            Write-OSINTError "Federation Metadata Discovery" $Domain "Metadata not available" -Silent
        }
    }
    catch {
        Write-OSINTError "Federation Metadata Discovery" $Domain $_.Exception.Message
    }
    
    # Method 4: Tenant Region Discovery via AutoDiscover
    Write-OSINTLog "Discovering tenant region and namespace type..." "INFO" Cyan
    try {
        $autoDiscoverUrl = "https://outlook.office365.com/autodiscover/autodiscover.svc"
        $soapEnvelope = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
               xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover"
               xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soap:Header>
    <a:RequestedServerVersion>Exchange2016</a:RequestedServerVersion>
  </soap:Header>
  <soap:Body>
    <a:GetDomainSettingsRequestMessage>
      <a:Request>
        <a:Domains>
          <a:Domain>$Domain</a:Domain>
        </a:Domains>
        <a:RequestedSettings>
          <a:Setting>ExternalEwsUrl</a:Setting>
          <a:Setting>UserDisplayName</a:Setting>
        </a:RequestedSettings>
      </a:Request>
    </a:GetDomainSettingsRequestMessage>
  </soap:Body>
</soap:Envelope>
"@
        
        $headers = @{
            "Content-Type" = "text/xml; charset=utf-8"
            "SOAPAction"   = '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetDomainSettings"'
        }
        
        $autodiscoverResponse = Invoke-RestMethod -Uri $autoDiscoverUrl -Method POST -Body $soapEnvelope -Headers $headers -ErrorAction SilentlyContinue
        if ($autodiscoverResponse) {
            Write-OSINTProperty "AutoDiscover" "Response received" Green
        }
    }
    catch { }
    
    # Method 5: Realm Discovery (Namespace Type)
    Write-OSINTLog "Discovering realm information..." "INFO" Cyan
    try {
        $realmUrl = "https://login.microsoftonline.com/common/userrealm/$Domain?api-version=1.0"
        $response = Invoke-WebRequestSafe -Uri $realmUrl
        
        if ($response) {
            $realmData = $response.Content | ConvertFrom-Json
            $tenantInfo.NameSpaceType = $realmData.NameSpaceType
            $tenantInfo.Federation = $realmData.federation_protocol
            $tenantInfo.CloudInstance = $realmData.cloud_instance_name
            $tenantInfo.PreferredUserName = $realmData.preferred_username
            
            Write-OSINTProperty "Namespace Type" $realmData.NameSpaceType $(if ($realmData.NameSpaceType -eq "Managed") { "Green" } else { "Yellow" })
            Write-OSINTProperty "Federation Protocol" $realmData.federation_protocol
            Write-OSINTProperty "Cloud Instance Name" $realmData.cloud_instance_name
            
            if ($realmData.federation_metadata_url) {
                Write-OSINTProperty "Federation Metadata URL" $realmData.federation_metadata_url Yellow
            }
        }
    }
    catch {
        Write-OSINTLog "Realm discovery failed: $($_.Exception.Message)" "ERROR" Red
    }
    
    return $tenantInfo
}

# Enhanced Domain Enumeration
function Get-DomainEnumeration {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "Domain Enumeration & Validation" "🌐"
    
    $domainInfo = @{
        PrimaryDomain    = $Domain
        ManagedDomains   = @()
        FederatedDomains = @()
        InitialDomain    = $null
        CustomDomains    = @()
        SubDomains       = @()
        RelatedDomains   = @()
        DomainValidation = @{}
    }
    
    # Test common Microsoft domain patterns
    Write-OSINTLog "Testing Microsoft service domain patterns..." "INFO" Cyan
    
    $baseName = $Domain.Split('.')[0]
    $microsoftDomains = @(
        "$baseName.onmicrosoft.com",
        "$baseName.mail.onmicrosoft.com",
        "$baseName.sharepoint.com",
        "$baseName-my.sharepoint.com",
        "$baseName.dynamics.com",
        "$baseName.crm.dynamics.com",
        "$baseName.powerbi.com"
    )
    
    foreach ($testDomain in $microsoftDomains) {
        try {
            # Test OpenID configuration for each domain
            $testUrl = "https://login.microsoftonline.com/$testDomain/.well-known/openid_configuration"
            $response = Invoke-WebRequestSafe -Uri $testUrl -TimeoutSec 5
            
            if ($response) {
                $domainInfo.RelatedDomains += $testDomain
                Write-OSINTProperty "Related Domain" $testDomain Green
            }
        }
        catch { }
        
        # Test DNS resolution
        try {
            $dnsResult = Resolve-DnsName -Name $testDomain -Type A -ErrorAction SilentlyContinue
            if ($dnsResult) {
                $domainInfo.ManagedDomains += @{
                    Domain      = $testDomain
                    Type        = "Microsoft Managed"
                    IPAddresses = $dnsResult.IPAddress
                }
                Write-OSINTProperty "DNS Resolved" $testDomain Green
            }
        }
        catch { }
    }
    
    return $domainInfo
}

# Enhanced Azure Service Discovery
function Get-AzureServiceDiscovery {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "Azure & Microsoft 365 Service Discovery" "☁️"
    
    $services = @{
        EntraID     = $null
        Exchange    = $null
        SharePoint  = $null
        Teams       = $null
        OneDrive    = $null
        PowerBI     = $null
        Dynamics    = $null
        Intune      = $null
        DefenderXDR = $null
        Compliance  = $null
        AzureAD     = $null
        Office365   = $null
    }
    
    # Test Entra ID/Azure AD
    Write-OSINTLog "Testing Entra ID (Azure AD) presence..." "INFO" Cyan
    if ($TenantId) {
        try {
            $aadUrl = "https://graph.microsoft.com/v1.0/organization"
            $response = Invoke-WebRequestSafe -Uri $aadUrl -TimeoutSec 5
            if ($response -and $response.StatusCode -eq 401) {
                $services.EntraID = @{ Status = "Active"; Evidence = "Graph API accessible" }
                Write-OSINTProperty "Entra ID" "✓ Active (Graph API)" Green
            }
        }
        catch { }
    }
    
    # Test Exchange Online
    Write-OSINTLog "Testing Exchange Online..." "INFO" Cyan
    try {
        $exchangeUrl = "https://outlook.office365.com/autodiscover/autodiscover.xml?EmailAddress=test@$Domain"
        $response = Invoke-WebRequestSafe -Uri $exchangeUrl -TimeoutSec 5
        if ($response) {
            $services.Exchange = @{ Status = "Active"; Evidence = "AutoDiscover accessible" }
            Write-OSINTProperty "Exchange Online" "✓ Active" Green
        }
    }
    catch { }
    
    # Test SharePoint Online
    Write-OSINTLog "Testing SharePoint Online..." "INFO" Cyan
    $baseName = $Domain.Split('.')[0]
    try {
        $spUrl = "https://$baseName.sharepoint.com"
        $response = Invoke-WebRequestSafe -Uri $spUrl -TimeoutSec 5
        if ($response) {
            $services.SharePoint = @{ 
                Status    = "Active"
                TenantUrl = $spUrl
                Evidence  = "SharePoint tenant accessible"
            }
            Write-OSINTProperty "SharePoint Online" "✓ Active - $spUrl" Green
        }
    }
    catch { }
    
    # Test OneDrive for Business
    Write-OSINTLog "Testing OneDrive for Business..." "INFO" Cyan
    try {
        $odUrl = "https://$baseName-my.sharepoint.com"
        $response = Invoke-WebRequestSafe -Uri $odUrl -TimeoutSec 5
        if ($response) {
            $services.OneDrive = @{
                Status    = "Active"
                TenantUrl = $odUrl
                Evidence  = "OneDrive tenant accessible"
            }
            Write-OSINTProperty "OneDrive for Business" "✓ Active - $odUrl" Green
        }
    }
    catch { }
    
    # Test Microsoft Teams
    Write-OSINTLog "Testing Microsoft Teams..." "INFO" Cyan
    try {
        $teamsUrl = "https://teams.microsoft.com/l/team/channel-id?groupId=$Domain"
        $response = Invoke-WebRequestSafe -Uri $teamsUrl -TimeoutSec 5
        if ($response) {
            $services.Teams = @{ Status = "Active"; Evidence = "Teams accessible" }
            Write-OSINTProperty "Microsoft Teams" "✓ Active" Green
        }
    }
    catch { }
    
    return $services
}

# Enhanced User Enumeration with Advanced Techniques
function Get-AdvancedUserEnumeration {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "Advanced User Enumeration" "👥"
    
    $userEnum = @{
        ValidUsers          = @()
        InvalidUsers        = @()
        TimingAttackResults = @()
        OneDriveUsers       = @()
        TeamsUsers          = @()
        Methods             = @()
    }
    
    # Common username patterns
    $commonUsers = @(
        "admin", "administrator", "root", "test", "guest", "user",
        "service", "info", "contact", "support", "help", "sales",
        "marketing", "hr", "it", "security", "finance", "legal",
        "compliance", "ceo", "cto", "cfo", "manager", "director"
    )
    
    # Method 1: OneDrive Enumeration (Most reliable)
    Write-OSINTLog "Enumerating users via OneDrive for Business..." "INFO" Cyan
    $baseName = $Domain.Split('.')[0]
    
    foreach ($username in $commonUsers) {
        try {
            $oneDriveUrl = "https://$baseName-my.sharepoint.com/personal/$($username)_$($Domain.Replace('.', '_'))"
            $response = Invoke-WebRequestSafe -Uri $oneDriveUrl -TimeoutSec 3
            
            if ($response) {
                $statusCode = $response.StatusCode
                if ($statusCode -eq 403 -or $statusCode -eq 200) {
                    $userEnum.ValidUsers += @{
                        Username   = "$username@$Domain"
                        Method     = "OneDrive"
                        Confidence = "High"
                        Evidence   = "OneDrive accessible (Status: $statusCode)"
                        Url        = $oneDriveUrl
                    }
                    Write-OSINTProperty "Valid User" "$username@$Domain" Green
                }
            }
        }
        catch { }
        Start-Sleep -Milliseconds 100  # Rate limiting
    }
    
    # Method 2: Microsoft Graph User Validation
    Write-OSINTLog "Testing Graph API user validation..." "INFO" Cyan
    foreach ($username in $commonUsers[0..5]) {
        # Limit to avoid rate limiting
        try {
            $graphUrl = "https://graph.microsoft.com/v1.0/users/$username@$Domain"
            $response = Invoke-WebRequestSafe -Uri $graphUrl -TimeoutSec 3
            
            if ($response -and $response.StatusCode -eq 401) {
                $userEnum.ValidUsers += @{
                    Username   = "$username@$Domain"
                    Method     = "Graph API"
                    Confidence = "Medium"
                    Evidence   = "Graph API user endpoint accessible (401)"
                }
                Write-OSINTProperty "Graph User" "$username@$Domain" Yellow
            }
        }
        catch { }
        Start-Sleep -Milliseconds 200
    }
    
    return $userEnum
}

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
            
            foreach ($cert in $crtData | Select-Object -First 20) {
                # Limit results
                $certInfo = @{
                    CommonName      = $cert.common_name
                    Issuer          = $cert.issuer_name
                    NotBefore       = $cert.not_before
                    NotAfter        = $cert.not_after
                    SerialNumber    = $cert.serial_number
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
        LinkedIn  = @()
        Twitter   = @()
        GitHub    = @()
        Facebook  = @()
        Instagram = @()
    }
    
    $companyName = $OrganizationName ?? $Domain.Split('.')[0]
    
    # LinkedIn Company Search
    try {
        $linkedInUrl = "https://www.linkedin.com/company/$companyName"
        $response = Invoke-WebRequestSafe -Uri $linkedInUrl
        
        if ($response -and $response.StatusCode -eq 200) {
            $socialMedia.LinkedIn += @{
                Url      = $linkedInUrl
                Status   = "Found"
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
                Url         = $orgData.html_url
                Name        = $orgData.name
                Description = $orgData.description
                PublicRepos = $orgData.public_repos
                Followers   = $orgData.followers
                Status      = "Found"
                Platform    = "GitHub"
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
                    Url         = $repo.html_url
                    Name        = $repo.full_name
                    Description = $repo.description
                    Stars       = $repo.stargazers_count
                    Language    = $repo.language
                    Type        = "Repository"
                    Status      = "Found"
                    Platform    = "GitHub"
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
        EmailBreaches  = @()
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
                Pattern    = $pattern
                Example    = $email
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
        WebApps         = @()
        KeyVaults       = @()
        Databases       = @()
        CDNEndpoints    = @()
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
                    Name   = $variation
                    Url    = $storageUrl
                    Type   = "Blob Storage"
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
                    Name    = $variation
                    Url     = $webAppUrl
                    Type    = "Web App"
                    Status  = "Accessible"
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
                    Name   = $variation
                    Url    = $keyVaultUrl
                    Type   = "Key Vault"
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
                    Name   = $variation
                    Url    = $sqlUrl
                    Type   = "SQL Database"
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
                FileType    = $fileType
                SearchQuery = $searchQuery
                Status      = "Placeholder"
            }
        }
        catch {
            Write-OSINTLog "Document search failed for $fileType : $($_.Exception.Message)" "ERROR" Red
        }
    }
    
    Write-OSINTLog "Document metadata search completed (placeholder implementation)" "INFO" Yellow
    return $documents
}

# Enhanced Office 365 Discovery
function Get-Office365ServiceDiscovery {
    param([string]$Domain)
    
    Write-OSINTSection "Office 365 Service Discovery" "📧"
    
    $o365Services = @{
        ExchangeOnline           = $null
        TeamsPhoneSystem         = $null
        PowerPlatform            = $null
        SecurityCompliance       = $null
        AzureRightsManagement    = $null
        AdvancedThreatProtection = $null
    }
    
    # Test various O365 endpoints
    $endpoints = @(
        @{ Name = "Exchange Admin Center"; Url = "https://admin.exchange.microsoft.com" },
        @{ Name = "Security & Compliance Center"; Url = "https://protection.office.com" },
        @{ Name = "Microsoft 365 Admin Center"; Url = "https://admin.microsoft.com" },
        @{ Name = "Azure Rights Management"; Url = "https://$Domain.aadrm.com" }
    )
    
    foreach ($endpoint in $endpoints) {
        try {
            $response = Invoke-WebRequestSafe -Uri $endpoint.Url -TimeoutSec 3
            if ($response) {
                Write-OSINTProperty $endpoint.Name "✓ Accessible" Green
            }
        }
        catch { }
    }
    
    return $o365Services
}

# Enhanced Azure Resource Enumeration with ARM Templates & Management
function Get-ExtendedAzureResources {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "Extended Azure Resource Discovery" "🔧"
    
    $azureResources = @{
        StorageAccounts   = @()
        WebApps           = @()
        KeyVaults         = @()
        Databases         = @()
        CosmosDB          = @()
        ServiceBus        = @()
        EventHubs         = @()
        FunctionApps      = @()
        LogicApps         = @()
        APIManagement     = @()
        ContainerRegistry = @()
        AzureSQL          = @()
    }
    
    $baseName = $Domain.Split('.')[0]
    $variations = @(
        $baseName, "$baseName-prod", "$baseName-dev", "$baseName-test",
        "$baseName-staging", "$baseName-backup", "$baseName-data",
        "$baseName-api", "$baseName-web", "$baseName-app", "$baseName-func",
        "$baseName-logic", "$baseName-sb", "$baseName-eh", "$baseName-acr"
    )
    
    # Enhanced Storage Account Discovery
    Write-OSINTLog "Discovering Azure Storage Accounts..." "INFO" Cyan
    foreach ($variation in $variations) {
        $storageEndpoints = @(
            "https://$variation.blob.core.windows.net",
            "https://$variation.file.core.windows.net",
            "https://$variation.table.core.windows.net",
            "https://$variation.queue.core.windows.net"
        )
        
        foreach ($endpoint in $storageEndpoints) {
            try {
                $response = Invoke-WebRequestSafe -Uri $endpoint -TimeoutSec 3
                if ($response) {
                    $type = ($endpoint -split '\.')[1]  # blob, file, table, queue
                    $azureResources.StorageAccounts += @{
                        Name       = $variation
                        Endpoint   = $endpoint
                        Type       = $type.ToUpper()
                        Status     = "Active"
                        StatusCode = $response.StatusCode
                    }
                    Write-OSINTProperty "$type Storage" "$variation (Status: $($response.StatusCode))" Green
                }
            }
            catch { }
        }
    }
    
    # Function Apps Discovery
    Write-OSINTLog "Discovering Azure Function Apps..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            $funcUrl = "https://$variation.azurewebsites.net"
            $response = Invoke-WebRequestSafe -Uri $funcUrl -TimeoutSec 3
            if ($response) {
                $azureResources.FunctionApps += @{
                    Name    = $variation
                    Url     = $funcUrl
                    Status  = "Active"
                    Headers = $response.Headers
                }
                Write-OSINTProperty "Function App" $funcUrl Green
            }
        }
        catch { }
    }
    
    # Cosmos DB Discovery
    Write-OSINTLog "Discovering Cosmos DB instances..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            $cosmosUrl = "https://$variation.documents.azure.com"
            $response = Invoke-WebRequestSafe -Uri $cosmosUrl -TimeoutSec 3
            if ($response) {
                $azureResources.CosmosDB += @{
                    Name   = $variation
                    Url    = $cosmosUrl
                    Status = "Active"
                }
                Write-OSINTProperty "Cosmos DB" $cosmosUrl Green
            }
        }
        catch { }
    }
    
    # Container Registry Discovery
    Write-OSINTLog "Discovering Azure Container Registry..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            $acrUrl = "https://$variation.azurecr.io"
            $response = Invoke-WebRequestSafe -Uri $acrUrl -TimeoutSec 3
            if ($response) {
                $azureResources.ContainerRegistry += @{
                    Name   = $variation
                    Url    = $acrUrl
                    Status = "Active"
                }
                Write-OSINTProperty "Container Registry" $acrUrl Green
            }
        }
        catch { }
    }
    
    return $azureResources
}

# DNS and Network Intelligence
function Get-NetworkIntelligence {
    param([string]$Domain)
    
    Write-OSINTSection "Network Intelligence & DNS Analysis" "🌐"
    
    $networkInfo = @{
        DNSRecords      = @()
        Subdomains      = @()
        IPRanges        = @()
        CDNs            = @()
        SecurityHeaders = @{}
        Certificates    = @()
    }
    
    # Enhanced subdomain discovery
    $subdomainPrefixes = @(
        "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
        "portal", "login", "sso", "auth", "remote", "vpn", "owa",
        "autodiscover", "lyncdiscover", "sip", "teams", "sharepoint",
        "onedrive", "msoid", "enterpriseregistration", "enterpriseenrollment"
    )
    
    Write-OSINTLog "Performing enhanced subdomain enumeration..." "INFO" Cyan
    foreach ($subdomain in $subdomainPrefixes) {
        try {
            $fullDomain = "$subdomain.$Domain"
            $dnsResult = Resolve-DnsName -Name $fullDomain -Type A -ErrorAction SilentlyContinue
            
            if ($dnsResult) {
                $networkInfo.Subdomains += @{
                    Subdomain   = $fullDomain
                    IPAddresses = $dnsResult.IPAddress
                    Type        = "A Record"
                }
                Write-OSINTProperty "Subdomain Found" "$fullDomain -> $($dnsResult.IPAddress -join ', ')" Green
            }
        }
        catch { }
    }
    
    return $networkInfo
}

# Comprehensive Main Reconnaissance Function
function Start-AdvancedReconnaissance {
    param(
        [string]$Domain,
        [string]$TenantId = $null,
        [string]$OrganizationName = $null
    )
    
    # Enhanced banner
    Write-OSINTBanner "Advanced Azure & Entra ID OSINT Reconnaissance" "AADInternals-Style Intelligence Gathering"
    Write-Host "Target Domain: " -ForegroundColor Gray -NoNewline
    Write-Host $Domain -ForegroundColor White
    Write-Host "Scan Started: " -ForegroundColor Gray -NoNewline 
    Write-Host (Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC") -ForegroundColor Cyan
    
    $advancedResults = @{
        Domain                 = $Domain
        TenantId               = $TenantId
        OrganizationName       = $OrganizationName
        TenantInfo             = @{}
        DomainInfo             = @{}
        ServiceDiscovery       = @{}
        Office365Discovery     = @{}
        UserEnumeration        = @{}
        AzureResources         = @{}
        ExtendedAzureResources = @{}
        NetworkIntelligence    = @{}
        Certificates           = @()
        SocialMedia            = @{}
        BreachData             = @{}
        EmailPatterns          = @()
        Documents              = @()
        Timestamp              = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        ScanDuration           = $null
    }
    
    $scanStart = Get-Date
    
    try {
        # Phase 1: Entra ID Tenant Discovery
        $advancedResults.TenantInfo = Get-EntraIDTenantInfo -Domain $Domain
        $discoveredTenantId = $advancedResults.TenantInfo.TenantId
        if ($discoveredTenantId) { $TenantId = $discoveredTenantId }
        
        # Phase 2: Domain Enumeration  
        $advancedResults.DomainInfo = Get-DomainEnumeration -Domain $Domain -TenantId $TenantId
        
        # Phase 3: Service Discovery
        $advancedResults.ServiceDiscovery = Get-AzureServiceDiscovery -Domain $Domain -TenantId $TenantId
        
        # Phase 4: Office 365 Discovery
        $advancedResults.Office365Discovery = Get-Office365ServiceDiscovery -Domain $Domain
        
        # Phase 5: Advanced User Enumeration
        $advancedResults.UserEnumeration = Get-AdvancedUserEnumeration -Domain $Domain -TenantId $TenantId
        
        # Phase 6: Extended Azure Resources
        $advancedResults.ExtendedAzureResources = Get-ExtendedAzureResources -Domain $Domain -TenantId $TenantId
        
        # Phase 7: Network Intelligence
        $advancedResults.NetworkIntelligence = Get-NetworkIntelligence -Domain $Domain
        
        # Phase 8: Certificate Transparency
        Write-OSINTSection "Certificate Transparency Analysis" "🔐"
        $advancedResults.Certificates = Get-CertificateTransparency -Domain $Domain
        
        # Phase 9: Social Media & Digital Footprint
        Write-OSINTSection "Digital Footprint Analysis" "📱"
        $advancedResults.SocialMedia = Get-SocialMediaFootprint -Domain $Domain -OrganizationName $OrganizationName
        
        # Phase 10: Breach Intelligence
        Write-OSINTSection "Breach Intelligence" "🛡️"
        $advancedResults.BreachData = Get-BreachData -Domain $Domain
        
        # Phase 11: Email Pattern Analysis
        Write-OSINTSection "Email Pattern Analysis" "📧"
        $advancedResults.EmailPatterns = Get-EmailPatterns -Domain $Domain
        
        # Calculate scan duration
        $scanEnd = Get-Date
        $advancedResults.ScanDuration = ($scanEnd - $scanStart).ToString("hh\:mm\:ss")
        
        # Enhanced Results Summary
        Write-OSINTSection "Reconnaissance Summary" "📊"
        
        Write-OSINTProperty "Scan Duration" $advancedResults.ScanDuration Cyan
        Write-OSINTProperty "Tenant ID" ($advancedResults.TenantInfo.TenantId ?? "Not Found") $(if ($advancedResults.TenantInfo.TenantId) { "Green" } else { "Red" })
        Write-OSINTProperty "Namespace Type" ($advancedResults.TenantInfo.NameSpaceType ?? "Unknown") $(if ($advancedResults.TenantInfo.NameSpaceType -eq "Managed") { "Green" } else { "Yellow" })
        Write-OSINTProperty "Related Domains" $advancedResults.DomainInfo.RelatedDomains.Count Green
        Write-OSINTProperty "Valid Users Found" $advancedResults.UserEnumeration.ValidUsers.Count Green  
        Write-OSINTProperty "Subdomains Found" $advancedResults.NetworkIntelligence.Subdomains.Count Green
        Write-OSINTProperty "Azure Resources" $advancedResults.ExtendedAzureResources.StorageAccounts.Count Green
        Write-OSINTProperty "Certificates Found" $advancedResults.Certificates.Count Green
        Write-OSINTProperty "GitHub Repositories" $advancedResults.SocialMedia.GitHub.Count Green
        
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║" -ForegroundColor Green -NoNewline
        Write-Host " Advanced OSINT Reconnaissance Completed Successfully!".PadRight(76) -ForegroundColor White -NoNewline  
        Write-Host "║" -ForegroundColor Green
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        
    }
    catch {
        Write-Host "Error during reconnaissance: $($_.Exception.Message)" -ForegroundColor Red
        $advancedResults.Error = $_.Exception.Message
    }
    
    return $advancedResults
}

# Enhanced Export with Multiple Formats
function Export-AdvancedResults {
    param(
        [hashtable]$Results,
        [string]$OutputPath = "advanced-osint-results"
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $domain = $Results.Domain -replace '[^a-zA-Z0-9]', '-'
    
    # Export JSON (detailed technical data)
    $jsonFile = "$OutputPath-$domain-$timestamp.json"
    $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
    Write-OSINTProperty "JSON Report" $jsonFile Green
    
    # Export HTML Report (visual summary)
    $htmlFile = "$OutputPath-$domain-$timestamp.html"
    Export-HTMLReport -Results $Results -OutputPath $htmlFile
    Write-OSINTProperty "HTML Report" $htmlFile Green
    
    # Export CSV (tabular data)
    $csvFile = "$OutputPath-$domain-$timestamp.csv"
    Export-CSVReport -Results $Results -OutputPath $csvFile
    Write-OSINTProperty "CSV Report" $csvFile Green
}

function Export-HTMLReport {
    param([hashtable]$Results, [string]$OutputPath)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Azure OSINT Report - $($Results.Domain)</title>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #0078d4, #106ebe); color: white; padding: 20px; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { color: #0078d4; margin-top: 0; border-bottom: 2px solid #e3f2fd; padding-bottom: 10px; }
        .property { display: flex; padding: 8px 0; border-bottom: 1px solid #eee; }
        .property-name { font-weight: bold; width: 200px; color: #333; }
        .property-value { flex: 1; color: #666; }
        .success { color: #4caf50; font-weight: bold; }
        .warning { color: #ff9800; font-weight: bold; }
        .error { color: #f44336; font-weight: bold; }
        .info { color: #2196f3; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f5f5f5; font-weight: bold; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-success { background: #4caf50; color: white; }
        .badge-warning { background: #ff9800; color: white; }
        .badge-info { background: #2196f3; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Advanced Azure OSINT Report</h1>
        <h2>$($Results.Domain)</h2>
        <p>Generated: $($Results.Timestamp) | Duration: $($Results.ScanDuration)</p>
    </div>
    
    <div class="container">
        <div class="section">
            <h2>📋 Executive Summary</h2>
            <div class="property">
                <div class="property-name">Target Domain:</div>
                <div class="property-value">$($Results.Domain)</div>
            </div>
            <div class="property">
                <div class="property-name">Tenant ID:</div>
                <div class="property-value $(if($Results.TenantInfo.TenantId){'success'}else{'error'})">$($Results.TenantInfo.TenantId ?? 'Not Found')</div>
            </div>
            <div class="property">
                <div class="property-name">Namespace Type:</div>
                <div class="property-value $(if($Results.TenantInfo.NameSpaceType -eq 'Managed'){'success'}else{'warning'})">$($Results.TenantInfo.NameSpaceType ?? 'Unknown')</div>
            </div>
            <div class="property">
                <div class="property-name">Cloud Instance:</div>
                <div class="property-value">$($Results.TenantInfo.CloudInstance ?? 'Not Detected')</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🏢 Tenant Information</h2>
            <div class="property">
                <div class="property-name">Federation Protocol:</div>
                <div class="property-value">$($Results.TenantInfo.Federation ?? 'N/A')</div>
            </div>
            <div class="property">
                <div class="property-name">Authentication URL:</div>
                <div class="property-value">$($Results.TenantInfo.AuthenticationUrl ?? 'N/A')</div>
            </div>
            <div class="property">
                <div class="property-name">Issuer:</div>
                <div class="property-value">$($Results.TenantInfo.Endpoints.Issuer ?? 'N/A')</div>
            </div>
        </div>
        
        <div class="section">
            <h2>👥 User Enumeration Results</h2>
            <table>
                <tr><th>Username</th><th>Method</th><th>Confidence</th><th>Evidence</th></tr>
"@
    
    foreach ($user in $Results.UserEnumeration.ValidUsers) {
        $html += "<tr><td>$($user.Username)</td><td>$($user.Method)</td><td><span class='badge badge-$(if($user.Confidence -eq "High"){"success"}elseif($user.Confidence -eq "Medium"){"warning"}else{"info"})'>$($user.Confidence)</span></td><td>$($user.Evidence)</td></tr>"
    }
    
    $html += @"
            </table>
        </div>
        
        <div class="section">
            <h2>🌐 Domain & Subdomain Discovery</h2>
            <h3>Related Microsoft Domains</h3>
            <ul>
"@
    
    foreach ($domain in $Results.DomainInfo.RelatedDomains) {
        $html += "<li class='success'>$domain</li>"
    }
    
    $html += @"
            </ul>
            <h3>Discovered Subdomains</h3>
            <table>
                <tr><th>Subdomain</th><th>IP Addresses</th><th>Type</th></tr>
"@
    
    foreach ($subdomain in $Results.NetworkIntelligence.Subdomains) {
        $html += "<tr><td>$($subdomain.Subdomain)</td><td>$($subdomain.IPAddresses -join ', ')</td><td>$($subdomain.Type)</td></tr>"
    }
    
    $html += @"
            </table>
        </div>
        
        <div class="section">
            <h2>☁️ Azure Services Discovery</h2>
            <div class="grid">
"@
    
    $serviceStatus = @(
        @{Name = "Entra ID"; Status = $Results.ServiceDiscovery.EntraID },
        @{Name = "Exchange Online"; Status = $Results.ServiceDiscovery.Exchange },
        @{Name = "SharePoint Online"; Status = $Results.ServiceDiscovery.SharePoint },
        @{Name = "OneDrive for Business"; Status = $Results.ServiceDiscovery.OneDrive },
        @{Name = "Microsoft Teams"; Status = $Results.ServiceDiscovery.Teams }
    )
    
    foreach ($service in $serviceStatus) {
        $status = if ($service.Status) { "✅ Active" } else { "❌ Not Detected" }
        $cssClass = if ($service.Status) { "success" } else { "error" }
        $html += "<div class='property'><div class='property-name'>$($service.Name):</div><div class='property-value $cssClass'>$status</div></div>"
    }
    
    $html += @"
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 Azure Resource Discovery</h2>
            <h3>Storage Accounts</h3>
            <table>
                <tr><th>Name</th><th>Type</th><th>Endpoint</th><th>Status</th></tr>
"@
    
    foreach ($storage in $Results.ExtendedAzureResources.StorageAccounts) {
        $html += "<tr><td>$($storage.Name)</td><td>$($storage.Type)</td><td>$($storage.Endpoint)</td><td class='success'>$($storage.Status)</td></tr>"
    }
    
    $html += @"
            </table>
            
            <h3>Other Azure Resources</h3>
            <ul>
"@
    
    foreach ($func in $Results.ExtendedAzureResources.FunctionApps) {
        $html += "<li><strong>Function App:</strong> <a href='$($func.Url)' target='_blank'>$($func.Url)</a></li>"
    }
    
    foreach ($cosmos in $Results.ExtendedAzureResources.CosmosDB) {
        $html += "<li><strong>Cosmos DB:</strong> $($cosmos.Url)</li>"
    }
    
    foreach ($acr in $Results.ExtendedAzureResources.ContainerRegistry) {
        $html += "<li><strong>Container Registry:</strong> $($acr.Url)</li>"
    }
    
    $html += @"
            </ul>
        </div>
        
        <div class="section">
            <h2>📱 Digital Footprint</h2>
            <h3>GitHub Repositories</h3>
            <table>
                <tr><th>Repository</th><th>Description</th><th>Language</th><th>Stars</th></tr>
"@
    
    foreach ($repo in $Results.SocialMedia.GitHub) {
        if ($repo.Type -eq "Repository") {
            $html += "<tr><td><a href='$($repo.Url)' target='_blank'>$($repo.Name)</a></td><td>$($repo.Description)</td><td>$($repo.Language)</td><td>$($repo.Stars)</td></tr>"
        }
    }
    
    $html += @"
            </table>
        </div>
        
        <div class="section">
            <h2>🔐 Certificate Analysis</h2>
            <table>
                <tr><th>Common Name</th><th>Issuer</th><th>Valid From</th><th>Valid To</th></tr>
"@
    
    foreach ($cert in $Results.Certificates) {
        $html += "<tr><td>$($cert.CommonName)</td><td>$($cert.Issuer)</td><td>$($cert.NotBefore)</td><td>$($cert.NotAfter)</td></tr>"
    }
    
    $html += @"
            </table>
        </div>
        
        <div class="section">
            <h2>📊 Statistics Summary</h2>
            <div class="grid">
                <div class="property"><div class="property-name">Total Scan Time:</div><div class="property-value info">$($Results.ScanDuration)</div></div>
                <div class="property"><div class="property-name">Valid Users Found:</div><div class="property-value success">$($Results.UserEnumeration.ValidUsers.Count)</div></div>
                <div class="property"><div class="property-name">Related Domains:</div><div class="property-value success">$($Results.DomainInfo.RelatedDomains.Count)</div></div>
                <div class="property"><div class="property-name">Subdomains Found:</div><div class="property-value success">$($Results.NetworkIntelligence.Subdomains.Count)</div></div>
                <div class="property"><div class="property-name">Azure Resources:</div><div class="property-value success">$($Results.ExtendedAzureResources.StorageAccounts.Count + $Results.ExtendedAzureResources.FunctionApps.Count + $Results.ExtendedAzureResources.CosmosDB.Count)</div></div>
                <div class="property"><div class="property-name">Certificates:</div><div class="property-value success">$($Results.Certificates.Count)</div></div>
            </div>
        </div>
    </div>
    
    <div style="text-align: center; padding: 20px; color: #666; font-size: 12px;">
        Generated by Advanced Azure OSINT Tool | $(Get-Date)
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Export-CSVReport {
    param([hashtable]$Results, [string]$OutputPath)
    
    $csvData = @()
    
    # Add user enumeration data
    foreach ($user in $Results.UserEnumeration.ValidUsers) {
        $csvData += [PSCustomObject]@{
            Type       = "User"
            Name       = $user.Username
            Method     = $user.Method
            Confidence = $user.Confidence
            Evidence   = $user.Evidence
            URL        = $user.Url ?? ""
        }
    }
    
    # Add subdomain data
    foreach ($subdomain in $Results.NetworkIntelligence.Subdomains) {
        $csvData += [PSCustomObject]@{
            Type       = "Subdomain"
            Name       = $subdomain.Subdomain
            Method     = "DNS Resolution"
            Confidence = "High"
            Evidence   = "Resolved to: $($subdomain.IPAddresses -join ', ')"
            URL        = ""
        }
    }
    
    # Add Azure resource data
    foreach ($storage in $Results.ExtendedAzureResources.StorageAccounts) {
        $csvData += [PSCustomObject]@{
            Type       = "Azure Storage"
            Name       = $storage.Name
            Method     = "HTTP Probe"
            Confidence = "High"
            Evidence   = "Status Code: $($storage.StatusCode)"
            URL        = $storage.Endpoint
        }
    }
    
    $csvData | Export-Csv -Path $OutputPath -NoTypeInformation
}

# =============================================================================
# MAIN EXECUTION LOGIC
# =============================================================================

# Help display
if ($Help) {
    Write-Host @"
Azure OSINT Advanced Tool
========================

This tool performs advanced OSINT reconnaissance on Azure AD/Entra ID tenants.

Usage:
    .\Azure-OSINT-Advanced.ps1 -Domain "contoso.com"
    .\Azure-OSINT-Advanced.ps1 -Domain "contoso.com" -OrganizationName "Contoso Corp"
    .\Azure-OSINT-Advanced.ps1 -Domain "contoso.com" -TenantId "12345678-1234-1234-1234-123456789012"

Parameters:
    -Domain            Target domain (e.g., contoso.com)
    -TenantId          Optional: Azure tenant ID
    -OrganizationName  Optional: Organization name for social media searches
    -OutputFile        Output file path (default: advanced-osint-results.json)
    -Help              Show this help message

Features:
    • Certificate Transparency logs
    • Social media footprint discovery
    • Breach data correlation (placeholder)
    • Email pattern analysis
    • Azure resource enumeration
    • Office document metadata search

"@ -ForegroundColor Cyan
    exit 0
}

# Interactive mode if no domain provided
if (-not $Domain) {
    Write-Host "Azure OSINT Advanced Tool" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    $Domain = Read-Host "Enter target domain (e.g., contoso.com)"
    
    if ([string]::IsNullOrWhiteSpace($Domain)) {
        Write-Host "Domain is required. Use -Help for usage information." -ForegroundColor Red
        exit 1
    }
    
    $OrganizationName = Read-Host "Enter organization name (optional, press Enter to skip)"
    if ([string]::IsNullOrWhiteSpace($OrganizationName)) {
        $OrganizationName = $null
    }
}

# Main execution
if ($Domain) {
    try {
        Write-Host "`nStarting Advanced Azure OSINT Reconnaissance..." -ForegroundColor Green
        Write-Host "Target: $Domain" -ForegroundColor White
        
        # Run advanced reconnaissance
        $results = Start-AdvancedReconnaissance -Domain $Domain -TenantId $TenantId -OrganizationName $OrganizationName
        
        # Export results
        Export-AdvancedResults -Results $results -OutputPath $OutputFile
        
        Write-Host "`nAdvanced OSINT scan completed successfully!" -ForegroundColor Green
        Write-Host "Results saved to: $OutputFile" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error during advanced reconnaissance: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
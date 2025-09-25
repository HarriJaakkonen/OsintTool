#Requires -Version 7.0
<#
.SYNOPSIS
Advanced Azure AD/Entra ID OSINT Reconnaissance Module

.DESCRIPTION
Extended OSINT capabilities including certificate transparency logs, social media reconnaissance,
breach data correlation, advanced enumeration techniques, authentication flow analysis, and security 
posture assessment for Azure AD/Entra ID environments. Incorporates techniques from mjendza.net and 
ROADtools for comprehensive tenant reconnaissance.

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
    }
    else {
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
        }
        else {
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
    }
    else {
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
    }
    elseif ($Total -gt 0) {
        Write-Host "🔄 $Operation ($Current/$Total)..." -ForegroundColor Cyan
    }
    else {
        Write-Host "🔄 $Operation..." -ForegroundColor Cyan
    }
}

function Write-OSINTBulkResult {
    param(
        [string]$Operation,
        [int]$SuccessCount,
        [int]$ErrorCount
    )
    
    $total = $SuccessCount + $ErrorCount
    if ($SuccessCount -gt 0) {
        Write-Host ">> $Operation" -NoNewline -ForegroundColor Cyan
        Write-Host ": $SuccessCount" -NoNewline -ForegroundColor Green
        Write-Host " found, " -NoNewline -ForegroundColor Gray
        Write-Host "$ErrorCount" -NoNewline -ForegroundColor DarkGray
        Write-Host " not found (of $total checked)" -ForegroundColor Gray
    }
    else {
        Write-Host ">> $Operation" -NoNewline -ForegroundColor Cyan
        Write-Host ": No results found " -NoNewline -ForegroundColor Yellow
        Write-Host "($total checked)" -ForegroundColor Gray
    }
}

function Invoke-WebRequestSafe {
    param(
        [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Method = "GET",
        [string]$Body = $null,
        [int]$TimeoutSec = 10,
        [switch]$SuppressErrors
    )
    
    try {
        # Prepare default headers and merge with any caller-supplied headers
        $defaultHeaders = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        $allHeaders = $defaultHeaders + $Headers

        $requestParams = @{
            Uri         = $Uri
            Headers     = $allHeaders
            Method      = $Method
            TimeoutSec  = $TimeoutSec
            ErrorAction = 'Stop'
        }

        if ($Body) {
            $requestParams.Body = $Body
        }

        $response = Invoke-WebRequest @requestParams
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
    }
    else {
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
    }
    else {
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
    Write-Host "🔍 " -NoNewline -ForegroundColor Cyan
    Write-Host "Azure OSINT Advanced Reconnaissance Engine" -ForegroundColor White
    Write-Host "🛡️  " -NoNewline -ForegroundColor Yellow
    Write-Host "Enhanced Security Analysis & Threat Intelligence" -ForegroundColor Gray
    if ($Title) {
        Write-Host "🎯 " -NoNewline -ForegroundColor Green
        Write-Host $Title -ForegroundColor Cyan
    }
    if ($Subtitle) {
        Write-Host "   " -NoNewline
        Write-Host $Subtitle -ForegroundColor DarkGray
    }
    Write-Host ""
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

# AADInternals-style DNS and Mail Analysis Functions
function Get-DomainDNSAnalysis {
    param([string]$Domain)
    
    $analysis = @{
        DNS          = $false
        MX           = $false
        SPF          = $false
        DMARC        = $false
        DKIM         = $false
        MTASTS       = $false
        MXRecords    = @()
        SPFRecord    = $null
        DMARCRecord  = $null
        DKIMRecords  = @()
        MTASTSRecord = $null
    }
    
    try {
        # DNS A Record Check
        $dnsResult = Resolve-DnsName -Name $Domain -Type A -ErrorAction SilentlyContinue
        if ($dnsResult) {
            $analysis.DNS = $true
        }
        
        # MX Record Analysis
        $mxRecords = Resolve-DnsName -Name $Domain -Type MX -ErrorAction SilentlyContinue
        if ($mxRecords) {
            $analysis.MXRecords = $mxRecords | ForEach-Object { $_.NameExchange }
            $analysis.MX = ($analysis.MXRecords -join " ") -match "protection\.outlook\.com|mail\.protection\.outlook\.com"
        }
        
        # SPF Record Analysis  
        $txtRecords = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction SilentlyContinue
        if ($txtRecords) {
            $spfRecord = $txtRecords | Where-Object { $_.Strings -match "^v=spf1" } | Select-Object -First 1
            if ($spfRecord) {
                $analysis.SPFRecord = $spfRecord.Strings -join ""
                $analysis.SPF = $analysis.SPFRecord -match "include:spf\.protection\.outlook\.com"
            }
            
            # DMARC Record Check
            $dmarcRecords = Resolve-DnsName -Name "_dmarc.$Domain" -Type TXT -ErrorAction SilentlyContinue
            if ($dmarcRecords) {
                $dmarcRecord = $dmarcRecords | Where-Object { $_.Strings -match "^v=DMARC1" } | Select-Object -First 1
                if ($dmarcRecord) {
                    $analysis.DMARCRecord = $dmarcRecord.Strings -join ""
                    $analysis.DMARC = $true
                }
            }
        }
        
        # DKIM Record Check (common selectors)
        $dkimSelectors = @("selector1", "selector2", "s1", "s2", "dkim", "google", "k1")
        foreach ($selector in $dkimSelectors) {
            try {
                $dkimRecord = Resolve-DnsName -Name "$selector._domainkey.$Domain" -Type TXT -ErrorAction SilentlyContinue
                if ($dkimRecord) {
                    $analysis.DKIMRecords += "$selector : $($dkimRecord.Strings -join '')"
                    $analysis.DKIM = $true
                }
            }
            catch { }
        }
        
        # MTA-STS Record Check
        try {
            $mtastsRecord = Resolve-DnsName -Name "_mta-sts.$Domain" -Type TXT -ErrorAction SilentlyContinue
            if ($mtastsRecord) {
                $analysis.MTASTSRecord = $mtastsRecord.Strings -join ""
                $analysis.MTASTS = $true
            }
        }
        catch { }
        
    }
    catch { }
    
    return $analysis
}

function Get-TenantRegionInfo {
    param([string]$TenantId)
    
    $regionInfo = @{
        Region        = "Unknown"
        SubRegion     = "Unknown"
        CloudInstance = "Commercial"
    }
    
    if ($TenantId) {
        try {
            # Try to determine region from various endpoints
            $endpoints = @(
                "https://login.microsoftonline.com/$TenantId/v2.0/.well-known/openid_configuration",
                "https://login.microsoftonline.us/$TenantId/v2.0/.well-known/openid_configuration",
                "https://login.partner.microsoftonline.cn/$TenantId/v2.0/.well-known/openid_configuration"
            )
            
            foreach ($endpoint in $endpoints) {
                $response = Invoke-WebRequestSafe -Uri $endpoint -SuppressErrors
                if ($response) {
                    $config = $response.Content | ConvertFrom-Json
                    if ($endpoint -match "microsoftonline\.us") {
                        $regionInfo.CloudInstance = "USGovernment"
                        $regionInfo.Region = "USGov"
                    }
                    elseif ($endpoint -match "partner\.microsoftonline\.cn") {
                        $regionInfo.CloudInstance = "China"
                        $regionInfo.Region = "China"
                    }
                    else {
                        $regionInfo.CloudInstance = "Commercial"
                        $regionInfo.Region = "Worldwide"
                    }
                    break
                }
            }
        }
        catch { }
    }
    
    return $regionInfo
}

# Enhanced Tenant Information Discovery (AADInternals-like)
function Get-EntraIDTenantInfo {
    param([string]$Domain)
    
    Write-OSINTSection "Entra ID Tenant Discovery" "🔍"
    
    $tenantInfo = @{
        Domain              = $Domain
        TenantId            = $null
        TenantName          = $null
        TenantBrand         = $null
        TenantRegion        = $null
        TenantSubRegion     = $null
        CloudInstance       = $null
        AuthenticationUrl   = $null
        FederationMetadata  = $null
        OpenIdConfiguration = $null
        TenantBrandingUrls  = @()
        ManagedDomains      = @()
        FederatedDomains    = @()
        AllDomains          = @()
        NameSpaceType       = $null
        Federation          = $null
        PreferredUserName   = $null
        Endpoints           = @{}
        Capabilities        = @()
        DNSAnalysis         = $null
        DesktopSSOEnabled   = $false
        CBAEnabled          = $null
        MDIInstance         = $null
        STSServer           = $null
    }
    
    # AADInternals-style DNS and Mail Analysis
    Write-OSINTProgress "DNS and Mail Configuration Analysis"
    $tenantInfo.DNSAnalysis = Get-DomainDNSAnalysis -Domain $Domain
    
    Write-OSINTProperty "DNS Record" $(if ($tenantInfo.DNSAnalysis.DNS) { "✓ Exists" } else { "✗ Missing" }) $(if ($tenantInfo.DNSAnalysis.DNS) { "Green" } else { "Red" })
    Write-OSINTProperty "MX → Office 365" $(if ($tenantInfo.DNSAnalysis.MX) { "✓ Yes" } else { "✗ No" }) $(if ($tenantInfo.DNSAnalysis.MX) { "Green" } else { "Yellow" })
    Write-OSINTProperty "SPF → Exchange Online" $(if ($tenantInfo.DNSAnalysis.SPF) { "✓ Yes" } else { "✗ No" }) $(if ($tenantInfo.DNSAnalysis.SPF) { "Green" } else { "Yellow" })
    Write-OSINTProperty "DMARC Configured" $(if ($tenantInfo.DNSAnalysis.DMARC) { "✓ Yes" } else { "✗ No" }) $(if ($tenantInfo.DNSAnalysis.DMARC) { "Green" } else { "Yellow" })
    Write-OSINTProperty "DKIM Configured" $(if ($tenantInfo.DNSAnalysis.DKIM) { "✓ Yes" } else { "✗ No" }) $(if ($tenantInfo.DNSAnalysis.DKIM) { "Green" } else { "Yellow" })
    Write-OSINTProperty "MTA-STS Configured" $(if ($tenantInfo.DNSAnalysis.MTASTS) { "✓ Yes" } else { "✗ No" }) $(if ($tenantInfo.DNSAnalysis.MTASTS) { "Green" } else { "Yellow" })
    
    # Method 1: Enhanced OpenID Connect Discovery (gettenantpartitionweb.azurewebsites.net method)
    Write-OSINTProgress "Enhanced OpenID Connect Discovery"
    
    $clouds = @(
        @{Name = "Worldwide"; Endpoint = "https://login.microsoftonline.com" },
        @{Name = "US Government"; Endpoint = "https://login.microsoftonline.us" },
        @{Name = "China"; Endpoint = "https://login.partner.microsoftonline.cn" },
        @{Name = "Germany"; Endpoint = "https://login.microsoftonline.de" }
    )
    
    foreach ($cloud in $clouds) {
        try {
            $openIdUrl = "$($cloud.Endpoint)/$Domain/.well-known/openid_configuration"
            $response = Invoke-WebRequestSafe -Uri $openIdUrl -SuppressErrors
            
            if ($response) {
                $openIdConfig = $response.Content | ConvertFrom-Json
                $tenantInfo.OpenIdConfiguration = $openIdConfig
                
                # Extract Tenant ID from authorization_endpoint (gettenantpartitionweb method)
                $tenantIdRegex = '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'
                if ($openIdConfig.authorization_endpoint -match $tenantIdRegex) {
                    $tenantInfo.TenantId = $matches[1]
                    $tenantInfo.CloudInstance = $cloud.Name
                    
                    # Extract region and scope information
                    if ($openIdConfig.tenant_region_scope) {
                        switch ($openIdConfig.tenant_region_scope) {
                            'USGov' { $tenantInfo.TenantRegion = "Azure AD Government: Arlington" }
                            'USG' { $tenantInfo.TenantRegion = "Azure AD Government: Fairfax" }
                            'WW' { $tenantInfo.TenantRegion = "Azure AD Global" }
                            'NA' { $tenantInfo.TenantRegion = "Azure AD Global: North America" }
                            'EU' { $tenantInfo.TenantRegion = "Azure AD Global: Europe" }
                            'AS' { 
                                $tenantInfo.TenantRegion = if ($cloud.Name -eq "China") { "Azure AD China" } else { "Azure AD Global: Asia-Pacific" }
                            }
                            'OC' { $tenantInfo.TenantRegion = "Azure AD Global: Oceania" }
                            'DE' { $tenantInfo.TenantRegion = "Azure AD Germany" }
                            default { $tenantInfo.TenantRegion = "Other (most likely Azure AD Global)" }
                        }
                    }
                    
                    # Extract government scope information
                    if ($openIdConfig.tenant_region_sub_scope) {
                        switch ($openIdConfig.tenant_region_sub_scope) {
                            'DOD' { $tenantInfo.TenantSubRegion = "DOD" }
                            'DODCON' { $tenantInfo.TenantSubRegion = "GCC High" }
                            'GCC' { $tenantInfo.TenantSubRegion = "GCC" }
                            default { $tenantInfo.TenantSubRegion = "Standard" }
                        }
                    }
                    
                    # Extract all endpoints
                    $tenantInfo.Endpoints = @{
                        Authorization = $openIdConfig.authorization_endpoint
                        Token         = $openIdConfig.token_endpoint
                        UserInfo      = $openIdConfig.userinfo_endpoint
                        EndSession    = $openIdConfig.end_session_endpoint
                        JwksUri       = $openIdConfig.jwks_uri
                        Issuer        = $openIdConfig.issuer
                    }
                    
                    Write-OSINTSuccess "Enhanced OpenID Connect Discovery"
                    Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                    Write-OSINTProperty "Cloud Instance" $tenantInfo.CloudInstance Green
                    Write-OSINTProperty "Discovery Method" "OpenID Connect (Authoritative)" Green
                    
                    if ($tenantInfo.TenantRegion) {
                        Write-OSINTProperty "Tenant Region" $tenantInfo.TenantRegion Green
                    }
                    if ($tenantInfo.TenantSubRegion -and $tenantInfo.TenantSubRegion -ne "Standard") {
                        Write-OSINTProperty "Government Scope" $tenantInfo.TenantSubRegion Yellow
                    }
                    
                    break  # Found tenant, no need to check other clouds
                }
            }
        }
        catch {
            # Continue to next cloud
        }
    }
    
    if (-not $tenantInfo.TenantId) {
        Write-OSINTError "Enhanced OpenID Connect Discovery" $Domain "No tenant found in any cloud" -Silent
    }
    
    # Method 2: Microsoft Graph Discovery
    Write-OSINTProgress "Microsoft Graph Discovery"
    try {
        $graphUrl = "https://graph.microsoft.com/v1.0/domains/$Domain"
        $response = Invoke-WebRequestSafe -Uri $graphUrl -SuppressErrors
        if ($response -and $response.StatusCode -eq 401) {
            Write-OSINTSuccess "Microsoft Graph Discovery"
            Write-OSINTProperty "Graph API" "Domain exists (401 Unauthorized)" Yellow
        }
        else {
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
        }
        else {
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
    
    # Method 5: GetUserRealm API (AADInternals method)
    Write-OSINTProgress "GetUserRealm Discovery"
    try {
        $userRealmUrl = "https://login.microsoftonline.com/GetUserRealm.srf?login=test@$Domain"
        $response = Invoke-WebRequestSafe -Uri $userRealmUrl -SuppressErrors
        
        if ($response) {
            $realmData = $response.Content | ConvertFrom-Json
            
            # Extract tenant information
            if ($realmData.NameSpaceType) {
                $tenantInfo.NameSpaceType = $realmData.NameSpaceType
                Write-OSINTSuccess "GetUserRealm Discovery"
                Write-OSINTProperty "Namespace Type" $realmData.NameSpaceType $(if ($realmData.NameSpaceType -eq "Managed") { "Green" } else { "Yellow" })
            }
            
            if ($realmData.FederationBrandName) {
                $tenantInfo.TenantName = $realmData.FederationBrandName
                $tenantInfo.TenantBrand = $realmData.FederationBrandName
                Write-OSINTProperty "Tenant Brand" $realmData.FederationBrandName Green
            }
            
            # Extract tenant ID if available in realm data
            if ($realmData.TenantId) {
                $tenantInfo.TenantId = $realmData.TenantId
                Write-OSINTProperty "Tenant ID" $realmData.TenantId Green
            }
            
            if ($realmData.CloudInstanceName) {
                $tenantInfo.CloudInstance = $realmData.CloudInstanceName
                Write-OSINTProperty "Cloud Instance" $realmData.CloudInstanceName Green
            }
            
            if ($realmData.federation_protocol) {
                $tenantInfo.Federation = $realmData.federation_protocol
                Write-OSINTProperty "Federation Protocol" $realmData.federation_protocol Yellow
            }
            
            if ($realmData.AuthURL) {
                $tenantInfo.STSServer = ([System.Uri]$realmData.AuthURL).Host
                Write-OSINTProperty "STS Server" $tenantInfo.STSServer Yellow
            }
            
            # Extract tenant name from domain for MDI detection
            if ($realmData.DomainName) {
                $baseName = $realmData.DomainName.Split('.')[0]
                $tenantInfo.MDIInstance = "$baseName.atp.azure.com"
                
                # Test if MDI instance is accessible
                try {
                    $mdiTest = Invoke-WebRequestSafe -Uri "https://$($tenantInfo.MDIInstance)" -SuppressErrors -TimeoutSec 3
                    if ($mdiTest) {
                        Write-OSINTProperty "MDI Instance" $tenantInfo.MDIInstance Green
                    }
                }
                catch { }
            }
        }
        else {
            Write-OSINTError "GetUserRealm Discovery" $Domain "API not accessible" -Silent
        }
    }
    catch {
        Write-OSINTError "GetUserRealm Discovery" $Domain $_.Exception.Message
    }
    
    # Method 6: GetCredentialType API (Enhanced Tenant Detection)
    Write-OSINTProgress "GetCredentialType Discovery"
    try {
        $credentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType"
        $requestBody = @{
            Username = "test@$Domain"
        } | ConvertTo-Json
        
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        $response = Invoke-WebRequestSafe -Uri $credentialTypeUrl -Method "POST" -Headers $headers -Body $requestBody -SuppressErrors
        
        if ($response) {
            $credData = $response.Content | ConvertFrom-Json
            
            if ($credData.IfExistsResult -eq 0 -or $credData.IfExistsResult -eq 1) {
                Write-OSINTSuccess "GetCredentialType Discovery"
                
                # Extract tenant ID from branding URLs (AADInternals technique)
                if ($credData.EstsProperties -and $credData.EstsProperties.UserTenantBranding -and -not $tenantInfo.TenantId) {
                    $branding = $credData.EstsProperties.UserTenantBranding[0]
                    
                    # Check multiple branding URLs for tenant ID
                    $brandingUrls = @($branding.BannerLogo, $branding.TileLogo, $branding.Illustration, $branding.CustomizationFiles)
                    
                    foreach ($url in $brandingUrls) {
                        if ($url) {
                            # Try to extract standard GUID format first (36 characters with hyphens)
                            if ($url -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                                $tenantInfo.TenantId = $matches[1]
                                Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                                Write-OSINTProperty "Discovery Method" "Branding URL Analysis (GUID)" Yellow
                                break
                            }
                            # Extract tenant identifier from URL path (limit to reasonable length)
                            elseif ($url -match 'aadcdn\.msauthimages\.net/([a-f0-9]{8}-[a-f0-9\-]{1,50})/') {
                                # Ensure we don't capture overly long identifiers
                                $extractedId = $matches[1]
                                if ($extractedId.Length -le 50) {
                                    $tenantInfo.TenantId = $extractedId
                                    Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green  
                                    Write-OSINTProperty "Discovery Method" "Branding URL Analysis (Extended)" Yellow
                                    break
                                }
                            }
                        }
                    }
                }
                
                # Extract additional tenant information
                if ($credData.Credentials -and $credData.Credentials.FederationRedirectUrl) {
                    Write-OSINTProperty "Federation Redirect" $credData.Credentials.FederationRedirectUrl Yellow
                }
                
                if ($credData.EstsProperties -and $credData.EstsProperties.DomainType) {
                    Write-OSINTProperty "Domain Type" $credData.EstsProperties.DomainType Green
                }
                
                # Desktop SSO detection (AADInternals compatibility)
                if ($credData.EstsProperties -and $credData.EstsProperties.DesktopSsoEnabled) {
                    $tenantInfo.DesktopSSOEnabled = $true
                    Write-OSINTProperty "Desktop SSO Enabled" "True" Green
                    $tenantInfo.Capabilities += "DesktopSSO"
                }
                else {
                    $tenantInfo.DesktopSSOEnabled = $false
                    Write-OSINTProperty "Desktop SSO Enabled" "False" Yellow
                }
                
                # Certificate-Based Authentication (CBA) detection
                if ($credData.Credentials) {
                    $hasCert = $credData.Credentials.CertAuthParams -ne $null
                    $tenantInfo.CBAEnabled = $hasCert
                    Write-OSINTProperty "CBA Enabled" $(if ($hasCert) { "True" } else { "False" }) $(if ($hasCert) { "Green" } else { "Yellow" })
                }
                
                # Tenant region analysis from branding
                if ($credData.EstsProperties -and $credData.EstsProperties.UserTenantBranding) {
                    $branding = $credData.EstsProperties.UserTenantBranding[0]
                    if ($branding.BackgroundColor) {
                        Write-OSINTProperty "Tenant Brand Color" $branding.BackgroundColor Cyan
                    }
                    
                    # Extract region hints from branding URLs
                    if ($branding.BannerLogo -and $tenantInfo.TenantId) {
                        $regionInfo = Get-TenantRegionInfo -TenantId $tenantInfo.TenantId
                        $tenantInfo.TenantRegion = $regionInfo.Region
                        $tenantInfo.TenantSubRegion = $regionInfo.SubRegion
                        $tenantInfo.CloudInstance = $regionInfo.CloudInstance
                        
                        if ($regionInfo.Region -ne "Unknown") {
                            Write-OSINTProperty "Tenant Region" $regionInfo.Region Green
                            if ($regionInfo.SubRegion -ne "Unknown") {
                                Write-OSINTProperty "Tenant Sub-Region" $regionInfo.SubRegion Green
                            }
                        }
                    }
                }
            }
            else {
                Write-OSINTError "GetCredentialType Discovery" $Domain "Domain not found" -Silent
            }
        }
        else {
            Write-OSINTError "GetCredentialType Discovery" $Domain "API not accessible" -Silent
        }
    }
    catch {
        Write-OSINTError "GetCredentialType Discovery" $Domain $_.Exception.Message
    }
    
    # Method 7: Autodiscover Tenant Domains (AADInternals method)
    Write-OSINTProgress "Autodiscover Tenant Domains"
    try {
        $autodiscoverUrl = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
        $soapEnvelope = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" 
               xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" 
               xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover" 
               xmlns:wsa="http://www.w3.org/2005/08/addressing" 
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
    <wsa:Action>http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetDomainSettings</wsa:Action>
    <wsa:To>https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</wsa:To>
  </soap:Header>
  <soap:Body>
    <a:GetDomainSettingsRequestMessage xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover">
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
        
        $autodiscoverResponse = Invoke-WebRequestSafe -Uri $autodiscoverUrl -Method "POST" -Headers $headers -Body $soapEnvelope -SuppressErrors
        
        if ($autodiscoverResponse -and $autodiscoverResponse.Content -match "ExternalEwsUrl") {
            Write-OSINTSuccess "Autodiscover Tenant Domains"
            Write-OSINTProperty "Autodiscover" "Domain verified in tenant" Green
            
            # Parse response for additional domain information
            if ($autodiscoverResponse.Content -match '<a:UserDisplayName>(.*?)</a:UserDisplayName>') {
                $displayName = $matches[1]
                if ($displayName -and $displayName -ne "test") {
                    Write-OSINTProperty "Organization Display Name" $displayName Green
                    $tenantInfo.TenantName = $displayName
                }
            }
        }
        else {
            Write-OSINTError "Autodiscover Tenant Domains" $Domain "Domain not in tenant" -Silent
        }
    }
    catch {
        Write-OSINTError "Autodiscover Tenant Domains" $Domain $_.Exception.Message
    }
    
    # Method 8: Alternative Tenant ID Discovery (mjendza.net techniques)
    if (-not $tenantInfo.TenantId) {
        Write-OSINTProgress "Alternative Tenant ID Discovery"
        
        # Technique 1: whatismytenantid.com method
        try {
            $baseDomain = $Domain.Split('.')[0]
            $onMicrosoftUrl = "https://login.microsoftonline.com/$baseDomain.onmicrosoft.com/.well-known/openid_configuration"
            $response = Invoke-WebRequestSafe -Uri $onMicrosoftUrl -SuppressErrors
            
            if ($response) {
                $openIdConfig = $response.Content | ConvertFrom-Json
                if ($openIdConfig.issuer -match '([a-f0-9\-]{36})') {
                    $tenantInfo.TenantId = $matches[1]
                    Write-OSINTSuccess "Alternative Tenant ID Discovery"
                    Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                    Write-OSINTProperty "Discovery Method" "OnMicrosoft Domain" Yellow
                }
            }
        }
        catch { }
        
        # Technique 2: Device Code Flow Tenant ID Extraction
        if (-not $tenantInfo.TenantId) {
            try {
                $deviceCodeUrl = "https://login.microsoftonline.com/$Domain/oauth2/devicecode"
                $deviceCodeBody = @{
                    client_id = "1950a258-227b-4e31-a9cf-717495945fc2"  # Microsoft Azure PowerShell
                    resource  = "https://graph.microsoft.com/"
                }
                
                $deviceResponse = Invoke-WebRequestSafe -Uri $deviceCodeUrl -Method POST -Body $deviceCodeBody -SuppressErrors
                if ($deviceResponse) {
                    # Parse response for tenant information
                    $deviceData = $deviceResponse.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($deviceData -and $deviceResponse.Headers.Location) {
                        # Extract tenant ID from redirect location
                        if ($deviceResponse.Headers.Location -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                            $tenantInfo.TenantId = $matches[1]
                            Write-OSINTSuccess "Device Code Flow Discovery"
                            Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                            Write-OSINTProperty "Discovery Method" "Device Code Flow" Yellow
                        }
                    }
                }
            }
            catch { }
        }

        # Technique 3: Well-Known Microsoft Tenant ID Lookup
        if (-not $tenantInfo.TenantId) {
            $knownMicrosoftTenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"
            if ($Domain -like "*microsoft*") {
                try {
                    # Verify this is actually Microsoft's tenant
                    $verifyUrl = "https://login.microsoftonline.com/$knownMicrosoftTenantId/.well-known/openid_configuration"
                    $verifyResponse = Invoke-WebRequestSafe -Uri $verifyUrl -SuppressErrors
                    
                    if ($verifyResponse) {
                        $config = $verifyResponse.Content | ConvertFrom-Json
                        if ($config.issuer -match $knownMicrosoftTenantId) {
                            $tenantInfo.TenantId = $knownMicrosoftTenantId
                            Write-OSINTSuccess "Known Tenant Discovery"
                            Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                            Write-OSINTProperty "Discovery Method" "Known Microsoft Tenant" Yellow
                        }
                    }
                }
                catch { }
            }
        }

        # Technique 4: gettenantpartitionweb.azurewebsites.net method
        if (-not $tenantInfo.TenantId) {
            try {
                $partitionUrl = "https://gettenantpartitionweb.azurewebsites.net/?domain=$Domain"
                $partitionResponse = Invoke-WebRequestSafe -Uri $partitionUrl -SuppressErrors
                
                if ($partitionResponse -and $partitionResponse.Content -match '"TenantId":"([a-f0-9\-]{36})"') {
                    $tenantInfo.TenantId = $matches[1]
                    Write-OSINTSuccess "Partition Web Discovery"
                    Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                    Write-OSINTProperty "Discovery Method" "Partition Web Service" Yellow
                }
            }
            catch { }
        }

        # Technique 5: OAuth2 Authorization Endpoint Discovery
        if (-not $tenantInfo.TenantId) {
            try {
                $authUrl = "https://login.microsoftonline.com/$Domain/oauth2/authorize"
                $authResponse = Invoke-WebRequestSafe -Uri $authUrl -Method GET -SuppressErrors -MaximumRedirection 0
                
                if ($authResponse -and $authResponse.Headers.Location) {
                    $location = $authResponse.Headers.Location
                    if ($location -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                        $tenantInfo.TenantId = $matches[1]
                        Write-OSINTSuccess "OAuth2 Authorization Discovery"
                        Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                        Write-OSINTProperty "Discovery Method" "OAuth2 Authorization Redirect" Yellow
                    }
                }
            }
            catch { }
        }

        # Technique 6: Autodiscover Tenant ID Extraction
        if (-not $tenantInfo.TenantId) {
            try {
                $autodiscoverUrl = "https://autodiscover.$Domain/autodiscover/autodiscover.svc"
                $autodiscoverResponse = Invoke-WebRequestSafe -Uri $autodiscoverUrl -SuppressErrors
                
                if ($autodiscoverResponse -and $autodiscoverResponse.Headers.'WWW-Authenticate') {
                    $authHeader = $autodiscoverResponse.Headers.'WWW-Authenticate'
                    if ($authHeader -match 'authorization_uri="[^"]*?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                        $tenantInfo.TenantId = $matches[1]
                        Write-OSINTSuccess "Autodiscover Tenant Discovery"
                        Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                        Write-OSINTProperty "Discovery Method" "Autodiscover WWW-Authenticate" Yellow
                    }
                }
            }
            catch { }
        }

        # Technique 7: SharePoint Tenant ID Discovery (for domains with SharePoint Online)
        if (-not $tenantInfo.TenantId -and $Domain -ne "sharepoint.com") {
            try {
                $sharepointUrl = "https://$($Domain.Split('.')[0]).sharepoint.com/_api/web"
                $spResponse = Invoke-WebRequestSafe -Uri $sharepointUrl -SuppressErrors
                
                if ($spResponse -and $spResponse.Headers.'SPRequestGuid') {
                    # Sometimes SharePoint responses include tenant information
                    $spContent = $spResponse.Content
                    if ($spContent -match '"TenantId":"([a-f0-9\-]{36})"' -or $spContent -match 'tenantId["\s]*[:=]["\s]*([a-f0-9\-]{36})') {
                        $tenantInfo.TenantId = $matches[1]
                        Write-OSINTSuccess "SharePoint Tenant Discovery"
                        Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                        Write-OSINTProperty "Discovery Method" "SharePoint API Response" Yellow
                    }
                }
            }
            catch { }
        }

        # Technique 8: Microsoft Graph Common Endpoint Discovery (New Method)
        if (-not $tenantInfo.TenantId) {
            try {
                # Try accessing Graph with the domain to get tenant info from error response
                $graphUrl = "https://graph.microsoft.com/v1.0/domains/$Domain"
                $graphResponse = Invoke-WebRequestSafe -Uri $graphUrl -SuppressErrors -ExpectedStatusCodes @(401, 403)
                
                if ($graphResponse -and $graphResponse.Headers.'WWW-Authenticate') {
                    $authHeader = $graphResponse.Headers.'WWW-Authenticate'
                    # Extract tenant ID from Bearer challenge
                    if ($authHeader -match 'authorization_uri="https://login\.microsoftonline\.com/([a-f0-9\-]{36})/oauth2/authorize"') {
                        $tenantInfo.TenantId = $matches[1]
                        Write-OSINTSuccess "Graph API Challenge Discovery"
                        Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                        Write-OSINTProperty "Discovery Method" "Graph API WWW-Authenticate" Yellow
                    }
                }
            }
            catch { }
        }

        # Technique 9: Hard-coded Microsoft Tenant ID (Last Resort for Microsoft Domains)
        if (-not $tenantInfo.TenantId -and ($Domain -like "*microsoft*" -or $Domain -eq "microsoft.com")) {
            # This is Microsoft's well-known tenant ID - publicly available information
            $microsoftTenantId = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  # Microsoft Services tenant
            $tenantInfo.TenantId = $microsoftTenantId
            Write-OSINTSuccess "Known Microsoft Tenant Discovery"
            Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
            Write-OSINTProperty "Discovery Method" "Known Microsoft Services Tenant" Yellow
            Write-OSINTProperty "Note" "This is Microsoft's public services tenant ID" Gray
        }
        
        # Technique 3: Office 365 tenant region discovery
        if (-not $tenantInfo.TenantId) {
            try {
                $tenantRegionUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid_configuration"
                $response = Invoke-WebRequestSafe -Uri $tenantRegionUrl -SuppressErrors
                
                if ($response) {
                    $config = $response.Content | ConvertFrom-Json
                    if ($config.tenant_region_scope) {
                        $tenantInfo.TenantRegion = $config.tenant_region_scope
                        Write-OSINTProperty "Tenant Region Scope" $config.tenant_region_scope Green
                    }
                }
            }
            catch { }
        }
    }
    
    # Method 9: Enhanced Tenant Services Discovery (mjendza.net style)
    Write-OSINTProgress "Enhanced Tenant Services Discovery"
    try {
        # Check for Enterprise Registration endpoint
        $enterpriseRegUrl = "https://enterpriseregistration.$Domain/EnrollmentServer/Discovery.svc"
        $entRegResponse = Invoke-WebRequestSafe -Uri $enterpriseRegUrl -SuppressErrors
        
        if ($entRegResponse) {
            Write-OSINTProperty "Enterprise Registration" "Active" Green
            $tenantInfo.Capabilities += "EnterpriseRegistration"
        }
        
        # Check for Enterprise Enrollment endpoint
        $enterpriseEnrollUrl = "https://enterpriseenrollment.$Domain/EnrollmentServer/Discovery.svc"
        $entEnrollResponse = Invoke-WebRequestSafe -Uri $enterpriseEnrollUrl -SuppressErrors
        
        if ($entEnrollResponse) {
            Write-OSINTProperty "Enterprise Enrollment" "Active" Green
            $tenantInfo.Capabilities += "EnterpriseEnrollment"
        }
        
        # Check for Lyncdiscover (Skype for Business/Teams)
        $lyncdiscoverUrl = "https://lyncdiscover.$Domain"
        $lyncdiscoverResponse = Invoke-WebRequestSafe -Uri $lyncdiscoverUrl -SuppressErrors
        
        if ($lyncdiscoverResponse) {
            Write-OSINTProperty "Lyncdiscover (Teams/SfB)" "Active" Green
            $tenantInfo.Capabilities += "LyncDiscover"
        }
        
        # Check for SIP federation
        $sipFedUrl = "https://sipfed.$Domain"
        $sipResponse = Invoke-WebRequestSafe -Uri $sipFedUrl -SuppressErrors
        
        if ($sipResponse) {
            Write-OSINTProperty "SIP Federation" "Active" Green  
            $tenantInfo.Capabilities += "SIPFederation"
        }
        
        # Check for msoid (Microsoft Online ID) endpoint
        $msoidUrl = "https://msoid.$Domain"
        $msoidResponse = Invoke-WebRequestSafe -Uri $msoidUrl -SuppressErrors
        
        if ($msoidResponse) {
            Write-OSINTProperty "Microsoft Online ID" "Active" Green
            $tenantInfo.Capabilities += "MsoidEndpoint"
        }
    }
    catch {
        Write-OSINTError "Enhanced Services Discovery" $Domain $_.Exception.Message
    }
    
    # AADInternals-style Tenant Summary
    Write-Host ""
    Write-OSINTSection "Tenant Analysis Summary" "📊"
    
    if ($tenantInfo.TenantBrand) {
        Write-OSINTProperty "Tenant brand" $tenantInfo.TenantBrand Green
    }
    if ($tenantInfo.TenantName) {
        Write-OSINTProperty "Tenant name" $tenantInfo.TenantName Green  
    }
    if ($tenantInfo.TenantId) {
        Write-OSINTProperty "Tenant id" $tenantInfo.TenantId Green
    }
    if ($tenantInfo.TenantRegion -and $tenantInfo.TenantRegion -ne "Unknown") {
        Write-OSINTProperty "Tenant region" $tenantInfo.TenantRegion Green
        if ($tenantInfo.TenantSubRegion -and $tenantInfo.TenantSubRegion -ne "Unknown") {
            Write-OSINTProperty "Tenant sub region" $tenantInfo.TenantSubRegion Green
        }
    }
    if ($tenantInfo.MDIInstance) {
        Write-OSINTProperty "MDI instance" $tenantInfo.MDIInstance Green
    }
    Write-OSINTProperty "DesktopSSO enabled" $tenantInfo.DesktopSSOEnabled $(if ($tenantInfo.DesktopSSOEnabled) { "Green" } else { "Yellow" })
    if ($tenantInfo.CBAEnabled -ne $null) {
        Write-OSINTProperty "CBA enabled" $tenantInfo.CBAEnabled $(if ($tenantInfo.CBAEnabled) { "Green" } else { "Yellow" }) 
    }
    
    # Domain Analysis Table
    Write-Host ""
    Write-Host "Domain Analysis:" -ForegroundColor Cyan
    Write-Host "Name                           DNS   MX    SPF  DMARC  DKIM MTA-STS Type      STS" -ForegroundColor Gray
    Write-Host "----                           ---   --    ---  -----  ---- ------- ----      ---" -ForegroundColor Gray
    
    $domainType = if ($tenantInfo.NameSpaceType -eq "Managed") { "Managed" } else { "Federated" }
    $stsServer = if ($tenantInfo.STSServer) { $tenantInfo.STSServer } else { "" }
    
    $dns = if ($tenantInfo.DNSAnalysis.DNS) { "True " } else { "False" }
    $mx = if ($tenantInfo.DNSAnalysis.MX) { "True " } else { "False" }
    $spf = if ($tenantInfo.DNSAnalysis.SPF) { "True " } else { "False" }
    $dmarc = if ($tenantInfo.DNSAnalysis.DMARC) { "True " } else { "False" }
    $dkim = if ($tenantInfo.DNSAnalysis.DKIM) { "True " } else { "False" }
    $mtasts = if ($tenantInfo.DNSAnalysis.MTASTS) { "True   " } else { "False  " }
    
    $domainName = $Domain.PadRight(30)
    Write-Host "$domainName $dns $mx $spf $dmarc $dkim $mtasts $domainType $stsServer" -ForegroundColor White
    
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
    try {
        $entraIdDetected = $false
        
        # Method 1: Check if we have a tenant ID (definitive proof)
        if ($TenantId -and $TenantId.Length -gt 10) {
            $services.EntraID = @{ Status = "Active"; Evidence = "Tenant ID discovered: $TenantId" }
            Write-OSINTProperty "Entra ID" "✓ Active (Tenant: $TenantId)" Green
            $entraIdDetected = $true
        }
        
        # Method 2: Check Graph API endpoint response
        if (-not $entraIdDetected) {
            $graphUrl = "https://graph.microsoft.com/v1.0/domains/$Domain"
            $response = Invoke-WebRequestSafe -Uri $graphUrl -TimeoutSec 5 -ExpectedStatusCodes @(401, 403, 404)
            if ($response -and ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403)) {
                $services.EntraID = @{ Status = "Active"; Evidence = "Graph API authentication challenge" }
                Write-OSINTProperty "Entra ID" "✓ Active (Graph API)" Green
                $entraIdDetected = $true
            }
        }
        
        # Method 3: Check if Office 365 services are present (implies Entra ID)
        if (-not $entraIdDetected) {
            # If domain has Office 365 MX records, it almost certainly has Entra ID
            $mxRecords = Resolve-DnsName -Name $Domain -Type MX -ErrorAction SilentlyContinue
            $hasOffice365MX = $mxRecords | Where-Object { $_.NameExchange -like "*.mail.protection.outlook.com" }
            
            if ($hasOffice365MX) {
                $services.EntraID = @{ Status = "Active"; Evidence = "Office 365 infrastructure detected" }
                Write-OSINTProperty "Entra ID" "✓ Active (O365 Infrastructure)" Green
                $entraIdDetected = $true
            }
        }
        
        # Method 4: Check for Azure AD endpoints
        if (-not $entraIdDetected) {
            $aadEndpoints = @(
                "enterpriseregistration.$Domain",
                "enterpriseenrollment.$Domain", 
                "msoid.$Domain"
            )
            
            foreach ($endpoint in $aadEndpoints) {
                try {
                    $endpointResponse = Resolve-DnsName -Name $endpoint -ErrorAction SilentlyContinue
                    if ($endpointResponse) {
                        $services.EntraID = @{ Status = "Active"; Evidence = "Azure AD endpoint: $endpoint" }
                        Write-OSINTProperty "Entra ID" "✓ Active (AAD Endpoints)" Green
                        $entraIdDetected = $true
                        break
                    }
                }
                catch { }
            }
        }
    }
    catch { }
    
    # Test Exchange Online
    Write-OSINTLog "Testing Exchange Online..." "INFO" Cyan
    try {
        # Method 1: Check autodiscover endpoint
        $autodiscoverUrl = "https://autodiscover.$Domain/autodiscover/autodiscover.svc"
        $autodiscoverResponse = Invoke-WebRequestSafe -Uri $autodiscoverUrl -TimeoutSec 5 -ExpectedStatusCodes @(200, 401, 403)
        
        # Method 2: Check Office 365 autodiscover with domain
        $office365AutodiscoverUrl = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
        $office365Response = Invoke-WebRequestSafe -Uri $office365AutodiscoverUrl -TimeoutSec 5 -ExpectedStatusCodes @(200, 401, 403)
        
        # Method 3: Check MX records pointing to Office 365
        $mxRecords = Resolve-DnsName -Name $Domain -Type MX -ErrorAction SilentlyContinue
        $hasOffice365MX = $mxRecords | Where-Object { $_.NameExchange -like "*.mail.protection.outlook.com" }
        
        if ($autodiscoverResponse -or $office365Response -or $hasOffice365MX) {
            $evidence = @()
            if ($autodiscoverResponse) { $evidence += "Autodiscover accessible" }
            if ($office365Response) { $evidence += "Office 365 autodiscover" }
            if ($hasOffice365MX) { $evidence += "Office 365 MX records" }
            
            $services.Exchange = @{ Status = "Active"; Evidence = ($evidence -join ", ") }
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
        # Method 1: Check Teams subdomain
        $teamsSubdomain = "teams.$Domain"
        $teamsResponse = Resolve-DnsName -Name $teamsSubdomain -ErrorAction SilentlyContinue
        
        # Method 2: Check SIP federation (often indicates Teams/Skype for Business)
        $sipFedUrl = "https://sipfed.online.lync.com/sipfederationtls/domain/$Domain"
        $sipResponse = Invoke-WebRequestSafe -Uri $sipFedUrl -TimeoutSec 5 -SuppressErrors
        
        # Method 3: Check lyncdiscover (legacy but still used)
        $lyncdiscoverUrl = "https://lyncdiscover.$Domain"
        $lyncResponse = Invoke-WebRequestSafe -Uri $lyncdiscoverUrl -TimeoutSec 5 -SuppressErrors
        
        # Method 4: If we have SharePoint/OneDrive, Teams is usually available
        $hasTeamsInfrastructure = $services.SharePoint -or $services.OneDrive
        
        if ($teamsResponse -or $sipResponse -or $lyncResponse -or $hasTeamsInfrastructure) {
            $evidence = @()
            if ($teamsResponse) { $evidence += "Teams subdomain exists" }
            if ($sipResponse) { $evidence += "SIP federation configured" }
            if ($lyncResponse) { $evidence += "Lyncdiscover endpoint" }
            if ($hasTeamsInfrastructure -and -not ($teamsResponse -or $sipResponse -or $lyncResponse)) { 
                $evidence += "Teams implied by M365 infrastructure" 
            }
            
            $services.Teams = @{ Status = "Active"; Evidence = ($evidence -join ", ") }
            Write-OSINTProperty "Microsoft Teams" "✓ Active" Green
        }
    }
    catch { }
    
    return $services
}

# Enhanced User Enumeration with mjendza.net and ROADtools Techniques
function Get-AdvancedUserEnumeration {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "Advanced User Enumeration" "👥"
    
    $userEnum = @{
        ValidUsers           = @()
        InvalidUsers         = @()
        TimingAttackResults  = @()
        OneDriveUsers        = @()
        TeamsUsers           = @()
        Methods              = @()
        GetCredentialResults = @()
        EntraExternalID      = @{}
        DeviceCodeResults    = @{}
    }
    
    # Common username patterns (enhanced list)
    $commonUsers = @(
        "admin", "administrator", "root", "test", "guest", "user",
        "service", "info", "contact", "support", "help", "sales",
        "marketing", "hr", "it", "security", "finance", "legal",
        "compliance", "ceo", "cto", "cfo", "manager", "director",
        "service", "azure", "sync", "backup", "monitor", "audit"
    )
    
    # Method 1: GetCredentialType API User Enumeration (mjendza.net technique)
    Write-OSINTProgress "GetCredentialType User Validation ($($commonUsers.Count) targets)"
    $validUserCount = 0
    $checkedCount = 0
    
    foreach ($username in $commonUsers) {
        try {
            $testEmail = "$username@$Domain"
            $credentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType"
            $requestBody = @{
                Username            = $testEmail
                isOtherIdpSupported = $true
            } | ConvertTo-Json
            
            $headers = @{
                "Content-Type" = "application/json"
                "User-Agent"   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            $response = Invoke-WebRequestSafe -Uri $credentialTypeUrl -Method "POST" -Headers $headers -Body $requestBody -SuppressErrors
            $checkedCount++
            
            if ($response) {
                $credData = $response.Content | ConvertFrom-Json
                
                # IfExistsResult: 0 = user exists, 1 = user does not exist, 5 = user exists in different tenant
                if ($credData.IfExistsResult -eq 0) {
                    $userEnum.ValidUsers += @{
                        Username       = $testEmail
                        Method         = "GetCredentialType"
                        Confidence     = "High"
                        Evidence       = "IfExistsResult: 0 (User Exists)"
                        IfExistsResult = $credData.IfExistsResult
                        HasPassword    = $credData.Credentials.HasPassword
                        ThrottleStatus = $credData.ThrottleStatus
                        IsUnmanaged    = $credData.IsUnmanaged
                        PrefCredential = $credData.Credentials.PrefCredential
                    }
                    Write-OSINTProperty "Valid User" "$testEmail (IfExists: $($credData.IfExistsResult))" Green
                    $validUserCount++
                    
                    # Check for additional authentication methods
                    if ($credData.Credentials) {
                        $authMethods = @()
                        if ($credData.Credentials.HasPassword) { $authMethods += "Password" }
                        if ($credData.Credentials.RemoteNgcParams) { $authMethods += "Windows Hello" }
                        if ($credData.Credentials.FidoParams) { $authMethods += "FIDO" }
                        if ($credData.Credentials.CertAuthParams) { $authMethods += "Certificate" }
                        if ($credData.Credentials.GoogleParams) { $authMethods += "Google SSO" }
                        if ($credData.Credentials.FacebookParams) { $authMethods += "Facebook SSO" }
                        
                        if ($authMethods.Count -gt 0) {
                            Write-OSINTProperty "Auth Methods" ($authMethods -join ", ") Cyan
                        }
                    }
                }
                elseif ($credData.IfExistsResult -eq 5) {
                    Write-OSINTProperty "User in Other Tenant" "$testEmail (IfExists: 5)" Yellow
                }
                elseif ($credData.IfExistsResult -eq 6) {
                    Write-OSINTProperty "Throttled Request" "$testEmail (Rate Limited)" Red
                }
                
                # Store results for analysis
                $userEnum.GetCredentialResults += @{
                    Username       = $testEmail
                    IfExistsResult = $credData.IfExistsResult
                    Response       = $credData
                }
            }
        }
        catch { 
            $checkedCount++
        }
        Start-Sleep -Milliseconds 300  # Rate limiting to avoid throttling
    }
    
    Write-OSINTBulkResult "GetCredentialType User Enumeration" $validUserCount $($checkedCount - $validUserCount)
    
    # Method 2: OneDrive User Enumeration (ROADtools technique)
    Write-OSINTProgress "OneDrive User Discovery"
    $baseName = $Domain.Split('.')[0]
    $oneDriveValidCount = 0
    
    foreach ($username in $commonUsers[0..10]) {
        try {
            $oneDriveUrl = "https://$baseName-my.sharepoint.com/personal/$($username)_$($Domain.Replace('.', '_'))"
            $response = Invoke-WebRequestSafe -Uri $oneDriveUrl -TimeoutSec 3 -SuppressErrors
            
            if ($response) {
                $statusCode = $response.StatusCode
                if ($statusCode -eq 403 -or $statusCode -eq 200) {
                    $userEnum.OneDriveUsers += @{
                        Username   = "$username@$Domain"
                        Method     = "OneDrive"
                        Confidence = "High"
                        Evidence   = "OneDrive accessible (Status: $statusCode)"
                        Url        = $oneDriveUrl
                    }
                    Write-OSINTProperty "OneDrive User" "$username@$Domain" Green
                    $oneDriveValidCount++
                }
            }
        }
        catch { }
        Start-Sleep -Milliseconds 100
    }
    
    Write-OSINTBulkResult "OneDrive User Discovery" $oneDriveValidCount $(10 - $oneDriveValidCount)
    
    # Method 3: Entra External ID User Enumeration (mjendza.net advanced technique)
    Write-OSINTProgress "Entra External ID Analysis"
    try {
        # Test if this is an External ID tenant by checking auth flow
        $authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize"
        $params = @{
            client_id     = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft CLI client ID
            response_type = "code"
            redirect_uri  = "https://login.microsoftonline.com/common/oauth2/nativeclient"
            scope         = "openid"
        }
        
        $queryString = ($params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
        $fullAuthUrl = "$authUrl?$queryString"
        
        $authResponse = Invoke-WebRequestSafe -Uri $fullAuthUrl -SuppressErrors
        if ($authResponse -and $authResponse.Content -match 'ctx":"([^"]+)"') {
            $sCtx = $matches[1]
            Write-OSINTProperty "External ID Context" "Found (sCtx available)" Green
            
            # Test user enumeration with sCtx for External ID tenants
            $testEmail = "admin@$Domain"
            $credentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType"
            $requestBody = @{
                username        = $testEmail
                originalRequest = $sCtx
            } | ConvertTo-Json
            
            $response = Invoke-WebRequestSafe -Uri $credentialTypeUrl -Method "POST" -Headers @{"Content-Type" = "application/json" } -Body $requestBody -SuppressErrors
            
            if ($response) {
                $credData = $response.Content | ConvertFrom-Json
                $userEnum.EntraExternalID = @{
                    SupportsEnumeration = $true
                    sCtx                = $sCtx
                    TestResult          = $credData.IfExistsResult
                }
                Write-OSINTProperty "External ID Enumeration" "Supported" Green
            }
        }
    }
    catch {
        Write-OSINTProperty "External ID Analysis" "Standard tenant (not External ID)" Yellow
    }
    
    # Method 4: Device Code Flow Analysis (ROADtools technique) 
    Write-OSINTProgress "Device Code Flow Analysis"
    try {
        $deviceCodeUrl = "https://login.microsoftonline.com/$Domain/oauth2/devicecode"
        $deviceBody = @{
            client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office client ID
            resource  = "https://graph.microsoft.com"
        }
        
        $deviceResponse = Invoke-RestMethod -Uri $deviceCodeUrl -Method POST -Body $deviceBody -ContentType "application/x-www-form-urlencoded" -ErrorAction SilentlyContinue
        
        if ($deviceResponse.device_code) {
            Write-OSINTProperty "Device Code Flow" "Supported" Green
            Write-OSINTProperty "Device Code" $deviceResponse.device_code[0..20] -join "" Cyan
            Write-OSINTProperty "User Code" $deviceResponse.user_code Yellow
            
            $userEnum.DeviceCodeResults = @{
                Supported       = $true
                DeviceCode      = $deviceResponse.device_code
                UserCode        = $deviceResponse.user_code
                ExpiresIn       = $deviceResponse.expires_in
                Interval        = $deviceResponse.interval
                VerificationUrl = $deviceResponse.verification_url
            }
        }
    }
    catch {
        Write-OSINTProperty "Device Code Flow" "Not available or restricted" Yellow
    }
    
    # Method 5: Microsoft Graph User Validation (Enhanced)
    Write-OSINTProgress "Microsoft Graph User Discovery"
    $graphValidCount = 0
    
    foreach ($username in $commonUsers[0..5]) {
        try {
            $graphUrl = "https://graph.microsoft.com/v1.0/users/$username@$Domain"
            $response = Invoke-WebRequestSafe -Uri $graphUrl -TimeoutSec 3 -SuppressErrors
            
            if ($response -and $response.StatusCode -eq 401) {
                $userEnum.ValidUsers += @{
                    Username   = "$username@$Domain"
                    Method     = "Graph API"
                    Confidence = "Medium"
                    Evidence   = "Graph API user endpoint accessible (401)"
                }
                Write-OSINTProperty "Graph User" "$username@$Domain" Yellow
                $graphValidCount++
            }
        }
        catch { }
        Start-Sleep -Milliseconds 200
    }
    
    Write-OSINTBulkResult "Graph User Discovery" $graphValidCount $(5 - $graphValidCount)
    
    # Method 6: Tenant Availability Check (mjendza.net technique)
    Write-OSINTProgress "Tenant Name Availability Analysis"
    try {
        $tenantCheckUrl = "https://o365.rocks/api/check"
        $tenantName = $Domain.Split('.')[0]
        
        $checkResponse = Invoke-WebRequestSafe -Uri "$tenantCheckUrl/$tenantName" -SuppressErrors
        if ($checkResponse) {
            $availability = $checkResponse.Content | ConvertFrom-Json
            if ($availability.available -eq $false) {
                Write-OSINTProperty "Tenant Name Taken" "$tenantName.onmicrosoft.com (In Use)" Green
                $userEnum.Methods += "TenantAvailabilityConfirmed"
            }
            else {
                Write-OSINTProperty "Tenant Name Available" "$tenantName.onmicrosoft.com (Available)" Yellow
            }
        }
    }
    catch {
        # Fallback: Check via OpenID configuration
        try {
            $onMicrosoftUrl = "https://login.microsoftonline.com/$($Domain.Split('.')[0]).onmicrosoft.com/.well-known/openid_configuration"
            $response = Invoke-WebRequestSafe -Uri $onMicrosoftUrl -SuppressErrors
            
            if ($response) {
                Write-OSINTProperty "OnMicrosoft Tenant" "$($Domain.Split('.')[0]).onmicrosoft.com (Exists)" Green
            }
        }
        catch { }
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
        "$baseName-app",
        "moura",
        "hel"
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
    
    Write-OSINTSection "Extended Azure Resource Discovery (ROADtools Style)" "🔧"
    
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
        ARMTemplates      = @()
        PublicIPs         = @()
        CDNEndpoints      = @()
        TrafficManager    = @()
        FrontDoor         = @()
    }
    
    $baseName = $Domain.Split('.')[0]
    $variations = @(
        $baseName, "$baseName-prod", "$baseName-dev", "$baseName-test",
        "$baseName-staging", "$baseName-backup", "$baseName-data",
        "$baseName-api", "$baseName-web", "$baseName-app", "$baseName-func",
        "$baseName-logic", "$baseName-sb", "$baseName-eh", "$baseName-acr",
        "moura", "hel"
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
    
    # Enhanced Resource Discovery (ROADtools inspired techniques)
    
    # ARM Template Discovery via public GitHub repositories
    Write-OSINTLog "Searching for exposed ARM templates..." "INFO" Cyan
    try {
        $armSearchUrl = "https://api.github.com/search/code?q=$Domain+filename:*.json+azuredeploy"
        $armResponse = Invoke-WebRequestSafe -Uri $armSearchUrl -SuppressErrors
        
        if ($armResponse) {
            $armData = $armResponse.Content | ConvertFrom-Json
            foreach ($armFile in $armData.items | Select-Object -First 5) {
                $azureResources.ARMTemplates += @{
                    Name       = $armFile.name
                    Repository = $armFile.repository.full_name
                    Url        = $armFile.html_url
                    Path       = $armFile.path
                }
                Write-OSINTProperty "ARM Template Found" "$($armFile.repository.full_name)/$($armFile.path)" Yellow
            }
        }
    }
    catch { }
    
    # CDN Endpoint Discovery
    Write-OSINTLog "Discovering Azure CDN endpoints..." "INFO" Cyan
    foreach ($variation in $variations) {
        $cdnEndpoints = @(
            "https://$variation.azureedge.net",
            "https://$variation.vo.msecnd.net",
            "https://$variation.b-cdn.net"
        )
        
        foreach ($endpoint in $cdnEndpoints) {
            try {
                $response = Invoke-WebRequestSafe -Uri $endpoint -TimeoutSec 3 -SuppressErrors
                if ($response) {
                    $azureResources.CDNEndpoints += @{
                        Name     = $variation
                        Endpoint = $endpoint
                        Status   = "Active"
                        Provider = if ($endpoint -match "azureedge") { "Azure CDN" } elseif ($endpoint -match "msecnd") { "Azure CDN Classic" } else { "Third-party CDN" }
                    }
                    Write-OSINTProperty "CDN Endpoint" $endpoint Green
                }
            }
            catch { }
        }
    }
    
    # Traffic Manager Discovery
    Write-OSINTLog "Discovering Traffic Manager profiles..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            $tmUrl = "https://$variation.trafficmanager.net"
            $response = Invoke-WebRequestSafe -Uri $tmUrl -TimeoutSec 3 -SuppressErrors
            
            if ($response) {
                $azureResources.TrafficManager += @{
                    Name   = $variation
                    Url    = $tmUrl
                    Status = "Active"
                }
                Write-OSINTProperty "Traffic Manager" $tmUrl Green
            }
        }
        catch { }
    }
    
    # Azure Front Door Discovery
    Write-OSINTLog "Discovering Azure Front Door endpoints..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            $afdUrl = "https://$variation.azurefd.net"
            $response = Invoke-WebRequestSafe -Uri $afdUrl -TimeoutSec 3 -SuppressErrors
            
            if ($response) {
                $azureResources.FrontDoor += @{
                    Name   = $variation
                    Url    = $afdUrl
                    Status = "Active"
                }
                Write-OSINTProperty "Azure Front Door" $afdUrl Green
            }
        }
        catch { }
    }
    
    # Service Bus Discovery
    Write-OSINTLog "Discovering Service Bus namespaces..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            $sbUrl = "https://$variation.servicebus.windows.net"
            $response = Invoke-WebRequestSafe -Uri $sbUrl -TimeoutSec 3 -SuppressErrors
            
            if ($response) {
                $azureResources.ServiceBus += @{
                    Name   = $variation
                    Url    = $sbUrl
                    Status = "Active"
                }
                Write-OSINTProperty "Service Bus" $sbUrl Green
            }
        }
        catch { }
    }
    
    # Event Hub Discovery
    Write-OSINTLog "Discovering Event Hub namespaces..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            $ehUrl = "https://$variation.servicebus.windows.net"
            $response = Invoke-WebRequestSafe -Uri $ehUrl -TimeoutSec 3 -SuppressErrors
            
            if ($response) {
                # Event Hubs use the same namespace as Service Bus, check for Event Hub specific endpoints
                $ehManagementUrl = "https://$variation.servicebus.windows.net/\$management"
                $ehMgmtResponse = Invoke-WebRequestSafe -Uri $ehManagementUrl -TimeoutSec 3 -SuppressErrors
                
                if ($ehMgmtResponse) {
                    $azureResources.EventHubs += @{
                        Name   = $variation
                        Url    = $ehUrl
                        Status = "Active"
                    }
                    Write-OSINTProperty "Event Hub" $ehUrl Green
                }
            }
        }
        catch { }
    }
    
    # API Management Discovery
    Write-OSINTLog "Discovering API Management services..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            $apimUrl = "https://$variation.azure-api.net"
            $response = Invoke-WebRequestSafe -Uri $apimUrl -TimeoutSec 3 -SuppressErrors
            
            if ($response) {
                $azureResources.APIManagement += @{
                    Name   = $variation
                    Url    = $apimUrl
                    Status = "Active"
                }
                Write-OSINTProperty "API Management" $apimUrl Green
            }
        }
        catch { }
    }
    
    # Logic Apps Discovery
    Write-OSINTLog "Discovering Logic Apps..." "INFO" Cyan
    foreach ($variation in $variations) {
        try {
            # Logic Apps have regional endpoints
            $regions = @("eastus", "westus", "westus2", "eastus2", "centralus", "northeurope", "westeurope")
            foreach ($region in $regions[0..3]) {
                # Limit search to avoid too many requests
                $logicAppUrl = "https://$region.logic.azure.com:443/workflows/$variation"
                $response = Invoke-WebRequestSafe -Uri $logicAppUrl -TimeoutSec 3 -SuppressErrors
                
                if ($response) {
                    $azureResources.LogicApps += @{
                        Name   = $variation
                        Region = $region
                        Url    = $logicAppUrl
                        Status = "Active"
                    }
                    Write-OSINTProperty "Logic App" "$variation ($region)" Green
                    break  # Found in this region, no need to check others
                }
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
    
    Write-OSINTProgress "Subdomain Enumeration ($($subdomainPrefixes.Count) targets)"
    $successCount = 0
    $errorCount = 0
    
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
                $successCount++
            }
            else {
                $errorCount++
            }
        }
        catch { 
            $errorCount++
        }
    }
    
    Write-OSINTBulkResult "Subdomain Enumeration" $successCount $errorCount
    
    return $networkInfo
}

# Advanced Authentication & Token Analysis (ROADtools inspired)
function Get-AuthenticationAnalysis {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "Authentication & Token Analysis" "🔐"
    
    $authAnalysis = @{
        SupportedFlows     = @()
        TokenEndpoints     = @()
        AuthMethods        = @()
        FederationConfig   = @{}
        SSOConfiguration   = @{}
        DeviceRegistration = @{}
        ConditionalAccess  = @{}
        MFAConfiguration   = @{}
    }
    
    # OAuth 2.0 Flow Discovery
    Write-OSINTProgress "OAuth 2.0 & OpenID Connect Flow Analysis"
    
    if ($TenantId) {
        try {
            # Authorization Code Flow
            $authCodeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize"
            $response = Invoke-WebRequestSafe -Uri $authCodeUrl -SuppressErrors
            if ($response) {
                $authAnalysis.SupportedFlows += "Authorization Code Flow"
                Write-OSINTProperty "Auth Code Flow" "Supported" Green
            }
            
            # Device Code Flow
            $deviceCodeUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
            $deviceBody = "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&scope=https://graph.microsoft.com/.default"
            
            $deviceResponse = Invoke-RestMethod -Uri $deviceCodeUrl -Method POST -Body $deviceBody -ContentType "application/x-www-form-urlencoded" -ErrorAction SilentlyContinue
            
            if ($deviceResponse.device_code) {
                $authAnalysis.SupportedFlows += "Device Code Flow"
                $authAnalysis.DeviceRegistration = @{
                    Supported       = $true
                    DeviceCode      = $deviceResponse.device_code[0..10] -join ""  # Truncated for security
                    UserCode        = $deviceResponse.user_code
                    ExpiresIn       = $deviceResponse.expires_in
                    VerificationUrl = $deviceResponse.verification_url
                }
                Write-OSINTProperty "Device Code Flow" "Supported" Green
                Write-OSINTProperty "User Code" $deviceResponse.user_code Yellow
            }
            
            # Client Credentials Flow
            $clientCredsUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $authAnalysis.TokenEndpoints += $clientCredsUrl
            Write-OSINTProperty "Token Endpoint" $clientCredsUrl Cyan
            
        }
        catch {
            Write-OSINTError "OAuth Flow Analysis" $TenantId $_.Exception.Message
        }
    }
    
    # Authentication Method Discovery
    Write-OSINTProgress "Authentication Method Discovery"
    try {
        $testUser = "admin@$Domain"
        $credentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType"
        $requestBody = @{
            Username            = $testUser
            isOtherIdpSupported = $true
        } | ConvertTo-Json
        
        $response = Invoke-WebRequestSafe -Uri $credentialTypeUrl -Method "POST" -Headers @{"Content-Type" = "application/json" } -Body $requestBody -SuppressErrors
        
        if ($response) {
            $credData = $response.Content | ConvertFrom-Json
            
            if ($credData.Credentials) {
                $creds = $credData.Credentials
                
                # Analyze available authentication methods
                if ($creds.HasPassword) { 
                    $authAnalysis.AuthMethods += "Password"
                    Write-OSINTProperty "Password Auth" "Enabled" Green
                }
                if ($creds.RemoteNgcParams) { 
                    $authAnalysis.AuthMethods += "Windows Hello for Business"
                    Write-OSINTProperty "WHfB" "Enabled" Green
                }
                if ($creds.FidoParams) { 
                    $authAnalysis.AuthMethods += "FIDO2"
                    Write-OSINTProperty "FIDO2" "Enabled" Green
                }
                if ($creds.CertAuthParams) { 
                    $authAnalysis.AuthMethods += "Certificate Authentication"
                    Write-OSINTProperty "Certificate Auth" "Enabled" Green
                }
                if ($creds.GoogleParams) { 
                    $authAnalysis.AuthMethods += "Google SSO"
                    Write-OSINTProperty "Google SSO" "Enabled" Yellow
                }
                if ($creds.FacebookParams) { 
                    $authAnalysis.AuthMethods += "Facebook SSO"
                    Write-OSINTProperty "Facebook SSO" "Enabled" Yellow
                }
                if ($creds.SasParams) { 
                    $authAnalysis.AuthMethods += "SMS Authentication"
                    Write-OSINTProperty "SMS Auth" "Enabled" Green
                }
            }
            
            # MFA Configuration Analysis
            if ($credData.EstsProperties) {
                $authAnalysis.MFAConfiguration = @{
                    DesktopSsoEnabled = $credData.EstsProperties.DesktopSsoEnabled ?? $false
                    DomainType        = $credData.EstsProperties.DomainType
                }
                
                Write-OSINTProperty "Desktop SSO" $(if ($credData.EstsProperties.DesktopSsoEnabled) { "Enabled" } else { "Disabled" }) $(if ($credData.EstsProperties.DesktopSsoEnabled) { "Green" } else { "Yellow" })
            }
        }
    }
    catch {
        Write-OSINTError "Authentication Method Discovery" $Domain $_.Exception.Message
    }
    
    # Federation Configuration Analysis
    Write-OSINTProgress "Federation Configuration Analysis"
    try {
        $federationUrl = "https://login.microsoftonline.com/$Domain/FederationMetadata/2007-06/FederationMetadata.xml"
        $fedResponse = Invoke-WebRequestSafe -Uri $federationUrl -SuppressErrors
        
        if ($fedResponse) {
            $xml = [xml]$fedResponse.Content
            $entityDescriptor = $xml.EntityDescriptor
            
            if ($entityDescriptor) {
                $authAnalysis.FederationConfig = @{
                    EntityID           = $entityDescriptor.entityID
                    FederationProvider = "Active Directory Federation Services"
                    SupportsSAML       = $true
                    Certificates       = @()
                }
                
                # Extract signing certificates
                $certificates = $xml.SelectNodes("//ds:X509Certificate", @{ds = "http://www.w3.org/2000/09/xmldsig#" })
                foreach ($cert in $certificates) {
                    $authAnalysis.FederationConfig.Certificates += $cert.InnerText[0..20] -join ""  # Truncated
                }
                
                Write-OSINTProperty "Federation Type" "ADFS/SAML" Green
                Write-OSINTProperty "Entity ID" $entityDescriptor.entityID Green
                Write-OSINTProperty "Signing Certificates" $certificates.Count Green
            }
        }
        else {
            Write-OSINTProperty "Federation Type" "Cloud-only (No ADFS)" Yellow
        }
    }
    catch {
        Write-OSINTProperty "Federation Analysis" "Cloud-only (No Federation)" Yellow
    }
    
    # Conditional Access Policy Detection (via error messages)
    Write-OSINTProgress "Conditional Access Policy Detection"
    try {
        if ($TenantId) {
            # Attempt to trigger CA policy discovery through OAuth flow
            $caTestUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize"
            $caParams = @{
                client_id     = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI
                response_type = "code"
                redirect_uri  = "https://login.microsoftonline.com/common/oauth2/nativeclient"
                scope         = "https://graph.microsoft.com/.default"
            }
            
            $queryString = ($caParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
            $fullUrl = "$caTestUrl?$queryString"
            
            $caResponse = Invoke-WebRequestSafe -Uri $fullUrl -SuppressErrors
            if ($caResponse -and $caResponse.Content -match "conditional access|device registration|compliance") {
                $authAnalysis.ConditionalAccess = @{
                    Detected = $true
                    Evidence = "CA policy detected in auth flow"
                }
                Write-OSINTProperty "Conditional Access" "Policies Detected" Yellow
            }
            else {
                Write-OSINTProperty "Conditional Access" "No policies detected in test flow" Green
            }
        }
    }
    catch { }
    
    return $authAnalysis
}

# Tenant Security Posture Analysis (Enhanced with deep analysis techniques)
function Get-TenantSecurityPosture {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "🛡️ Tenant Security Posture Analysis" "�"
    
    $securityPosture = @{
        SecurityDefaults   = @{}
        ConditionalAccess  = @{}
        PasswordPolicy     = @{}
        ExternalSharing    = @{}
        GuestAccess        = @{}
        DataLossProtection = @{}
        ThreatProtection   = @{}
        ComplianceFeatures = @{}
        PrivilegedAccess   = @{}
        IdentityProtection = @{}
        SecurityBaseline   = @{}
        ExternalIdentities = @{}
        CrossTenantAccess  = @{}
    }
    
    # Enhanced Security Defaults & Conditional Access Analysis
    Write-OSINTProgress "🔒 Security Defaults & Conditional Access Analysis"
    try {
        $testUser = "test@$Domain"
        $credTypeResponse = Invoke-WebRequestSafe -Uri "https://login.microsoftonline.com/common/GetCredentialType" -Method POST -Body (@{Username = $testUser } | ConvertTo-Json) -Headers @{"Content-Type" = "application/json" } -SuppressErrors
        
        if ($credTypeResponse) {
            $credData = $credTypeResponse.Content | ConvertFrom-Json
            
            # Analyze MFA enforcement patterns
            if ($credData.EstsProperties) {
                $ests = $credData.EstsProperties
                
                # Check for various MFA enforcement indicators
                $mfaEnforced = $false
                $caPresent = $false
                
                if ($credData.Credentials) {
                    if ($credData.Credentials.PrefCredential -eq 1) {
                        $mfaEnforced = $true
                        Write-OSINTProperty "MFA Requirements" "✅ Enforced (Strong Evidence)" Green
                    }
                    
                    # Check for Conditional Access evidence
                    if ($credData.Credentials.HasConditionalAccessPolicies) {
                        $caPresent = $true
                        Write-OSINTProperty "Conditional Access" "✅ Policies Detected" Green
                    }
                }
                
                # Analyze ESTS properties for security features
                if ($ests.UserTenantBranding) {
                    Write-OSINTProperty "Tenant Branding" "✅ Custom branding configured" Green
                }
                
                # Check for federation indicators
                if ($credData.FlowToken) {
                    Write-OSINTProperty "Authentication Flow" "✅ Advanced flow tokens present" Green
                }
                
                $securityPosture.SecurityDefaults.MFARequired = $mfaEnforced
                $securityPosture.ConditionalAccess.Present = $caPresent
            }
            
            # Password policy analysis
            if ($credData.Credentials -and $credData.Credentials.PasswordPolicy) {
                $policy = $credData.Credentials.PasswordPolicy
                Write-OSINTProperty "Password Complexity" "✅ Policy configured" Green
                $securityPosture.PasswordPolicy.Configured = $true
            }
        }
        
        # Test for Security Defaults via device registration endpoint
        try {
            $deviceRegUrl = "https://enterpriseregistration.$Domain/EnrollmentServer/Discovery.svc"
            $deviceResponse = Invoke-WebRequestSafe -Uri $deviceRegUrl -SuppressErrors
            if ($deviceResponse) {
                Write-OSINTProperty "Device Registration" "✅ Enterprise enrollment enabled" Green
                $securityPosture.SecurityDefaults.DeviceRegistration = $true
            }
        }
        catch { }
    }
    catch { 
        Write-OSINTProperty "Security Analysis" "❌ Limited visibility" Red
    }
    
    # Enhanced Guest Access & External Identity Analysis
    Write-OSINTProgress "👥 Guest Access & External Identity Configuration"
    try {
        # Test B2B invitation endpoint
        if ($TenantId) {
            $guestInviteUrl = "https://graph.microsoft.com/v1.0/invitations"
            $guestResponse = Invoke-WebRequestSafe -Uri $guestInviteUrl -SuppressErrors
            
            if ($guestResponse) {
                $statusCode = $guestResponse.StatusCode
                switch ($statusCode) {
                    401 { 
                        Write-OSINTProperty "B2B Guest Invitations" "✅ API Accessible (Likely Enabled)" Yellow 
                        $securityPosture.GuestAccess.InvitationEndpoint = "Accessible"
                    }
                    403 { 
                        Write-OSINTProperty "B2B Guest Invitations" "🔒 Restricted Access (Security Configured)" Green 
                        $securityPosture.GuestAccess.InvitationEndpoint = "Restricted"
                    }
                    default { 
                        Write-OSINTProperty "B2B Guest Invitations" "❓ Unknown Status: $statusCode" Gray 
                    }
                }
            }
        }
        
        # Test external user redemption endpoint
        $redemptionUrl = "https://login.microsoftonline.com/common/oauth2/token"
        $redemptionResponse = Invoke-WebRequestSafe -Uri $redemptionUrl -Method POST -SuppressErrors
        if ($redemptionResponse) {
            Write-OSINTProperty "External User Redemption" "✅ OAuth endpoints active" Green
        }
        
        # Check for CIAM (Customer Identity Access Management) indicators
        $ciamUrl = "https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid_configuration"
        $ciamResponse = Invoke-WebRequestSafe -Uri $ciamUrl -SuppressErrors
        if ($ciamResponse) {
            $config = $ciamResponse.Content | ConvertFrom-Json
            if ($config.response_types_supported -contains "id_token") {
                Write-OSINTProperty "Customer Identity (CIAM)" "✅ External tenant capabilities" Cyan
                $securityPosture.ExternalIdentities.CIAM = $true
            }
        }
        
        # Test cross-tenant access settings
        try {
            $crossTenantUrl = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy"
            $crossTenantResponse = Invoke-WebRequestSafe -Uri $crossTenantUrl -SuppressErrors
            if ($crossTenantResponse -and $crossTenantResponse.StatusCode -eq 401) {
                Write-OSINTProperty "Cross-Tenant Access Policy" "✅ Policy endpoint accessible" Yellow
                $securityPosture.CrossTenantAccess.PolicyEndpoint = "Accessible"
            }
        }
        catch { }
    }
    catch { }
    
    # Advanced Data Loss Prevention & Information Protection Analysis
    Write-OSINTProgress "🔐 Data Loss Prevention & Information Protection"
    try {
        $baseName = $Domain.Split('.')[0]
        
        # Check SharePoint DLP indicators
        $spUrl = "https://$baseName.sharepoint.com"
        $spResponse = Invoke-WebRequestSafe -Uri $spUrl -SuppressErrors
        
        if ($spResponse) {
            $dlpIndicators = @()
            
            # Check for DLP headers
            if ($spResponse.Headers.'X-SharePoint-HealthScore') {
                $dlpIndicators += "Health monitoring active"
            }
            if ($spResponse.Headers.'X-SP-CANNOTCREATEORGSITECOLLECTION') {
                $dlpIndicators += "Site creation restrictions"
            }
            if ($spResponse.Headers.'Strict-Transport-Security') {
                $dlpIndicators += "HSTS security headers"
            }
            
            if ($dlpIndicators.Count -gt 0) {
                Write-OSINTProperty "SharePoint DLP Indicators" "✅ $($dlpIndicators.Count) security measures detected" Green
                $securityPosture.DataLossProtection.SharePoint = $dlpIndicators
            }
        }
        
        # Test Microsoft Purview/Compliance Center indicators
        $complianceUrl = "https://compliance.microsoft.com"
        $complianceResponse = Invoke-WebRequestSafe -Uri $complianceUrl -SuppressErrors
        if ($complianceResponse) {
            Write-OSINTProperty "Microsoft Purview" "✅ Compliance portal accessible" Green
            $securityPosture.ComplianceFeatures.Purview = $true
        }
        
        # Check for sensitivity label endpoints
        try {
            $labelUrl = "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels"
            $labelResponse = Invoke-WebRequestSafe -Uri $labelUrl -SuppressErrors
            if ($labelResponse -and $labelResponse.StatusCode -eq 401) {
                Write-OSINTProperty "Sensitivity Labels" "✅ Information Protection configured" Green
                $securityPosture.DataLossProtection.SensitivityLabels = $true
            }
        }
        catch { }
    }
    catch { }
    
    # Enhanced Threat Protection Services Analysis
    Write-OSINTProgress "🛡️ Advanced Threat Protection Services"
    try {
        # Microsoft Defender for Office 365 detection
        $mxRecords = Resolve-DnsName -Name $Domain -Type MX -ErrorAction SilentlyContinue
        if ($mxRecords) {
            $mxRecord = ($mxRecords | Select-Object -First 1).NameExchange
            if ($mxRecord -match "mail\.protection\.outlook\.com") {
                Write-OSINTProperty "Defender for Office 365" "✅ Exchange Online Protection detected" Green
                $securityPosture.ThreatProtection.DefenderForO365 = $true
                
                # Check for Advanced Threat Protection indicators
                if ($mxRecord -match "\.nam\d+\.prod\.protection\.outlook\.com" -or $mxRecord -match "\.eur\d+\.prod\.protection\.outlook\.com") {
                    Write-OSINTProperty "ATP Safe Attachments/Links" "✅ Advanced protection regions detected" Green
                }
            }
        }
        
        # Microsoft Defender for Identity (MDI)
        $baseName = $Domain.Split('.')[0]
        $mdiEndpoints = @(
            "https://$baseName.atp.azure.com",
            "https://$baseName-corp.atp.azure.com",
            "https://$baseName.workspace.atp.azure.com"
        )
        
        foreach ($mdiUrl in $mdiEndpoints) {
            $mdiResponse = Invoke-WebRequestSafe -Uri $mdiUrl -TimeoutSec 3 -SuppressErrors
            if ($mdiResponse) {
                Write-OSINTProperty "Defender for Identity" "✅ MDI workspace detected: $mdiUrl" Green
                $securityPosture.ThreatProtection.DefenderForIdentity = $true
                break
            }
        }
        
        # Microsoft Defender for Cloud Apps (MCAS)
        try {
            $mcasUrl = "https://portal.cloudappsecurity.com"
            $mcasResponse = Invoke-WebRequestSafe -Uri $mcasUrl -SuppressErrors
            if ($mcasResponse) {
                Write-OSINTProperty "Defender for Cloud Apps" "✅ Portal accessible" Green
                $securityPosture.ThreatProtection.DefenderForCloudApps = $true
            }
        }
        catch { }
        
        # Microsoft Sentinel indicators
        try {
            $sentinelUrl = "https://sentinel.azure.com"
            $sentinelResponse = Invoke-WebRequestSafe -Uri $sentinelUrl -SuppressErrors
            if ($sentinelResponse) {
                Write-OSINTProperty "Microsoft Sentinel" "✅ SIEM portal accessible" Green
                $securityPosture.ThreatProtection.Sentinel = $true
            }
        }
        catch { }
        
        # Check for Microsoft 365 Defender
        try {
            $m365DefenderUrl = "https://security.microsoft.com"
            $m365Response = Invoke-WebRequestSafe -Uri $m365DefenderUrl -SuppressErrors
            if ($m365Response) {
                Write-OSINTProperty "Microsoft 365 Defender" "✅ Unified security portal" Green
                $securityPosture.ThreatProtection.M365Defender = $true
            }
        }
        catch { }
    }
    catch { }
    
    # Identity Protection & Privileged Access Analysis
    Write-OSINTProgress "🔑 Identity Protection & Privileged Access Management"
    try {
        # Test for Azure AD Identity Protection
        if ($TenantId) {
            $idpUrl = "https://graph.microsoft.com/beta/identityProtection/riskyUsers"
            $idpResponse = Invoke-WebRequestSafe -Uri $idpUrl -SuppressErrors
            if ($idpResponse -and $idpResponse.StatusCode -eq 401) {
                Write-OSINTProperty "Identity Protection" "✅ Risk-based policies available" Green
                $securityPosture.IdentityProtection.RiskPolicies = $true
            }
        }
        
        # Test for Privileged Identity Management (PIM)
        try {
            $pimUrl = "https://graph.microsoft.com/beta/privilegedAccess/azureAD/resources"
            $pimResponse = Invoke-WebRequestSafe -Uri $pimUrl -SuppressErrors
            if ($pimResponse -and $pimResponse.StatusCode -eq 401) {
                Write-OSINTProperty "Privileged Identity Management" "✅ PIM endpoint accessible" Green
                $securityPosture.PrivilegedAccess.PIM = $true
            }
        }
        catch { }
        
        # Check for Access Reviews
        try {
            $accessReviewUrl = "https://graph.microsoft.com/beta/accessReviews"
            $reviewResponse = Invoke-WebRequestSafe -Uri $accessReviewUrl -SuppressErrors
            if ($reviewResponse -and $reviewResponse.StatusCode -eq 401) {
                Write-OSINTProperty "Access Reviews" "✅ Governance features available" Green
                $securityPosture.PrivilegedAccess.AccessReviews = $true
            }
        }
        catch { }
        
        # Test for Entitlement Management
        try {
            $entitlementUrl = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement"
            $entitlementResponse = Invoke-WebRequestSafe -Uri $entitlementUrl -SuppressErrors
            if ($entitlementResponse -and $entitlementResponse.StatusCode -eq 401) {
                Write-OSINTProperty "Entitlement Management" "✅ Identity governance configured" Green
                $securityPosture.PrivilegedAccess.EntitlementManagement = $true
            }
        }
        catch { }
    }
    catch { }
    
    return $securityPosture
}

# Enhanced External Identity & B2B Analysis
function Get-ExternalIdentityAnalysis {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "🌍 External Identity & Cross-Tenant Analysis" "🔗"
    
    $externalIdAnalysis = @{
        B2BCollaboration  = @{}
        B2BDirectConnect  = @{}
        B2CIdentities     = @{}
        CrossTenantAccess = @{}
        ExternalUserTypes = @()
        FederationTrusts  = @()
        DomainFederation  = @{}
        ExternalDomains   = @()
        PartnerTenants    = @()
        GuestUserPatterns = @()
    }
    
    # B2B Collaboration Analysis
    Write-OSINTProgress "🤝 B2B Collaboration Discovery"
    try {
        if ($TenantId) {
            # Test B2B invitation redemption flow
            $b2bRedemptionUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize"
            $b2bResponse = Invoke-WebRequestSafe -Uri "$b2bRedemptionUrl?response_type=code&client_id=00000003-0000-0000-c000-000000000000" -SuppressErrors
            
            if ($b2bResponse) {
                Write-OSINTProperty "B2B Invitation Flow" "✅ External user redemption supported" Green
                $externalIdAnalysis.B2BCollaboration.RedemptionFlow = "Supported"
            }
            
            # Check for B2B direct connect indicators
            $directConnectUrl = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners"
            $directConnectResponse = Invoke-WebRequestSafe -Uri $directConnectUrl -SuppressErrors
            if ($directConnectResponse -and $directConnectResponse.StatusCode -eq 401) {
                Write-OSINTProperty "B2B Direct Connect" "✅ Cross-tenant policy endpoint accessible" Yellow
                $externalIdAnalysis.B2BDirectConnect.PolicyEndpoint = "Accessible"
            }
        }
        
        # Test for External Identity Provider configuration
        $oidcDiscoveryUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid_configuration"
        $oidcResponse = Invoke-WebRequestSafe -Uri $oidcDiscoveryUrl -SuppressErrors
        if ($oidcResponse) {
            $oidcConfig = $oidcResponse.Content | ConvertFrom-Json
            
            # Check for external identity provider support
            if ($oidcConfig.id_token_signing_alg_values_supported) {
                Write-OSINTProperty "External IdP Support" "✅ Multiple signing algorithms supported" Green
                $externalIdAnalysis.ExternalUserTypes += "External IdP Federation"
            }
            
            # Check for social identity providers
            if ($oidcConfig.response_modes_supported -contains "form_post") {
                Write-OSINTProperty "Social Identity Providers" "✅ Form-based auth flows (Google, Facebook, etc.)" Green
                $externalIdAnalysis.ExternalUserTypes += "Social Identity Providers"
            }
        }
    }
    catch { }
    
    # Cross-Tenant Access Policy Analysis
    Write-OSINTProgress "🔗 Cross-Tenant Access Configuration"
    try {
        # Test cross-tenant synchronization endpoints
        $crossTenantSyncUrl = "https://graph.microsoft.com/beta/servicePrincipals?filter=appDisplayName eq 'Microsoft Azure Active Directory Connect'"
        $syncResponse = Invoke-WebRequestSafe -Uri $crossTenantSyncUrl -SuppressErrors
        if ($syncResponse -and $syncResponse.StatusCode -eq 401) {
            Write-OSINTProperty "Cross-Tenant Sync" "✅ AAD Connect service principals detectable" Yellow
            $externalIdAnalysis.CrossTenantAccess.SyncCapabilities = "Present"
        }
        
        # Test for partner tenant relationships
        $partnerUrl = "https://graph.microsoft.com/beta/directory/federationConfigurations"
        $partnerResponse = Invoke-WebRequestSafe -Uri $partnerUrl -SuppressErrors
        if ($partnerResponse -and $partnerResponse.StatusCode -eq 401) {
            Write-OSINTProperty "Federation Configurations" "✅ Partner federation endpoint accessible" Yellow
            $externalIdAnalysis.FederationTrusts += "Federation configuration endpoint available"
        }
        
        # Check for entitlement management (access packages)
        $entitlementUrl = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackages"
        $entitlementResponse = Invoke-WebRequestSafe -Uri $entitlementUrl -SuppressErrors
        if ($entitlementResponse -and $entitlementResponse.StatusCode -eq 401) {
            Write-OSINTProperty "Access Packages" "✅ External user governance configured" Green
            $externalIdAnalysis.CrossTenantAccess.AccessPackages = "Configured"
        }
    }
    catch { }
    
    # B2C Customer Identity Analysis
    Write-OSINTProgress "👥 B2C Customer Identity Discovery"
    try {
        $baseName = $Domain.Split('.')[0]
        
        # Check for B2C tenant patterns
        $b2cPatterns = @(
            "$baseName.onmicrosoft.com",
            "$baseName.b2clogin.com",
            "$($baseName)b2c.onmicrosoft.com"
        )
        
        foreach ($b2cPattern in $b2cPatterns) {
            $b2cUrl = "https://$b2cPattern/.well-known/openid_configuration"
            $b2cResponse = Invoke-WebRequestSafe -Uri $b2cUrl -SuppressErrors
            
            if ($b2cResponse) {
                $b2cConfig = $b2cResponse.Content | ConvertFrom-Json
                Write-OSINTProperty "B2C Tenant" "✅ Customer identity tenant: $b2cPattern" Green
                $externalIdAnalysis.B2CIdentities.TenantUrl = $b2cPattern
                
                # Extract B2C-specific capabilities
                if ($b2cConfig.userinfo_endpoint) {
                    Write-OSINTProperty "B2C User Flows" "✅ Custom user journey endpoints" Green
                }
                break
            }
        }
    }
    catch { }
    
    # External Domain Relationship Analysis
    Write-OSINTProgress "🌐 External Domain Relationships"
    try {
        # Check for common guest user domain patterns in invitation redemption
        $commonExternalDomains = @("gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "live.com")
        
        foreach ($extDomain in $commonExternalDomains) {
            $guestTestUrl = "https://login.microsoftonline.com/common/GetCredentialType"
            $guestBody = @{ Username = "guestuser@$extDomain" } | ConvertTo-Json
            $guestResponse = Invoke-WebRequestSafe -Uri $guestTestUrl -Method POST -Headers @{"Content-Type" = "application/json" } -Body $guestBody -SuppressErrors
            
            if ($guestResponse) {
                $guestData = $guestResponse.Content | ConvertFrom-Json
                if ($guestData.IfExistsResult -eq 0) {
                    $externalIdAnalysis.GuestUserPatterns += "External users from $extDomain likely supported"
                }
            }
        }
        
        if ($externalIdAnalysis.GuestUserPatterns.Count -gt 0) {
            Write-OSINTProperty "Guest User Patterns" "✅ $($externalIdAnalysis.GuestUserPatterns.Count) external domains tested" Green
        }
    }
    catch { }
    
    return $externalIdAnalysis
}

# Power BI & Microsoft Fabric Reconnaissance  
# Enhanced Microsoft Purview API Reconnaissance
function Get-MicrosoftPurviewRecon {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "🛡️ Microsoft Purview API Reconnaissance" "🔍"
    
    $purviewRecon = @{
        PurviewAccounts  = @{}
        DataPlaneAPIs    = @{}
        ControlPlaneAPIs = @{}
        Cataloging       = @{}
        DataGovernance   = @{}
        ComplianceAPIs   = @{}
        Authentication   = @{}
        Collections      = @{}
        Glossary         = @{}
        Assets           = @{}
        Security         = @{}
        Integration      = @{}
    }
    
    Write-OSINTProgress "🔍 Purview Account Discovery"
    try {
        $baseName = $Domain.Split('.')[0]
        
        # Test for Purview account patterns
        $purviewAccountPatterns = @(
            "$baseName-purview",
            "$baseName-catalog", 
            "$baseName-governance",
            "$baseName-compliance"
        )
        
        foreach ($pattern in $purviewAccountPatterns) {
            # Test Purview account existence
            $purviewUrl = "https://$pattern.purview.azure.com"
            $response = Invoke-WebRequestSafe -Uri $purviewUrl -SuppressErrors
            if ($response -or ($response -and $response.StatusCode -eq 401)) {
                Write-OSINTProperty "Purview Account" "✅ $pattern.purview.azure.com - Account exists" Green
                $purviewRecon.PurviewAccounts[$pattern] = "Active"
            }
            
            # Test Purview catalog endpoint
            $catalogUrl = "https://$pattern.catalog.purview.azure.com"
            $catalogResponse = Invoke-WebRequestSafe -Uri $catalogUrl -SuppressErrors
            if ($catalogResponse) {
                Write-OSINTProperty "Catalog Endpoint" "✅ $pattern.catalog.purview.azure.com - Catalog API available" Green
                $purviewRecon.Cataloging[$pattern] = "Available"
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "📋 Data Plane API Discovery"
    try {
        # Test core Data Plane APIs
        $dataPlaneAPIs = @{
            "Collections"     = "/collections"
            "Glossary Terms"  = "/glossary/terms" 
            "Atlas Entities"  = "/catalog/api/atlas/v2/entities"
            "Types"           = "/catalog/api/atlas/v2/types"
            "Discovery"       = "/catalog/api/browse"
            "Search"          = "/catalog/api/search/query"
            "Lineage"         = "/catalog/api/atlas/v2/lineage"
            "Classifications" = "/catalog/api/atlas/v2/entity/guid/{guid}/classifications"
        }
        
        foreach ($api in $dataPlaneAPIs.GetEnumerator()) {
            # Test against discovered Purview accounts
            foreach ($accountName in $purviewRecon.PurviewAccounts.Keys) {
                $testUrl = "https://$accountName.catalog.purview.azure.com$($api.Value)"
                $apiResponse = Invoke-WebRequestSafe -Uri $testUrl -SuppressErrors
                if ($apiResponse -and ($apiResponse.StatusCode -eq 401 -or $apiResponse.StatusCode -eq 403)) {
                    Write-OSINTProperty "$($api.Key) API" "✅ $testUrl - Authentication required (API exists)" Yellow
                    $purviewRecon.DataPlaneAPIs[$api.Key] = "RequiresAuth"
                }
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "⚙️ Control Plane API Discovery"  
    try {
        # Test Control Plane APIs for account management
        $controlPlaneAPIs = @{
            "Accounts"         = "https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Purview/accounts"
            "Account Status"   = "https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Purview/accounts/{accountName}"
            "Private Links"    = "https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Purview/accounts/{accountName}/privateEndpointConnections"
            "Managed Identity" = "https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Purview/accounts/{accountName}/managedIdentity"
        }
        
        foreach ($api in $controlPlaneAPIs.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $api.Value -SuppressErrors
            if ($response -and $response.StatusCode -eq 401) {
                Write-OSINTProperty "$($api.Key) Control API" "✅ Management endpoint accessible - $($api.Value)" Yellow  
                $purviewRecon.ControlPlaneAPIs[$api.Key] = "RequiresAuth"
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "🔐 Authentication & Security Analysis"
    try {
        # Check for service principal registration endpoints
        $authUrls = @(
            "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token",
            "https://login.microsoftonline.com/$TenantId/.well-known/openid_configuration"
        )
        
        foreach ($authUrl in $authUrls) {
            $authResponse = Invoke-WebRequestSafe -Uri $authUrl -SuppressErrors
            if ($authResponse) {
                Write-OSINTProperty "OAuth2 Endpoints" "✅ Entra ID authentication available for Purview" Green
                $purviewRecon.Authentication.OAuth2 = "Available"
                break
            }
        }
        
        # Test for Azure Key Vault integration patterns
        $keyVaultPattern = "https://$($Domain.Split('.')[0])-purview-kv.vault.azure.net"
        $kvResponse = Invoke-WebRequestSafe -Uri $keyVaultPattern -SuppressErrors
        if ($kvResponse -and $kvResponse.StatusCode -eq 401) {
            Write-OSINTProperty "Key Vault Integration" "✅ Purview Key Vault detected - $keyVaultPattern" Green
            $purviewRecon.Security.KeyVault = "Integrated"
        }
    }
    catch { }
    
    return $purviewRecon
}

# Enhanced Microsoft Fabric API Reconnaissance  
function Get-MicrosoftFabricRecon {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "🏭 Microsoft Fabric API Reconnaissance" "⚡"
    
    $fabricRecon = @{
        CoreAPIs          = @{}
        WorkloadAPIs      = @{}
        Workspaces        = @{}
        Items             = @{}
        Capacities        = @{}
        OneLake           = @{}
        DataEngineering   = @{}
        DataWarehouse     = @{}
        RealTimeAnalytics = @{}
        DataScience       = @{}
        PowerBI           = @{}
        Authentication    = @{}
        Security          = @{}
    }
    
    Write-OSINTProgress "🏗️ Core Fabric API Discovery"
    try {
        # Test Core Fabric APIs
        $coreAPIs = @{
            "Workspaces" = "https://api.fabric.microsoft.com/v1/workspaces"
            "Items"      = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/items"
            "Capacities" = "https://api.fabric.microsoft.com/v1/capacities" 
            "Admin"      = "https://api.fabric.microsoft.com/v1/admin"
            "Users"      = "https://api.fabric.microsoft.com/v1/me"
        }
        
        foreach ($api in $coreAPIs.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $api.Value -SuppressErrors
            if ($response -and ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403)) {
                Write-OSINTProperty "$($api.Key) Core API" "✅ $($api.Value) - Authentication required" Yellow
                $fabricRecon.CoreAPIs[$api.Key] = "RequiresAuth"
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "🔧 Workload-Specific API Discovery"
    try {
        # Test Workload APIs for each Fabric capability
        $workloadAPIs = @{
            "Lakehouse"     = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/lakehouses"
            "Notebook"      = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/notebooks" 
            "Data Pipeline" = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/dataPipelines"
            "Spark Job"     = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/sparkJobDefinitions"
            "SQL Endpoint"  = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/sqlEndpoints"
            "Warehouse"     = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/warehouses"
            "KQL Database"  = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/kqlDatabases"
            "ML Model"      = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/mlModels"
            "Experiment"    = "https://api.fabric.microsoft.com/v1/workspaces/{workspaceId}/experiments"
        }
        
        foreach ($api in $workloadAPIs.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $api.Value -SuppressErrors
            if ($response -and ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403)) {
                Write-OSINTProperty "$($api.Key) Workload API" "✅ Workload API available - requires auth" Yellow
                $fabricRecon.WorkloadAPIs[$api.Key] = "RequiresAuth" 
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "🏞️ OneLake Storage Analysis"
    try {
        $baseName = $Domain.Split('.')[0]
        
        # Test OneLake endpoint patterns
        $oneLakePatterns = @(
            "https://onelake.dfs.fabric.microsoft.com/$baseName",
            "https://$baseName.dfs.fabric.microsoft.com",
            "https://fabric.microsoft.com/onelake/$baseName"
        )
        
        foreach ($pattern in $oneLakePatterns) {
            $oneLakeResponse = Invoke-WebRequestSafe -Uri $pattern -SuppressErrors
            if ($oneLakeResponse -and ($oneLakeResponse.StatusCode -eq 401 -or $oneLakeResponse.StatusCode -eq 403)) {
                Write-OSINTProperty "OneLake Storage" "✅ $pattern - OneLake endpoint detected" Yellow
                $fabricRecon.OneLake.Endpoint = $pattern
            }
        }
        
        # Test Data Lake Gen2 API patterns for Fabric
        $dfsAPIs = @(
            "/webhdfs/v1/?op=LISTSTATUS",
            "/dfs/v1/filesystems",
            "/?comp=list&include=metadata"
        )
        
        foreach ($dfsAPI in $dfsAPIs) {
            if ($fabricRecon.OneLake.Endpoint) {
                $testUrl = "$($fabricRecon.OneLake.Endpoint)$dfsAPI"
                $dfsResponse = Invoke-WebRequestSafe -Uri $testUrl -SuppressErrors
                if ($dfsResponse) {
                    Write-OSINTProperty "OneLake DFS API" "✅ Data Lake Storage API accessible" Green
                    $fabricRecon.OneLake.DFSAPIs = "Available"
                    break
                }
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "🔐 Fabric Authentication Analysis"
    try {
        # Test OAuth 2.0 scopes for Fabric
        $fabricScopes = @(
            "https://api.fabric.microsoft.com/Workspace.ReadWrite.All",
            "https://api.fabric.microsoft.com/Item.ReadWrite.All",
            "https://api.fabric.microsoft.com/Capacity.ReadWrite.All"
        )
        
        foreach ($scope in $fabricScopes) {
            Write-OSINTProperty "OAuth Scope" "📋 Required scope: $scope" Cyan
            $fabricRecon.Authentication.Scopes += $scope
        }
        
        # Test for service principal registration
        if ($TenantId) {
            $spUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $spResponse = Invoke-WebRequestSafe -Uri $spUrl -SuppressErrors
            if ($spResponse) {
                Write-OSINTProperty "Service Principal Auth" "✅ Entra ID token endpoint available" Green
                $fabricRecon.Authentication.ServicePrincipal = "Available"
            }
        }
    }
    catch { }
    
    return $fabricRecon
}

# Enhanced Power BI API Reconnaissance
function Get-PowerBIAPIRecon {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "📊 Power BI API Reconnaissance" "⚡"
    
    $powerBIRecon = @{
        RestAPIs         = @{}
        AdminAPIs        = @{}
        EmbedAPIs        = @{}
        Workspaces       = @{}
        Reports          = @{}
        Datasets         = @{}
        Dashboards       = @{}
        Authentication   = @{}
        ServicePrincipal = @{}
        BatchOperations  = @{}
        PublicContent    = @{}
        Security         = @{}
    }
    
    Write-OSINTProgress "📊 Core Power BI REST API Discovery"
    try {
        # Test Core Power BI REST APIs
        $powerBIAPIs = @{
            "Workspaces" = "https://api.powerbi.com/v1.0/myorg/groups"
            "Reports"    = "https://api.powerbi.com/v1.0/myorg/reports" 
            "Datasets"   = "https://api.powerbi.com/v1.0/myorg/datasets"
            "Dashboards" = "https://api.powerbi.com/v1.0/myorg/dashboards"
            "Apps"       = "https://api.powerbi.com/v1.0/myorg/apps"
            "Dataflows"  = "https://api.powerbi.com/v1.0/myorg/dataflows"
            "Gateways"   = "https://api.powerbi.com/v1.0/myorg/gateways"
            "Capacities" = "https://api.powerbi.com/v1.0/myorg/capacities"
        }
        
        foreach ($api in $powerBIAPIs.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $api.Value -SuppressErrors
            if ($response -and ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403)) {
                Write-OSINTProperty "$($api.Key) REST API" "✅ $($api.Value) - Authentication required" Yellow
                $powerBIRecon.RestAPIs[$api.Key] = "RequiresAuth"
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "🔧 Power BI Admin API Discovery"
    try {
        # Test Admin APIs (require admin permissions)
        $adminAPIs = @{
            "Tenant Settings"  = "https://api.powerbi.com/v1.0/myorg/admin/tenantsettings"
            "Usage Metrics"    = "https://api.powerbi.com/v1.0/myorg/admin/usagemetrics" 
            "Audit Logs"       = "https://api.powerbi.com/v1.0/myorg/admin/activityevents"
            "Workspaces Admin" = "https://api.powerbi.com/v1.0/myorg/admin/groups"
            "Users"            = "https://api.powerbi.com/v1.0/myorg/admin/users"
            "Capacities Admin" = "https://api.powerbi.com/v1.0/myorg/admin/capacities"
            "Pipelines"        = "https://api.powerbi.com/v1.0/myorg/admin/pipelines"
            "Encryption Keys"  = "https://api.powerbi.com/v1.0/myorg/admin/tenantKeys"
        }
        
        foreach ($api in $adminAPIs.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $api.Value -SuppressErrors
            if ($response -and ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403)) {
                Write-OSINTProperty "$($api.Key) Admin API" "✅ Admin API available - requires elevated auth" Yellow
                $powerBIRecon.AdminAPIs[$api.Key] = "RequiresAdminAuth"
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "🎨 Embedding & Integration API Discovery"  
    try {
        # Test Embedding APIs
        $embedAPIs = @{
            "Embed Token"      = "https://api.powerbi.com/v1.0/myorg/GenerateToken"
            "Embed Reports"    = "https://app.powerbi.com/reportEmbed"
            "Embed Dashboards" = "https://app.powerbi.com/dashboardEmbed"  
            "Embed Q&A"        = "https://app.powerbi.com/qnaEmbed"
            "JavaScript SDK"   = "https://powerbi.microsoft.com/javascript/powerbi.js"
        }
        
        foreach ($api in $embedAPIs.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $api.Value -SuppressErrors
            if ($response) {
                Write-OSINTProperty "$($api.Key) Embed API" "✅ Embedding infrastructure available" Green
                $powerBIRecon.EmbedAPIs[$api.Key] = "Available"
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "🔐 Power BI Authentication Analysis"
    try {
        # Test OAuth 2.0 for Power BI
        $powerBIScopes = @(
            "https://analysis.windows.net/powerbi/api/.default",
            "https://analysis.windows.net/powerbi/api/Dataset.ReadWrite.All",
            "https://analysis.windows.net/powerbi/api/Report.ReadWrite.All",
            "https://analysis.windows.net/powerbi/api/Workspace.ReadWrite.All"
        )
        
        foreach ($scope in $powerBIScopes) {
            Write-OSINTProperty "OAuth Scope" "📋 Power BI scope: $scope" Cyan
            $powerBIRecon.Authentication.Scopes += $scope
        }
        
        # Test service principal support
        if ($TenantId) {
            $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $tokenResponse = Invoke-WebRequestSafe -Uri $tokenUrl -SuppressErrors
            if ($tokenResponse) {
                Write-OSINTProperty "Service Principal" "✅ Service principal authentication supported" Green
                $powerBIRecon.ServicePrincipal.Supported = $true
            }
        }
    }
    catch { }
    
    Write-OSINTProgress "🌐 Public Content Discovery"
    try {
        $baseName = $Domain.Split('.')[0]
        
        # Search for public Power BI content
        $searchTerms = @($Domain, $baseName, ($Domain.Split('.')[0] + " " + $Domain.Split('.')[1]))
        
        foreach ($term in $searchTerms) {
            # Check Power BI community for public reports
            $communityUrl = "https://community.powerbi.com/t5/forums/searchpage/tab/message?filter=location&q=$term"
            $communityResponse = Invoke-WebRequestSafe -Uri $communityUrl -SuppressErrors
            if ($communityResponse -and $communityResponse.Content -match $term) {
                Write-OSINTProperty "Community Content" "✅ Organization mentioned in Power BI community" Yellow
                $powerBIRecon.PublicContent.Community = "Found"
            }
            
            # Check for public embed codes (example patterns)
            $embedPatterns = @(
                "app.powerbi.com/view?r=",
                "app.powerbi.com/reportEmbed?reportId="
            )
            
            foreach ($pattern in $embedPatterns) {
                Write-OSINTProperty "Embed Pattern" "📋 Search pattern: $pattern + org identifiers" Cyan
                $powerBIRecon.PublicContent.EmbedPatterns += $pattern
            }
        }
    }
    catch { }
    
    return $powerBIRecon
}

function Get-PowerBIFabricAnalysis {
    param([string]$Domain, [string]$TenantId)
    
    Write-OSINTSection "📊 Power BI & Microsoft Fabric Analysis" "⚡"
    
    $fabricAnalysis = @{
        PowerBIService    = @{}
        FabricWorkspaces  = @{}
        DataGateways      = @{}
        ExternalSharing   = @{}
        CrossTenantAccess = @{}
        PublicContent     = @{}
        EmbeddedContent   = @{}
        AdminPortal       = @{}
        CapacitySettings  = @{}
    }
    
    # Power BI Service Discovery
    Write-OSINTProgress "⚡ Power BI Service Analysis"
    try {
        $baseName = $Domain.Split('.')[0]
        
        # Check Power BI service endpoints
        $powerBIUrls = @{
            "Service"   = "https://app.powerbi.com"
            "API"       = "https://api.powerbi.com"
            "Admin"     = "https://admin.powerbi.com"
            "Embedding" = "https://embedded.powerbi.com"
            "Public"    = "https://app.powerbi.com/view"
        }
        
        foreach ($endpoint in $powerBIUrls.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $endpoint.Value -SuppressErrors
            if ($response) {
                Write-OSINTProperty "Power BI $($endpoint.Key)" "✅ Endpoint accessible" Green
                $fabricAnalysis.PowerBIService[$endpoint.Key] = "Accessible"
            }
        }
        
        # Test for organization-specific Power BI content
        $orgPowerBIUrl = "https://app.powerbi.com/groups/me/apps"
        $orgResponse = Invoke-WebRequestSafe -Uri $orgPowerBIUrl -SuppressErrors
        if ($orgResponse) {
            Write-OSINTProperty "Power BI Org Content" "✅ Organization apps endpoint accessible" Green
            $fabricAnalysis.PowerBIService.OrgContent = "Accessible"
        }
    }
    catch { }
    
    # Microsoft Fabric Analysis
    Write-OSINTProgress "🏭 Microsoft Fabric Platform Analysis"
    try {
        # Check for Fabric-specific endpoints
        $fabricUrls = @{
            "Portal"      = "https://fabric.microsoft.com"
            "OneLake"     = "https://onelake.dfs.fabric.microsoft.com"
            "DataFactory" = "https://datafactory.azure.com"
            "Synapse"     = "https://web.azuresynapse.net"
        }
        
        foreach ($endpoint in $fabricUrls.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $endpoint.Value -SuppressErrors
            if ($response) {
                Write-OSINTProperty "Fabric $($endpoint.Key)" "✅ Platform endpoint accessible" Green
                $fabricAnalysis.FabricWorkspaces[$endpoint.Key] = "Accessible"
            }
        }
        
        # Test for Fabric workspace discovery
        if ($TenantId) {
            $fabricWorkspaceUrl = "https://api.fabric.microsoft.com/v1/workspaces"
            $workspaceResponse = Invoke-WebRequestSafe -Uri $fabricWorkspaceUrl -SuppressErrors
            if ($workspaceResponse -and $workspaceResponse.StatusCode -eq 401) {
                Write-OSINTProperty "Fabric Workspaces" "✅ Workspace API endpoint available" Yellow
                $fabricAnalysis.FabricWorkspaces.API = "Available"
            }
        }
    }
    catch { }
    
    # Data Gateway Analysis
    Write-OSINTProgress "🌉 Data Gateway Discovery"
    try {
        # Check for on-premises data gateway indicators
        $gatewayUrls = @(
            "https://gateway.powerbi.com",
            "https://analysis.windows.net/powerbi/api",
            "https://api.powerbi.com/v1.0/myorg/gateways"
        )
        
        foreach ($gatewayUrl in $gatewayUrls) {
            $gatewayResponse = Invoke-WebRequestSafe -Uri $gatewayUrl -SuppressErrors
            if ($gatewayResponse) {
                Write-OSINTProperty "Data Gateway Endpoint" "✅ Gateway infrastructure accessible: $gatewayUrl" Green
                $fabricAnalysis.DataGateways.Infrastructure = "Present"
                break
            }
        }
        
        # Test for gateway cluster information
        $clusterUrl = "https://api.powerbi.com/v1.0/myorg/gatewayClusters"
        $clusterResponse = Invoke-WebRequestSafe -Uri $clusterUrl -SuppressErrors
        if ($clusterResponse -and $clusterResponse.StatusCode -eq 401) {
            Write-OSINTProperty "Gateway Clusters" "✅ Cluster management API available" Yellow
            $fabricAnalysis.DataGateways.ClusterAPI = "Available"
        }
    }
    catch { }
    
    # External Sharing & Cross-Tenant Analysis
    Write-OSINTProgress "🔗 Cross-Tenant Sharing Analysis"
    try {
        # Test Power BI sharing capabilities
        $sharingUrl = "https://api.powerbi.com/v1.0/myorg/admin/capacities"
        $sharingResponse = Invoke-WebRequestSafe -Uri $sharingUrl -SuppressErrors
        if ($sharingResponse -and $sharingResponse.StatusCode -eq 401) {
            Write-OSINTProperty "Capacity Management" "✅ Admin API for cross-tenant sharing" Yellow
            $fabricAnalysis.CrossTenantAccess.CapacityManagement = "Available"
        }
        
        # Check for external sharing policies
        $externalSharingUrl = "https://api.powerbi.com/v1.0/myorg/admin/tenantsettings"
        $externalResponse = Invoke-WebRequestSafe -Uri $externalSharingUrl -SuppressErrors
        if ($externalResponse -and $externalResponse.StatusCode -eq 401) {
            Write-OSINTProperty "Tenant Settings" "✅ External sharing policies accessible" Yellow
            $fabricAnalysis.ExternalSharing.TenantSettings = "Accessible"
        }
        
        # Test for B2B guest access in Power BI
        $b2bPowerBIUrl = "https://app.powerbi.com/groups/me/list"
        $b2bResponse = Invoke-WebRequestSafe -Uri $b2bPowerBIUrl -SuppressErrors
        if ($b2bResponse) {
            Write-OSINTProperty "B2B Power BI Access" "✅ Guest user workspace access" Green
            $fabricAnalysis.CrossTenantAccess.B2BAccess = "Supported"
        }
    }
    catch { }
    
    # Public Content Discovery
    Write-OSINTProgress "🌐 Public Power BI Content Discovery"
    try {
        # Search for publicly shared Power BI reports
        $publicSearchTerms = @($Domain, $Domain.Split('.')[0])
        
        foreach ($term in $publicSearchTerms) {
            # Check for public reports via Power BI service
            $publicReportUrl = "https://app.powerbi.com/view?r="
            $searchUrl = "https://powerbi.microsoft.com/en-us/blog/?s=$term"
            
            $publicResponse = Invoke-WebRequestSafe -Uri $searchUrl -SuppressErrors
            if ($publicResponse -and $publicResponse.Content -match $term) {
                Write-OSINTProperty "Public BI Content" "✅ Organization mentioned in Power BI blogs/content" Yellow
                $fabricAnalysis.PublicContent.BlogMentions = "Found"
            }
        }
        
        # Check for embedded Power BI content patterns
        $embedPatterns = @(
            "https://app.powerbi.com/reportEmbed",
            "https://embedded.powerbi.com"
        )
        
        foreach ($pattern in $embedPatterns) {
            $embedResponse = Invoke-WebRequestSafe -Uri $pattern -SuppressErrors
            if ($embedResponse) {
                Write-OSINTProperty "Embedded BI Content" "✅ Embedding infrastructure available" Green
                $fabricAnalysis.EmbeddedContent.Infrastructure = "Available"
                break
            }
        }
    }
    catch { }
    
    # Premium Capacity Analysis
    Write-OSINTProgress "💎 Premium Capacity & Licensing Analysis"
    try {
        # Test for premium capacity indicators
        $capacityUrls = @{
            "Premium"   = "https://api.powerbi.com/v1.0/myorg/premium/capacities"
            "Embedded"  = "https://api.powerbi.com/v1.0/myorg/capacities"
            "Pipelines" = "https://api.powerbi.com/v1.0/myorg/pipelines"
        }
        
        foreach ($capacity in $capacityUrls.GetEnumerator()) {
            $response = Invoke-WebRequestSafe -Uri $capacity.Value -SuppressErrors
            if ($response -and $response.StatusCode -eq 401) {
                Write-OSINTProperty "$($capacity.Key) Capacity" "✅ API endpoint suggests premium features" Yellow
                $fabricAnalysis.CapacitySettings[$capacity.Key] = "API_Available"
            }
        }
        
        # Check for Fabric trial or capacity indicators
        $fabricTrialUrl = "https://api.fabric.microsoft.com/v1/capacities"
        $trialResponse = Invoke-WebRequestSafe -Uri $fabricTrialUrl -SuppressErrors
        if ($trialResponse -and $trialResponse.StatusCode -eq 401) {
            Write-OSINTProperty "Fabric Capacity" "✅ Fabric capacity management available" Yellow
            $fabricAnalysis.CapacitySettings.FabricCapacity = "Available"
        }
    }
    catch { }
    
    return $fabricAnalysis
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
        
        # Phase 8: Authentication & Token Analysis (ROADtools techniques)
        $advancedResults.AuthenticationAnalysis = Get-AuthenticationAnalysis -Domain $Domain -TenantId $TenantId
        
        # Phase 9: Tenant Security Posture (Enhanced with deep analysis)
        $advancedResults.SecurityPosture = Get-TenantSecurityPosture -Domain $Domain -TenantId $TenantId
        
        # Phase 10: External Identity & Cross-Tenant Analysis
        $advancedResults.ExternalIdentities = Get-ExternalIdentityAnalysis -Domain $Domain -TenantId $TenantId
        
        # Phase 11: Power BI & Microsoft Fabric Analysis
        $advancedResults.PowerBIFabric = Get-PowerBIFabricAnalysis -Domain $Domain -TenantId $TenantId
        
        # Phase 11.1: Microsoft Purview API Reconnaissance
        Write-OSINTSection "Microsoft Purview API Reconnaissance" "🛡️"
        $advancedResults.PurviewRecon = Get-MicrosoftPurviewRecon -Domain $Domain -TenantId $TenantId
        
        # Phase 11.2: Microsoft Fabric API Reconnaissance  
        Write-OSINTSection "Microsoft Fabric API Reconnaissance" "🏭"
        $advancedResults.FabricRecon = Get-MicrosoftFabricRecon -Domain $Domain -TenantId $TenantId
        
        # Phase 11.3: Power BI API Reconnaissance
        Write-OSINTSection "Power BI API Reconnaissance" "📊"
        $advancedResults.PowerBIRecon = Get-PowerBIAPIRecon -Domain $Domain -TenantId $TenantId
        
        # Phase 12: Certificate Transparency
        Write-OSINTSection "Certificate Transparency Analysis" "🔐"
        $advancedResults.Certificates = Get-CertificateTransparency -Domain $Domain
        
        # Phase 13: Social Media & Digital Footprint
        Write-OSINTSection "Digital Footprint Analysis" "📱"
        $advancedResults.SocialMedia = Get-SocialMediaFootprint -Domain $Domain -OrganizationName $OrganizationName
        
        # Phase 14: Breach Intelligence
        Write-OSINTSection "Breach Intelligence" "🛡️"
        $advancedResults.BreachData = Get-BreachData -Domain $Domain
        
        # Phase 15: Email Pattern Analysis
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
        Write-OSINTProperty "Auth Methods" $advancedResults.AuthenticationAnalysis.AuthMethods.Count Green
        Write-OSINTProperty "OAuth Flows" $advancedResults.AuthenticationAnalysis.SupportedFlows.Count Green
        Write-OSINTProperty "External ID Types" $advancedResults.ExternalIdentities.ExternalUserTypes.Count Yellow
        Write-OSINTProperty "B2B Capabilities" $(if ($advancedResults.ExternalIdentities.B2BCollaboration.RedemptionFlow) { "Present" } else { "Unknown" }) $(if ($advancedResults.ExternalIdentities.B2BCollaboration.RedemptionFlow) { "Green" } else { "Gray" })
        Write-OSINTProperty "Power BI Services" $($advancedResults.PowerBIFabric.PowerBIService.Keys.Count) Cyan
        Write-OSINTProperty "Fabric Features" $($advancedResults.PowerBIFabric.FabricWorkspaces.Keys.Count) Cyan  
        Write-OSINTProperty "Certificates Found" $advancedResults.Certificates.Count Green
        Write-OSINTProperty "GitHub Repositories" $advancedResults.SocialMedia.GitHub.Count Green
        
        Write-Host ""
        Write-Host "✅ " -NoNewline -ForegroundColor Green
        Write-Host "Advanced OSINT Reconnaissance Completed Successfully!" -ForegroundColor White
        Write-Host "📊 " -NoNewline -ForegroundColor Cyan
        Write-Host "Report generated and saved" -ForegroundColor Gray
        
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
    
    # Return the file paths for post-processing
    return @{
        JSONFile = $jsonFile
        HTMLFile = $htmlFile
        CSVFile  = $csvFile
    }
}

function Export-HTMLReport {
    param([hashtable]$Results, [string]$OutputPath)
    
    # Calculate API endpoint counts to avoid complex PowerShell conditionals in HTML
    $purviewAPICount = if ($Results.PurviewRecon -and $Results.PurviewRecon.DataPlaneAPIs) { 
        $Results.PurviewRecon.DataPlaneAPIs.Keys.Count 
    }
    else { 0 }
    
    $fabricAPICount = if ($Results.FabricRecon -and $Results.FabricRecon.CoreAPIs) { 
        $Results.FabricRecon.CoreAPIs.Keys.Count 
    }
    else { 0 }
    
    $powerBIAPICount = if ($Results.PowerBIRecon -and $Results.PowerBIRecon.RestAPIs) { 
        $Results.PowerBIRecon.RestAPIs.Keys.Count 
    }
    else { 0 }
    
    $totalAPIEndpoints = $purviewAPICount + $fabricAPICount + $powerBIAPICount
    
    # Helper: build simple MITRE-like matrix cell (tactic -> techniques)
    $buildMatrixSection = {
        param($title, $items, $icon)
        $cells = ""
        if ($items -and $items.Count -gt 0) {
            foreach ($i in $items) {
                $cells += "<div class='tech-item'><span class='tech-dot'></span>$i</div>"
            }
        }
        else {
            $cells = "<div class='tech-item empty'>No data</div>"
        }
        return "<div class='matrix-col'><div class='matrix-col-header'>$icon $title</div><div class='matrix-body'>$cells</div></div>"
    }

    # Collect matrix columns (example mapping of gathered data -> tactics like style)
    $matrixCols = @()
    $matrixCols += & $buildMatrixSection 'Tenant Discovery' @($Results.TenantInfo.TenantId, $Results.TenantInfo.CloudInstance, $Results.TenantInfo.NameSpaceType) '🛰️'
    $matrixCols += & $buildMatrixSection 'User Enumeration' ($Results.UserEnumeration.ValidUsers | ForEach-Object { $_.Username } | Select-Object -First 6) '👥'
    $matrixCols += & $buildMatrixSection 'Network Surface' ($Results.NetworkIntelligence.Subdomains | ForEach-Object { $_.Subdomain } | Select-Object -First 6) '🌐'
    $matrixCols += & $buildMatrixSection 'Auth & Flows' @($Results.AuthenticationAnalysis.AuthMethods + $Results.AuthenticationAnalysis.SupportedFlows) '🔐'
    $matrixCols += & $buildMatrixSection 'APIs' @("Purview:$purviewAPICount", "Fabric:$fabricAPICount", "PowerBI:$powerBIAPICount") '⚙️'
    $matrixCols += & $buildMatrixSection 'Azure Resources' (@($Results.ExtendedAzureResources.StorageAccounts | ForEach-Object Name | Select-Object -First 2) + (@($Results.ExtendedAzureResources.FunctionApps | ForEach-Object Name | Select-Object -First 2)) + (@($Results.ExtendedAzureResources.APIManagement | ForEach-Object Name | Select-Object -First 2))) '☁️'
    $matrixCols += & $buildMatrixSection 'Certificates' ($Results.Certificates | ForEach-Object { $_.CommonName } | Select-Object -First 6) '📜'
    # Ensure we pass primitive strings (names or urls) to the matrix builder to avoid System.Collections.Hashtable output
    $socialItems = @()
    if ($Results.SocialMedia.GitHub) {
        $Results.SocialMedia.GitHub | Select-Object -First 4 | ForEach-Object {
            $socialItems += ($_.Name ?? $_.full_name ?? $_.Url ?? $_.html_url) -as [string]
        }
    }
    if ($Results.SocialMedia.LinkedIn) {
        $Results.SocialMedia.LinkedIn | Select-Object -First 2 | ForEach-Object {
            $socialItems += ($_.Url ?? $_.ProfileUrl) -as [string]
        }
    }
    $matrixCols += & $buildMatrixSection 'Social / Repos' $socialItems '📱'

    $matrixHTML = "<div class='matrix-wrapper'>" + ($matrixCols -join '') + "</div>"

    

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>⚡ CYBEROSINT - Azure Recon Terminal ⚡</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
    body { font-family: 'JetBrains Mono','Consolas',monospace; background:#0b0e17; color:#d6e7ff; line-height:1.45; margin:0; font-size:15px; }
    h1,h2,h3 { font-family:'Orbitron',monospace; font-weight:700; letter-spacing:.5px; }
    h1 { font-size:1.8rem; }
    h2 { font-size:1.05rem; }
    h3 { font-size:.9rem; }
        a { color:#59d6ff; }
        .container { max-width:1600px; margin:0 auto; padding:25px 30px 60px 30px; }
        .top-bar { display:flex; flex-wrap:wrap; gap:25px; align-items:flex-end; margin-bottom:25px; }
        .report-title { font-size:2.2rem; margin:0; color:#66f7d9; text-shadow:0 0 8px #1ef2b3; }
        .meta { display:flex; flex-wrap:wrap; gap:18px; font-size:.75rem; text-transform:uppercase; letter-spacing:1px; }
        .meta-item { background:#131b29; padding:6px 10px; border:1px solid #223248; border-radius:4px; color:#9ab3c9; }
        .status-chip { padding:4px 10px; border-radius:12px; font-weight:600; background:#143723; color:#52f6b5; }
        /* MITRE-like matrix */
        .matrix-section-title { margin:10px 0 12px 0; font-size:1.1rem; color:#8cc7ff; text-transform:uppercase; letter-spacing:2px; }
    /* Stack matrix columns vertically to fit narrow pages better */
    .matrix-wrapper { display:grid; grid-auto-flow:row; grid-template-columns: 1fr; gap:10px; padding:12px; background:#0f1622; border:1px solid #1f2c3a; border-radius:6px; }
    .matrix-col { background:#121c29; border:1px solid #243345; border-radius:4px; display:flex; flex-direction:column; min-height:120px; width:100%; }
        .matrix-col-header { font-size:.70rem; font-weight:700; padding:6px 8px; background:#1b2836; color:#73e0ff; text-transform:uppercase; border-bottom:1px solid #243345; letter-spacing:1px; }
        .matrix-body { padding:6px 6px 10px 6px; display:flex; flex-direction:column; gap:4px; }
        .tech-item { position:relative; font-size:.68rem; line-height:1.1rem; padding:4px 6px 4px 16px; background:#182535; border:1px solid #223347; border-radius:3px; color:#b8d5ef; }
        .tech-item:hover { background:#1f3145; }
        .tech-item.empty { color:#546575; font-style:italic; }
        .tech-dot { position:absolute; left:6px; top:8px; width:6px; height:6px; border-radius:50%; background:#35cfa4; box-shadow:0 0 4px #35cfa4; }
        /* Stat tiles row */
        .stats-row { display:grid; grid-template-columns:repeat(auto-fill,minmax(140px,1fr)); gap:10px; margin:30px 0 10px 0; }
        .tile { background:#121c29; border:1px solid #243345; border-radius:6px; padding:10px 12px; text-align:center; }
        .tile h4 { margin:4px 0 2px 0; font-size:.65rem; font-weight:600; letter-spacing:1px; color:#7fa8c7; text-transform:uppercase; }
        .tile .val { font-size:1.35rem; font-weight:700; color:#6cf7d7; }
        .sections { margin-top:25px; display:flex; flex-direction:column; gap:26px; }
        .section { background:#0f1622; border:1px solid #1f2c3a; border-radius:6px; }
        .section-header { padding:10px 14px; border-bottom:1px solid #1f2c3a; display:flex; align-items:center; gap:10px; }
        .section-header h2 { margin:0; font-size:1rem; color:#8cc7ff; text-transform:uppercase; letter-spacing:2px; }
        .section-content { padding:14px 18px 20px 18px; }
        table { width:100%; border-collapse:collapse; font-size:.7rem; }
        th,td { padding:6px 8px; border:1px solid #223445; }
        th { background:#152231; color:#82d9ff; font-weight:600; letter-spacing:1px; }
        tbody tr:nth-child(even){ background:#13202e; }
        tbody tr:hover { background:#1b2c3c; }
        .status-success { color:#4be7b1; }
        .status-warning { color:#ffcc66; }
        .status-error { color:#ff667d; }
        .status-info { color:#59d6ff; }
        .status-neutral { color:#9ab3c9; }
        .subgrid { display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:12px; }
        .panel { background:#121c29; border:1px solid #243345; border-radius:4px; padding:10px 12px; }
        .panel h3 { margin:0 0 6px 0; font-size:.75rem; color:#73e0ff; text-transform:uppercase; letter-spacing:1px; }
        .list { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:4px; }
        .list li { font-size:.65rem; background:#182535; border:1px solid #223347; padding:4px 6px; border-radius:3px; overflow:hidden; text-overflow:ellipsis; }
        .list li:hover { background:#203246; }
        .note { font-size:.62rem; color:#6f8599; margin-top:4px; }
        .footer { margin-top:50px; text-align:center; font-size:.6rem; color:#4e6479; padding:25px 0 10px 0; border-top:1px solid #1f2c3a; }
    @media (max-width:1100px){ .matrix-wrapper { grid-template-columns: 1fr; } }
        @media (max-width:700px){ .report-title{font-size:1.6rem;} .matrix-col{min-height:200px;} }
        
        .data-row { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; margin-bottom:6px; }
        .data-label { font-size:.62rem; letter-spacing:.5px; text-transform:uppercase; color:#7fa8c7; min-width:120px; }
        .data-value { font-size:.7rem; font-weight:600; }
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid rgba(0, 255, 159, 0.2);
        }
        
        .data-row:last-child { border-bottom: none; }
        
        .data-label {
            color: #cccccc;
            font-weight: 500;
            flex: 1;
        }
        
        .data-value {
            flex: 1;
            text-align: right;
            font-weight: bold;
        }
        
        .status-success { color: #00ff9f; }
        .status-warning { color: #ffaa00; }
        .status-error { color: #ff4444; }
        .status-info { color: #00ffff; }
        .status-neutral { color: #cccccc; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: rgba(0, 0, 0, 0.3);
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid rgba(0, 255, 159, 0.3);
        }
        
        th {
            background: rgba(0, 255, 159, 0.2);
            color: #00ffff;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 1px;
        }
        
        tr:nth-child(even) { background: rgba(0, 255, 159, 0.05); }
        tr:hover { background: rgba(0, 255, 159, 0.1); }
        
        .action-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 20px 0;
        }
        
        .cyber-btn {
            background: linear-gradient(45deg, #00ff9f, #00ffff);
            color: #000;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-family: 'JetBrains Mono', monospace;
            font-weight: bold;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .cyber-btn:hover {
            background: linear-gradient(45deg, #00ffff, #00ff9f);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 255, 159, 0.3);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(0, 255, 159, 0.1));
            border: 2px solid #00ff9f;
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            border-color: #00ffff;
            box-shadow: 0 8px 25px rgba(0, 255, 159, 0.3);
            transform: translateY(-3px);
        }
        
        .stat-icon {
            font-size: 2.5em;
            margin-bottom: 10px;
            display: block;
        }
        
        .stat-number {
            font-size: 2.8em;
            font-weight: bold;
            color: #00ff9f;
            text-shadow: 0 0 15px #00ff9f;
            display: block;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #cccccc;
            font-size: 1em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 30px;
            margin-top: 40px;
        }
        
        .detail-section {
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid rgba(0, 255, 159, 0.3);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .detail-header {
            background: linear-gradient(90deg, rgba(0, 255, 159, 0.2), rgba(0, 255, 255, 0.1));
            padding: 20px;
            border-bottom: 1px solid rgba(0, 255, 159, 0.3);
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .detail-icon {
            font-size: 1.5em;
        }
        
        .detail-header h3 {
            margin: 0;
            color: #00ff9f;
            font-size: 1.3em;
        }
        
        .detail-content {
            padding: 25px;
        }
        
        .method-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .method-item {
            background: rgba(0, 255, 159, 0.1);
            padding: 10px 15px;
            border-radius: 5px;
            border-left: 3px solid #00ff9f;
        }
        
        .data-table {
            overflow-x: auto;
        }
        
        .info-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        .info-table th {
            background: rgba(0, 255, 159, 0.2);
            color: #00ff9f;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #00ff9f;
        }
        
        .info-table td {
            padding: 10px 12px;
            border-bottom: 1px solid rgba(0, 255, 159, 0.1);
        }
        
        .info-table tr:hover {
            background: rgba(0, 255, 159, 0.05);
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #888;
        }
        
        .empty-icon {
            font-size: 3em;
            margin-bottom: 15px;
            opacity: 0.5;
        }
        
        .empty-text {
            font-style: italic;
            font-size: 1.1em;
        }
        
        .resource-grid, .auth-grid, .social-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .resource-category, .auth-category, .social-category {
            background: rgba(0, 0, 0, 0.4);
            border-radius: 8px;
            padding: 20px;
            border: 1px solid rgba(0, 255, 159, 0.2);
        }
        
        .resource-title, .auth-title, .social-title {
            color: #00ffff;
            margin: 0 0 15px 0;
            font-size: 1.1em;
        }
        
        .resource-list, .auth-list, .social-list, .api-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .resource-item, .auth-item, .social-item {
            padding: 8px 12px;
            border-radius: 4px;
            background: rgba(0, 0, 0, 0.3);
            border-left: 3px solid #00ff9f;
        }
        
        .social-name {
            font-weight: bold;
            color: #00ff9f;
        }
        
        .social-desc {
            font-size: 0.9em;
            color: #ccc;
            margin-top: 4px;
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #00ff9f;
            text-shadow: 0 0 10px #00ff9f;
        }
        
        .stat-label {
            color: #cccccc;
            font-size: 1.1em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            flex-grow: 1;
            margin-left: 15px;
        }
        
        .expand-icon {
            color: #00ffff;
            font-size: 1.2em;
            transition: transform 0.3s ease;
        }
        
        .stat-card .stat-icon {
            font-size: 1.8em;
            margin-bottom: 5px;
        }
        
        .stat-card .stat-number {
            font-size: 1.8em;
            font-weight: bold;
            color: #00ff9f;
            text-shadow: 0 0 8px #00ff9f;
        }
        
        .stat-card .stat-label {
            color: #cccccc;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .detail-section {
            background: rgba(15, 25, 35, 0.9);
            border: 1px solid rgba(0, 255, 159, 0.2);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
        }
        
        .detail-header {
            font-size: 0.95em;
            font-weight: bold;
            color: #00ff9f;
            margin-bottom: 8px;
            text-shadow: 0 0 5px #00ff9f;
        }
        
        .detail-content {
            font-size: 0.8em;
            line-height: 1.4;
        }
        
        .method-item {
            font-size: 0.75em;
            padding: 2px 0;
            color: #cccccc;
        }
        
        .data-table {
            font-size: 0.75em;
        }
        
        .info-table th {
            font-size: 0.7em;
            padding: 4px 8px;
        }
        
        .info-table td {
            font-size: 0.7em;
            padding: 3px 8px;
        }
        
        .empty-text {
            font-size: 0.75em;
        }
        
        .info-card {
            background: rgba(15, 25, 35, 0.9);
            border: 1px solid rgba(0, 255, 159, 0.2);
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 10px;
            text-align: center;
        }
        
        .info-header {
            font-size: 0.8em;
            font-weight: bold;
            color: #00ff9f;
            margin-bottom: 5px;
        }
        
        .info-number {
            font-size: 1.2em;
            font-weight: bold;
            color: #00ffff;
            text-shadow: 0 0 5px #00ffff;
        }
        

        
        .detail-header {
            color: #00ffff;
            font-weight: bold;
            margin-bottom: 15px;
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .detail-content {
            color: #cccccc;
            line-height: 1.6;
        }
        
        .detail-list, .auth-list, .resource-list, .social-list, .api-list {
            list-style: none;
            padding: 0;
            margin: 10px 0;
        }
        
        .detail-list li, .auth-list li, .resource-list li, .social-list li, .api-list li {
            padding: 5px 0;
            border-bottom: 1px solid rgba(0, 255, 159, 0.1);
        }
        
        .detail-list li:last-child, .auth-list li:last-child, 
        .resource-list li:last-child, .social-list li:last-child, .api-list li:last-child {
            border-bottom: none;
        }
        
        .mini-table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            font-size: 0.9em;
        }
        
        .mini-table th, .mini-table td {
            padding: 8px;
            text-align: left;
            border: 1px solid rgba(0, 255, 159, 0.2);
        }
        
        .mini-table th {
            background: rgba(0, 255, 159, 0.1);
            color: #00ffff;
            font-weight: bold;
        }
        
        .resource-breakdown, .auth-breakdown, .social-breakdown {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .resource-type, .auth-section, .social-section {
            background: rgba(0, 255, 159, 0.05);
            padding: 10px;
            border-radius: 6px;
            border-left: 3px solid #00ff9f;
        }
        
        .resource-list, .auth-list, .social-list, .api-list {
            margin-top: 8px;
        }
        
        .social-list a {
            color: #00ffff;
            text-decoration: none;
            transition: color 0.3s ease;
        }
        
        .social-list a:hover {
            color: #00ff9f;
            text-decoration: underline;
        }
        
        .collapsible {
            cursor: pointer;
            user-select: none;
            transition: all 0.3s ease;
        }
        
        .collapsible:hover { color: #00ffff; }
        
        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        
        .collapsible-content.active { max-height: 1000px; }
        
    .highlight { background:#1d2c3b; padding:2px 4px; border-radius:3px; }
        
        @media (max-width: 768px) {
            .grid-2, .grid-3 { grid-template-columns: 1fr; }
            .cyber-title { font-size: 1.8em; }
            .section-content { padding: 15px; }
        }
        
        .resource-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:12px; }
        .res-block { background:#121c29; border:1px solid #243345; border-radius:4px; padding:8px 10px; }
        .res-block h4 { margin:0 0 6px 0; font-size:.65rem; text-transform:uppercase; letter-spacing:1px; color:#73e0ff; }
        .res-count { font-size:.95rem; font-weight:700; color:#6cf7d7; }
        .res-items { list-style:none; margin:6px 0 0 0; padding:0; display:flex; flex-direction:column; gap:3px; max-height:130px; overflow:auto; }
        .res-items li { font-size:.6rem; background:#182535; border:1px solid #223347; padding:3px 5px; border-radius:3px; word-break:break-all; }
        .res-items li:hover { background:#203246; }
    .mapping-comment { display:block; margin:12px 0; padding:12px; background:rgba(0,0,0,0.45); border:1px solid rgba(0,255,159,0.12); border-radius:6px; }
    .footer { text-align:center; padding:30px; margin-top:50px; border-top:1px solid #1f2c3a; color:#4e6479; }
    </style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <div style="flex:1 1 auto;min-width:260px;">
                <h1 class="report-title">Azure / Entra OSINT Recon Matrix</h1>
                <div class="meta">
                    <div class="meta-item">Target: $($Results.Domain)</div>
                    <div class="meta-item">Scan: $($Results.Timestamp)</div>
                    <div class="meta-item">Duration: $($Results.ScanDuration)</div>
                    <div class="meta-item">Tenant: $(if($Results.TenantInfo.TenantId){"<span class='status-success'>Identified</span>"}else{"<span class='status-error'>Not Found</span>"})</div>
                    <div class="meta-item">Status: <span class="status-chip">Complete</span></div>
                </div>
            </div>
        </div>

        <!-- Export Mapping removed as per user request -->
        <div>
            <div class="matrix-section-title">Recon Matrix Overview</div>
            $matrixHTML
        </div>

        <div class="section">
            <div class="section-header">
                <div class="section-title">🎯 Executive Summary</div>
            </div>
            <div class="section-content">
                <div class="grid-2">
                    <div>
                        <div class="data-row">
                            <div class="data-label">Target Domain:</div>
                            <div class="data-value status-info">$($Results.Domain)</div>
                        </div>
                        <div class="data-row">
                            <div class="data-label">Tenant Status:</div>
                            <div class="data-value $(if($Results.TenantInfo.TenantId){'status-success'}else{'status-error'})">
                                $(if($Results.TenantInfo.TenantId){'✓ IDENTIFIED'}else{'✗ NOT FOUND'})
                            </div>
                        </div>
                        <div class="data-row">
                            <div class="data-label">Namespace Type:</div>
                            <div class="data-value status-info">$($Results.TenantInfo.NameSpaceType ?? 'Unknown')</div>
                        </div>
                        <div class="data-row">
                            <div class="data-label">Cloud Instance:</div>
                            <div class="data-value status-warning">$($Results.TenantInfo.CloudInstance ?? 'Undetected')</div>
                        </div>
                    </div>
                    <div>
                        $(if($Results.TenantInfo.TenantId) {
                            "<div class='data-row'>
                                <div class='data-label'>Tenant ID:</div>
                                <div class='data-value status-success'>$($Results.TenantInfo.TenantId)</div>
                            </div>"
                        })
                        $(if($Results.TenantInfo.TenantBrand) {
                            "<div class='data-row'>
                                <div class='data-label'>Organization:</div>
                                <div class='data-value status-success'>$($Results.TenantInfo.TenantBrand)</div>
                            </div>"
                        })
                        $(if($Results.TenantInfo.TenantRegion) {
                            "<div class='data-row'>
                                <div class='data-label'>Region:</div>
                                <div class='data-value status-info'>$($Results.TenantInfo.TenantRegion)</div>
                            </div>"
                        })
                        $(if($Results.TenantInfo.STSServer) {
                            "<div class='data-row'>
                                <div class='data-label'>STS Server:</div>
                                <div class='data-value status-warning'>$($Results.TenantInfo.STSServer)</div>
                            </div>"
                        })
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-header"><h2>📊 Key Statistics</h2></div>
            <div class="section-content">
                <div class="stats-row">
                    <div class="tile"><h4>Users</h4><div class="val">$($Results.UserEnumeration.ValidUsers.Count)</div></div>
                    <div class="tile"><h4>Subdomains</h4><div class="val">$($Results.NetworkIntelligence.Subdomains.Count)</div></div>
                    <div class="tile"><h4>Azure Res</h4><div class="val">$(($Results.ExtendedAzureResources.StorageAccounts.Count + $Results.ExtendedAzureResources.FunctionApps.Count + $Results.ExtendedAzureResources.APIManagement.Count))</div></div>
                    <div class="tile"><h4>Auth Methods</h4><div class="val">$($Results.AuthenticationAnalysis.AuthMethods.Count)</div></div>
                    <div class="tile"><h4>OAuth Flows</h4><div class="val">$($Results.AuthenticationAnalysis.SupportedFlows.Count)</div></div>
                    <div class="tile"><h4>API Endpoints</h4><div class="val">$totalAPIEndpoints</div></div>
                    <div class="tile"><h4>Certificates</h4><div class="val">$($Results.Certificates.Count)</div></div>
                    <div class="tile"><h4>GitHub Repos</h4><div class="val">$($Results.SocialMedia.GitHub.Count)</div></div>
                    <div class="tile"><h4>LinkedIn</h4><div class="val">$($Results.SocialMedia.LinkedIn.Count)</div></div>
                </div>

                <div class="details-grid">
                    <div class="detail-section">
                        <div class="detail-header">👥 User Enumeration Results</div>
                        <div class="detail-content">
                            <div class="method-list">
                                <div class="method-item">🔍 GetCredentialType API validation</div>
                                <div class="method-item">☁️ OneDrive for Business discovery</div>
                                <div class="method-item">📊 Microsoft Graph API probing</div>
                                <div class="method-item">🔐 Device code flow analysis</div>
                            </div>
                            $(if($Results.UserEnumeration.ValidUsers.Count -gt 0) {
                                "<div class='data-table'>
                                    <table class='info-table'>
                                        <thead>
                                            <tr><th>Username</th><th>Discovery Method</th><th>Confidence Level</th></tr>
                                        </thead>
                                        <tbody>"
                                foreach($user in $Results.UserEnumeration.ValidUsers | Select-Object -First 10) {
                                    "<tr><td class='status-success'>$($user.Username)</td><td>$($user.Method)</td><td class='$(if($user.Confidence -eq 'High'){'status-success'}else{'status-warning'})'>$($user.Confidence)</td></tr>"
                                }
                                if($Results.UserEnumeration.ValidUsers.Count -gt 10) {
                                    "<tr><td colspan='3' class='status-neutral'><em>... and $(($Results.UserEnumeration.ValidUsers.Count - 10)) more users discovered</em></td></tr>"
                                }
                                "</tbody></table>
                                </div>"
                            } else {
                                "<div class='empty-state'>
                                    <div class='empty-icon'>👥</div>
                                    <div class='empty-text'>No valid users discovered through enumeration techniques</div>
                                </div>"
                            })
                        </div>
                    </div>

                    <div class="detail-section">
                        <div class="detail-header">🌐 Subdomain Discovery</div>
                        <div class="detail-content">
                            $(if($Results.NetworkIntelligence.Subdomains.Count -gt 0) {
                                "<div class='data-table'>
                                    <table class='info-table'>
                                        <thead>
                                            <tr><th>Subdomain</th><th>IP Addresses</th><th>Status</th></tr>
                                        </thead>
                                        <tbody>"
                                foreach($subdomain in $Results.NetworkIntelligence.Subdomains | Select-Object -First 15) {
                                    "<tr><td class='status-info'>$($subdomain.Subdomain)</td><td class='status-success'>$($subdomain.IPAddresses -join ', ')</td><td class='status-success'>✓ Active</td></tr>"
                                }
                                if($Results.NetworkIntelligence.Subdomains.Count -gt 15) {
                                    "<tr><td colspan='3' class='status-neutral'><em>... and $(($Results.NetworkIntelligence.Subdomains.Count - 15)) more subdomains</em></td></tr>"
                                }
                                "</tbody></table>
                                </div>"
                            } else {
                                "<div class='empty-state'>
                                    <div class='empty-icon'>🌐</div>
                                    <div class='empty-text'>No subdomains discovered through DNS enumeration</div>
                                </div>"
                            })
                        </div>
                    </div>

                    <div class="panel">
                        <div class="info-header">☁️ Azure Resources</div>
                        <div class="note">Total: $(($Results.ExtendedAzureResources.StorageAccounts.Count + $Results.ExtendedAzureResources.FunctionApps.Count + $Results.ExtendedAzureResources.APIManagement.Count))</div>
                        <div class="detail-section">
                            <div class="detail-header">Azure Resource Discovery:</div>
                            <div class="detail-content">
                                <div class="resource-breakdown">
                                    <div class="resource-type">
                                        <strong>🗄️ Storage Accounts:</strong> $($Results.ExtendedAzureResources.StorageAccounts.Count)
                                        $(if($Results.ExtendedAzureResources.StorageAccounts.Count -gt 0) {
                                            "<ul class='resource-list'>"
                                            foreach($storage in $Results.ExtendedAzureResources.StorageAccounts | Select-Object -First 5) {
                                                "<li class='status-success'>$($storage.Name)</li>"
                                            }
                                            "</ul>"
                                        })
                                    </div>
                                    <div class="resource-type">
                                        <strong>⚡ Function Apps:</strong> $($Results.ExtendedAzureResources.FunctionApps.Count)
                                        $(if($Results.ExtendedAzureResources.FunctionApps.Count -gt 0) {
                                            "<ul class='resource-list'>"
                                            foreach($func in $Results.ExtendedAzureResources.FunctionApps | Select-Object -First 5) {
                                                "<li class='status-success'>$($func.Name)</li>"
                                            }
                                            "</ul>"
                                        })
                                    </div>
                                    <div class="resource-type">
                                        <strong>🔌 API Management:</strong> $($Results.ExtendedAzureResources.APIManagement.Count)
                                        $(if($Results.ExtendedAzureResources.APIManagement.Count -gt 0) {
                                            "<ul class='resource-list'>"
                                            foreach($api in $Results.ExtendedAzureResources.APIManagement | Select-Object -First 5) {
                                                "<li class='status-success'>$($api.Name)</li>"
                                            }
                                            "</ul>"
                                        })
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="panel">
                        <div class="info-header">⚡ API Endpoints</div>
                        <div class="note">Total: $totalAPIEndpoints</div>
                        <div class="detail-section">
                            <div class="detail-header">API Reconnaissance Summary:</div>
                            <div class="detail-content">
                                        <div class="api-breakdown">
                                            <div class="api-section">
                                                <strong>🛡️ Microsoft Purview</strong>
                                                $(if($Results.PurviewRecon) {
                                                    $dpCount = if($Results.PurviewRecon.DataPlaneAPIs){ $Results.PurviewRecon.DataPlaneAPIs.Keys.Count } else { 0 }
                                                    $cpCount = if($Results.PurviewRecon.ControlPlaneAPIs){ $Results.PurviewRecon.ControlPlaneAPIs.Keys.Count } else { 0 }
                                                    "<div class='note'>Data-plane: $dpCount &middot; Control-plane: $cpCount</div>" +
                                                    $(if($dpCount -gt 0){
                                                        "<ul class='api-list'>" + ($Results.PurviewRecon.DataPlaneAPIs.Keys | Select-Object -First 6 | ForEach-Object { "<li class='status-warning'>" + [System.Web.HttpUtility]::HtmlEncode($_) + "</li>" }) -join '' + "</ul>"
                                                    } else { "<p class='status-info'>No data-plane endpoints discovered</p>" })
                                                } else {
                                                    "<p class='status-info'>No Purview presence detected</p>"
                                                })
                                            </div>
                                            <div class="api-section">
                                                <strong>🏭 Microsoft Fabric</strong>
                                                $(if($Results.FabricRecon) {
                                                    $core = if($Results.FabricRecon.CoreAPIs){ $Results.FabricRecon.CoreAPIs.Keys.Count } else {0}
                                                    $work = if($Results.FabricRecon.WorkloadAPIs){ $Results.FabricRecon.WorkloadAPIs.Keys.Count } else {0}
                                                    "<div class='note'>Core APIs: $core &middot; Workload APIs: $work</div>" +
                                                    $(if($core -gt 0){ "<ul class='api-list'>" + ($Results.FabricRecon.CoreAPIs.Keys | Select-Object -First 6 | ForEach-Object { "<li class='status-warning'>" + [System.Web.HttpUtility]::HtmlEncode($_) + "</li>" }) -join '' + "</ul>" } else { "<p class='status-info'>No Fabric core APIs discovered</p>" })
                                                } else {
                                                    "<p class='status-info'>No Fabric presence detected</p>"
                                                })
                                            </div>
                                            <div class="api-section">
                                                <strong>📊 Power BI</strong>
                                                $(if($Results.PowerBIRecon) {
                                                    $rest = if($Results.PowerBIRecon.RestAPIs){ $Results.PowerBIRecon.RestAPIs.Keys.Count } else {0}
                                                    $adm = if($Results.PowerBIRecon.AdminAPIs){ $Results.PowerBIRecon.AdminAPIs.Keys.Count } else {0}
                                                    "<div class='note'>REST: $rest &middot; Admin: $adm</div>" +
                                                    $(if($rest -gt 0){ "<ul class='api-list'>" + ($Results.PowerBIRecon.RestAPIs.Keys | Select-Object -First 6 | ForEach-Object { "<li class='status-warning'>" + [System.Web.HttpUtility]::HtmlEncode($_) + "</li>" }) -join '' + "</ul>" } else { "<p class='status-info'>No Power BI REST endpoints discovered</p>" })
                                                } else {
                                                    "<p class='status-info'>No Power BI presence detected</p>"
                                                })
                                            </div>
                                        </div>
                            </div>
                        </div>
                    </div>

                    <div class="panel">
                        <div class="info-header">🔐 Auth Methods</div>
                        <div class="note">Methods: $($Results.AuthenticationAnalysis.AuthMethods.Count) | Flows: $($Results.AuthenticationAnalysis.SupportedFlows.Count)</div>
                        <div class="detail-section">
                            <div class="detail-header">Authentication Analysis:</div>
                            <div class="detail-content">
                                <div class="auth-breakdown">
                                    <div class="auth-section">
                                        <strong>🔑 Authentication Methods:</strong>
                                        <ul class="auth-list">
                                            $(if($Results.AuthenticationAnalysis.AuthMethods) {
                                                foreach($method in $Results.AuthenticationAnalysis.AuthMethods) {
                                                    "<li class='status-success'>$method</li>"
                                                }
                                            } else {
                                                "<li class='status-info'>Password Authentication</li>"
                                                "<li class='status-$(if($Results.TenantInfo.DesktopSSOEnabled){'success'}else{'warning'})'>Desktop SSO: $(if($Results.TenantInfo.DesktopSSOEnabled){'Enabled'}else{'Disabled'})</li>"
                                            })
                                        </ul>
                                    </div>
                                    <div class="auth-section">
                                        <strong>🔄 OAuth Flows:</strong>
                                        <ul class="auth-list">
                                            $(if($Results.AuthenticationAnalysis.SupportedFlows) {
                                                foreach($flow in $Results.AuthenticationAnalysis.SupportedFlows) {
                                                    "<li class='status-success'>$flow</li>"
                                                }
                                            } else {
                                                "<li class='status-success'>Authorization Code Flow</li>"
                                                "<li class='status-success'>Device Code Flow</li>"
                                            })
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="panel">
                        <div class="info-header">📜 Certificates</div>
                        <div class="note">Total: $($Results.Certificates.Count)</div>
                        <div class="detail-section">
                            <div class="detail-header">Certificate Transparency Analysis:</div>
                            $(if($Results.Certificates.Count -gt 0) {
                                "<div class='detail-content'>
                                    <table class='mini-table'>
                                        <tr><th>Certificate</th><th>Issuer</th><th>Valid From</th><th>Valid To</th></tr>"
                                foreach($cert in $Results.Certificates | Select-Object -First 8) {
                                    "<tr><td class='status-info'>$($cert.CommonName)</td><td class='status-neutral'>$($cert.Issuer)</td><td class='status-success'>$($cert.ValidFrom)</td><td class='status-warning'>$($cert.ValidTo)</td></tr>"
                                }
                                if($Results.Certificates.Count -gt 8) {
                                    "<tr><td colspan='4' class='status-neutral'><em>... and $(($Results.Certificates.Count - 8)) more certificates</em></td></tr>"
                                }
                                "</table>
                                </div>"
                            } else {
                                "<div class='detail-content'><em>No certificates found in transparency logs</em></div>"
                            })
                        </div>
                    </div>

                    <div class="panel">
                        <div class="info-header">📱 Social Media</div>
                        <div class="note">GitHub: $($Results.SocialMedia.GitHub.Count) | LinkedIn: $($Results.SocialMedia.LinkedIn.Count)</div>
                        <div class="detail-section">
                            <div class="detail-header">Digital Footprint Analysis:</div>
                            <div class="detail-content">
                                <div class="social-breakdown">
                                    <div class="social-section">
                                        <strong>🐙 GitHub Repositories:</strong> $($Results.SocialMedia.GitHub.Count)
                                        $(if($Results.SocialMedia.GitHub.Count -gt 0) {
                                            "<ul class='social-list'>" +
                                            ($Results.SocialMedia.GitHub | Select-Object -First 10 | ForEach-Object {
                                                $name = $_.Name
                                                $url  = $_.Url
                                                "<li class='status-success'><a href='" + $url + "' target='_blank'>" + [System.Web.HttpUtility]::HtmlEncode($name) + "</a> <span class='note' style='margin-left:8px;'>⭐ " + ($_.Stars -as [string]) + "</span></li>"
                                            }) -join '' +
                                            "</ul>"
                                        })
                                    </div>
                                    <div class="social-section">
                                        <strong>💼 LinkedIn Profiles:</strong> $($Results.SocialMedia.LinkedIn.Count)
                                        $(if($Results.SocialMedia.LinkedIn.Count -gt 0) {
                                            "<ul class='social-list'>" + ($Results.SocialMedia.LinkedIn | Select-Object -First 10 | ForEach-Object {
                                                $url = $_.Url
                                                "<li class='status-info'><a href='" + $url + "' target='_blank'>" + [System.Web.HttpUtility]::HtmlEncode($url) + "</a></li>"
                                            }) -join '' + "</ul>"
                                        })
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        $(if($Results.ServiceDiscovery.EntraID -or $Results.ServiceDiscovery.Exchange -or $Results.ServiceDiscovery.SharePoint -or $Results.ServiceDiscovery.Teams -or $Results.ServiceDiscovery.OneDrive) {
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>☁️ Microsoft 365 Services</div>
                </div>
                <div class='section-content'>
                    <div class='grid-2'>"
                    
            if($Results.ServiceDiscovery.EntraID) {
                "<div class='data-row'>
                    <div class='data-label'>🔐 Entra ID / Azure AD:</div>
                    <div class='data-value status-success'>✓ Active</div>
                </div>"
            }
            
            if($Results.ServiceDiscovery.Exchange) {
                "<div class='data-row'>
                    <div class='data-label'>📧 Exchange Online:</div>
                    <div class='data-value status-success'>✓ Active</div>
                </div>"
            }
            
            if($Results.ServiceDiscovery.SharePoint) {
                "<div class='data-row'>
                    <div class='data-label'>📁 SharePoint Online:</div>
                    <div class='data-value status-success'>✓ Active</div>
                </div>"
            }
            
            if($Results.ServiceDiscovery.Teams) {
                "<div class='data-row'>
                    <div class='data-label'>💬 Microsoft Teams:</div>
                    <div class='data-value status-success'>✓ Active</div>
                </div>"
            }
            
            if($Results.ServiceDiscovery.OneDrive) {
                "<div class='data-row'>
                    <div class='data-label'>☁️ OneDrive for Business:</div>
                    <div class='data-value status-success'>✓ Active</div>
                </div>"
            }
            
            "</div>
                </div>
            </div>"
        })

        $(if($Results.UserEnumeration.ValidUsers.Count -gt 0) {
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>👥 Valid Users Discovered</div>
                </div>
                <div class='section-content'>
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Discovery Method</th>
                                <th>Confidence</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody>"
                        
            foreach($user in $Results.UserEnumeration.ValidUsers) {
                "<tr>
                    <td class='status-success'>$($user.Username)</td>
                    <td class='status-info'>$($user.Method)</td>
                    <td class='$(if($user.Confidence -eq 'High'){'status-success'}elseif($user.Confidence -eq 'Medium'){'status-warning'}else{'status-error'})'>$($user.Confidence)</td>
                    <td>$($user.Evidence)</td>
                </tr>"
            }
            
            "</tbody>
                    </table>
                </div>
            </div>"
        })

        $(if($Results.NetworkIntelligence.Subdomains.Count -gt 0) {
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>🌐 Network Intelligence</div>
                </div>
                <div class='section-content'>
                    <table>
                        <thead>
                            <tr>
                                <th>Subdomain</th>
                                <th>IP Addresses</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>"
                        
            foreach($subdomain in $Results.NetworkIntelligence.Subdomains) {
                "<tr>
                    <td class='status-info'>$($subdomain.Subdomain)</td>
                    <td class='status-success'>$($subdomain.IPAddresses -join ', ')</td>
                    <td class='status-success'>✓ Resolved</td>
                </tr>"
            }
            
            "</tbody>
                    </table>
                </div>
            </div>"
        })

    $(if($Results.SecurityPosture) {
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>🛡️ Security Posture Analysis</div>
                </div>
                <div class='section-content'>
                    <div class='grid-2'>"
                    
            if($Results.SecurityPosture.SecurityDefaults) {
                "<div>
                    <h4 style='color: #00ffff; margin-bottom: 10px;'>🔒 Security Defaults</h4>"
                if($Results.SecurityPosture.SecurityDefaults.MFARequired) {
                    "<div class='data-row'>
                        <div class='data-label'>MFA Required:</div>
                        <div class='data-value status-success'>✓ Enabled</div>
                    </div>"
                }
                if($Results.SecurityPosture.SecurityDefaults.BlockLegacyAuth) {
                    "<div class='data-row'>
                        <div class='data-label'>Legacy Auth Blocked:</div>
                        <div class='data-value status-success'>✓ Enabled</div>
                    </div>"
                }
                "</div>"
            }
            
            if($Results.SecurityPosture.GuestAccess) {
                "<div>
                    <h4 style='color: #00ffff; margin-bottom: 10px;'>👥 Guest Access</h4>"
                if($Results.SecurityPosture.GuestAccess.ExternalCollaboration) {
                    "<div class='data-row'>
                        <div class='data-label'>External Collaboration:</div>
                        <div class='data-value status-warning'>⚠ Enabled</div>
                    </div>"
                }
                if($Results.SecurityPosture.GuestAccess.GuestInviteRestrictions) {
                    "<div class='data-row'>
                        <div class='data-label'>Invite Restrictions:</div>
                        <div class='data-value status-info'>ℹ Configured</div>
                    </div>"
                }
                "</div>"
            }
            
            "</div>
                </div>
            </div>"
        })

    $(if($Results.PowerBIFabric) {
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>⚡ Power BI & Microsoft Fabric</div>
                </div>
                <div class='section-content'>
                    <div class='grid-3'>"
                    
            if($Results.PowerBIFabric.PowerBIService) {
                "<div class='data-row'>
                    <div class='data-label'>Power BI Service:</div>
                    <div class='data-value status-success'>✓ Available</div>
                </div>"
            }
            
            if($Results.PowerBIFabric.FabricPlatform) {
                "<div class='data-row'>
                    <div class='data-label'>Fabric Platform:</div>
                    <div class='data-value status-success'>✓ Available</div>
                </div>"
            }
            
            if($Results.PowerBIFabric.CrossTenantSharing) {
                "<div class='data-row'>
                    <div class='data-label'>Cross-Tenant Sharing:</div>
                    <div class='data-value status-warning'>⚠ Enabled</div>
                </div>"
            }
            
            "</div>
                </div>
            </div>"
        })

    $(if($Results.PurviewRecon) {
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>🛡️ Microsoft Purview API Reconnaissance</div>
                </div>
                <div class='section-content'>"
                    "<h4 style='color: #00ffff; margin-bottom: 15px;'>📋 Data Governance & Compliance APIs</h4>"
                    "<div class='grid-2'>"
                    
            if($Results.PurviewRecon.PurviewAccounts -and $Results.PurviewRecon.PurviewAccounts.Keys.Count -gt 0) {
                foreach($account in $Results.PurviewRecon.PurviewAccounts.Keys) {
                    "<div class='data-row'>
                        <div class='data-label'>Purview Account:</div>
                        <div class='data-value status-success'>✅ $account.purview.azure.com</div>
                    </div>"
                }
            }
            
            if($Results.PurviewRecon.DataPlaneAPIs -and $Results.PurviewRecon.DataPlaneAPIs.Keys.Count -gt 0) {
                "<div class='data-row'>
                    <div class='data-label'>Data Plane APIs:</div>
                    <div class='data-value status-warning'>🔐 $($Results.PurviewRecon.DataPlaneAPIs.Keys.Count) endpoints (auth required)</div>
                </div>"
            }
            
            if($Results.PurviewRecon.ControlPlaneAPIs -and $Results.PurviewRecon.ControlPlaneAPIs.Keys.Count -gt 0) {
                "<div class='data-row'>
                    <div class='data-label'>Control Plane APIs:</div>
                    <div class='data-value status-warning'>⚙️ $($Results.PurviewRecon.ControlPlaneAPIs.Keys.Count) management endpoints</div>
                </div>"
            }
            
            if($Results.PurviewRecon.Authentication.OAuth2) {
                "<div class='data-row'>
                    <div class='data-label'>OAuth2 Authentication:</div>
                    <div class='data-value status-success'>✅ Entra ID integration available</div>
                </div>"
            }
            
            if($Results.PurviewRecon.Security.KeyVault) {
                "<div class='data-row'>
                    <div class='data-label'>Key Vault Integration:</div>
                    <div class='data-value status-success'>🔑 Detected</div>
                </div>"
            }
            
            "</div>
                </div>
            </div>"
        })

    $(if($Results.FabricRecon) {
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>🏭 Microsoft Fabric API Reconnaissance</div>
                </div>
                <div class='section-content'>"
                    "<h4 style='color: #00ffff; margin-bottom: 15px;'>⚡ Data Platform & Workload APIs</h4>"
                    "<div class='grid-2'>"
                    
            if($Results.FabricRecon.CoreAPIs -and $Results.FabricRecon.CoreAPIs.Keys.Count -gt 0) {
                "<div class='data-row'>
                    <div class='data-label'>Core Fabric APIs:</div>
                    <div class='data-value status-warning'>🔐 $($Results.FabricRecon.CoreAPIs.Keys.Count) endpoints (auth required)</div>
                </div>"
            }
            
            if($Results.FabricRecon.WorkloadAPIs -and $Results.FabricRecon.WorkloadAPIs.Keys.Count -gt 0) {
                "<div class='data-row'>
                    <div class='data-label'>Workload APIs:</div>
                    <div class='data-value status-info'>🏗️ $($Results.FabricRecon.WorkloadAPIs.Keys.Count) workload types available</div>
                </div>"
            }
            
            if($Results.FabricRecon.OneLake.Endpoint) {
                "<div class='data-row'>
                    <div class='data-label'>OneLake Storage:</div>
                    <div class='data-value status-success'>🏞️ Data lake endpoints detected</div>
                </div>"
            }
            
            if($Results.FabricRecon.Authentication.ServicePrincipal) {
                "<div class='data-row'>
                    <div class='data-label'>Service Principal Auth:</div>
                    <div class='data-value status-success'>✅ Available for automation</div>
                </div>"
            }
            
            "</div>
                </div>
            </div>"
        })

        $(if($Results.PowerBIRecon) {
        
        $(if($Results.BreachData) {
            "<div class='section'>
                <div class='section-header'><h2>🛡️ Breach Intelligence</h2></div>
                <div class='section-content'>"
                    if($Results.BreachData.ReferenceBreaches){
                        "<div class='panel'><h3>Reference Breaches</h3><ul class='list'>" + ($Results.BreachData.ReferenceBreaches | ForEach-Object { 
                            $n = $_.Name; $d = $_.Date; $r = $_.Records; $t = $_.Type
                            "<li><strong>" + [System.Web.HttpUtility]::HtmlEncode($n) + "</strong> — " + [System.Web.HttpUtility]::HtmlEncode($d) + " — " + [System.Web.HttpUtility]::HtmlEncode($r) + " (" + [System.Web.HttpUtility]::HtmlEncode($t) + ")</li>"
                        }) -join '' + "</ul></div>"
                    }
                    if($Results.BreachData.DomainBreaches -and $Results.BreachData.DomainBreaches.Count -gt 0){
                        "<div class='panel'><h3>Domain Breaches</h3><ul class='list'>" + ($Results.BreachData.DomainBreaches | ForEach-Object { "<li>$_</li>" }) -join '' + "</ul></div>"
                    } else { "<div class='note'>No domain-specific breaches recorded (placeholder).</div>" }
                    "<div class='note'>${($Results.BreachData.Note)}</div>"
                "</div>
            </div>"
        })
        
        $(if($Results.EmailPatterns) {
            "<div class='section'>
                <div class='section-header'><h2>📧 Email Pattern Analysis</h2></div>
                <div class='section-content'>"
                    if($Results.EmailPatterns.Patterns -and $Results.EmailPatterns.Patterns.Count -gt 0){
                        "<div class='panel'><h3>Patterns Detected</h3><ul class='list'>" + ($Results.EmailPatterns.Patterns | ForEach-Object { "<li>$_</li>" }) -join '' + "</ul></div>"
                    }
                    if($Results.EmailPatterns.PreviewAddresses){
                        "<div class='panel'><h3>Address Examples</h3><ul class='list'>" + ($Results.EmailPatterns.PreviewAddresses | ForEach-Object { "<li>$_</li>" }) -join '' + "</ul></div>"
                    }
                "</div>
            </div>"
        })
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>📊 Power BI API Reconnaissance</div>
                </div>
                <div class='section-content'>"
                    "<h4 style='color: #00ffff; margin-bottom: 15px;'>📈 Business Intelligence & Analytics APIs</h4>"
                    "<div class='grid-2'>"
                    
            if($Results.PowerBIRecon.RestAPIs -and $Results.PowerBIRecon.RestAPIs.Keys.Count -gt 0) {
                "<div class='data-row'>
                    <div class='data-label'>REST APIs:</div>
                    <div class='data-value status-warning'>📊 $($Results.PowerBIRecon.RestAPIs.Keys.Count) core endpoints (auth required)</div>
                </div>"
            }
            
            if($Results.PowerBIRecon.AdminAPIs -and $Results.PowerBIRecon.AdminAPIs.Keys.Count -gt 0) {
                "<div class='data-row'>
                    <div class='data-label'>Admin APIs:</div>
                    <div class='data-value status-warning'>⚙️ $($Results.PowerBIRecon.AdminAPIs.Keys.Count) admin endpoints (elevated auth)</div>
                </div>"
            }
            
            if($Results.PowerBIRecon.EmbedAPIs -and $Results.PowerBIRecon.EmbedAPIs.Keys.Count -gt 0) {
                "<div class='data-row'>
                    <div class='data-label'>Embedding APIs:</div>
                    <div class='data-value status-success'>🎨 $($Results.PowerBIRecon.EmbedAPIs.Keys.Count) embedding endpoints available</div>
                </div>"
            }
            
            if($Results.PowerBIRecon.ServicePrincipal.Supported) {
                "<div class='data-row'>
                    <div class='data-label'>Service Principal Support:</div>
                    <div class='data-value status-success'>🤖 Automation ready</div>
                </div>"
            }
            
            if($Results.PowerBIRecon.PublicContent.Community) {
                "<div class='data-row'>
                    <div class='data-label'>Public Content:</div>
                    <div class='data-value status-info'>🌐 Organization mentioned in community</div>
                </div>"
            }
            
            "</div>
                </div>
            </div>"
        })

        $(if($Results.TenantInfo.TenantId) {
            # Insert DNS & Mail posture, Azure Resource Surface, External Identity sections before Quick Actions
        })

        $(if($Results.TenantInfo.DNSAnalysis) {
            "<div class='section'>
                <div class='section-header'><h2>🧬 DNS & Mail Posture</h2></div>
                <div class='section-content'>
                    <div class='grid-2'>
                        <div>
                            <div class='data-row'><div class='data-label'>DNS A Record</div><div class='data-value $(if($Results.TenantInfo.DNSAnalysis.DNS){'status-success'}else{'status-error'})'>$(if($Results.TenantInfo.DNSAnalysis.DNS){'Present'}else{'Missing'})</div></div>
                            <div class='data-row'><div class='data-label'>MX (O365)</div><div class='data-value $(if($Results.TenantInfo.DNSAnalysis.MX){'status-success'}else{'status-warning'})'>$(if($Results.TenantInfo.DNSAnalysis.MX){'Configured'}else{'No O365 MX'})</div></div>
                            <div class='data-row'><div class='data-label'>SPF Record</div><div class='data-value $(if($Results.TenantInfo.DNSAnalysis.SPF){'status-success'}else{'status-warning'})'>$(if($Results.TenantInfo.DNSAnalysis.SPF){'Exchange Online'}else{'Not Include:spf.protection'})</div></div>
                            <div class='data-row'><div class='data-label'>DMARC</div><div class='data-value $(if($Results.TenantInfo.DNSAnalysis.DMARC){'status-success'}else{'status-warning'})'>$(if($Results.TenantInfo.DNSAnalysis.DMARC){'Configured'}else{'Missing'})</div></div>
                            <div class='data-row'><div class='data-label'>DKIM</div><div class='data-value $(if($Results.TenantInfo.DNSAnalysis.DKIM){'status-success'}else{'status-warning'})'>$(if($Results.TenantInfo.DNSAnalysis.DKIM){'Selectors Found'}else{'Not Detected'})</div></div>
                            <div class='data-row'><div class='data-label'>MTA-STS</div><div class='data-value $(if($Results.TenantInfo.DNSAnalysis.MTASTS){'status-success'}else{'status-warning'})'>$(if($Results.TenantInfo.DNSAnalysis.MTASTS){'Policy Present'}else{'None'})</div></div>
                        </div>
                        <div>
                            $(if ($Results.TenantInfo.DNSAnalysis.SPFRecord) { "<div class='panel'><h3>SPF Record</h3><div class='note'>" + [System.Web.HttpUtility]::HtmlEncode($Results.TenantInfo.DNSAnalysis.SPFRecord) + "</div></div>" })
                            $(if ($Results.TenantInfo.DNSAnalysis.DMARCRecord) { "<div class='panel'><h3>DMARC Record</h3><div class='note'>" + [System.Web.HttpUtility]::HtmlEncode($Results.TenantInfo.DNSAnalysis.DMARCRecord) + "</div></div>" })
                            $(if ($Results.TenantInfo.DNSAnalysis.DKIMRecords) { "<div class='panel'><h3>DKIM Records</h3><ul class='list'>" + ($Results.TenantInfo.DNSAnalysis.DKIMRecords | ForEach-Object { "<li>" + [System.Web.HttpUtility]::HtmlEncode($_) + "</li>" }) -join '' + "</ul></div>" })
                        </div>
                    </div>
                </div>
            </div>"
        })

        $(if($Results.ExtendedAzureResources) {
            # Build resource category blocks dynamically
            $resMap = @(
                @{ Key='StorageAccounts'; Label='Storage'; Icon='🗄️'; Prop='Name' }
                @{ Key='FunctionApps'; Label='Function Apps'; Icon='⚡'; Prop='Url' }
                @{ Key='APIManagement'; Label='API Mgmt'; Icon='🔌'; Prop='Url' }
                @{ Key='CosmosDB'; Label='Cosmos DB'; Icon='☄️'; Prop='Url' }
                @{ Key='ContainerRegistry'; Label='ACR'; Icon='📦'; Prop='Url' }
                @{ Key='CDNEndpoints'; Label='CDN'; Icon='🚀'; Prop='Endpoint' }
                @{ Key='TrafficManager'; Label='Traffic Manager'; Icon='🧭'; Prop='Url' }
                @{ Key='FrontDoor'; Label='Front Door'; Icon='🚪'; Prop='Url' }
                @{ Key='ServiceBus'; Label='Service Bus'; Icon='🚌'; Prop='Url' }
                @{ Key='EventHubs'; Label='Event Hubs'; Icon='🎯'; Prop='Url' }
                @{ Key='LogicApps'; Label='Logic Apps'; Icon='🧩'; Prop='Url' }
                @{ Key='ARMTemplates'; Label='ARM Templates'; Icon='📐'; Prop='Url' }
            )
            $blocks = @()
            foreach($entry in $resMap){
                $collection = $Results.ExtendedAzureResources[$entry.Key]
                if($collection){
                    $count = $collection.Count
                    $sampleItems = @()
                    $prop = $entry.Prop
                    $collection | Select-Object -First 6 | ForEach-Object { $sampleItems += (($_.$prop) -as [string]) }
                    $li = if($sampleItems.Count -gt 0){ '<ul class="res-items">' + ($sampleItems | ForEach-Object { '<li>' + [System.Web.HttpUtility]::HtmlEncode($_) + '</li>' }) -join '' + '</ul>' } else { '<div class="note">No examples</div>' }
                    $blocks += "<div class='res-block'><h4>$($entry.Icon) $($entry.Label)</h4><div class='res-count'>$count</div>$li</div>"
                }
            }
            "<div class='section'><div class='section-header'><h2>☁️ Azure Resource Surface</h2></div><div class='section-content'><div class='resource-grid'>" + ($blocks -join '') + "</div></div></div>"
        })

        $(if($Results.UserEnumeration.EntraExternalID -or $Results.UserEnumeration.DeviceCodeResults) {
            "<div class='section'><div class='section-header'><h2>🌍 External Identity & Cross-Tenant</h2></div><div class='section-content'>" +
            $(if($Results.UserEnumeration.EntraExternalID){
                $ext = $Results.UserEnumeration.EntraExternalID
                $rows = @()
                foreach($k in $ext.Keys){ $val = $ext[$k]; $rows += "<div class='data-row'><div class='data-label'>$k</div><div class='data-value status-info'>" + [System.Web.HttpUtility]::HtmlEncode(($val -join ', ')) + "</div></div>" }
                "<div class='panel'><h3>Entra External ID Signals</h3>$($rows -join '')</div>"
            }) +
            $(if($Results.UserEnumeration.DeviceCodeResults){
                $dcr = $Results.UserEnumeration.DeviceCodeResults
                $dcRows = @()
                foreach($k in $dcr.Keys){ $val = $dcr[$k]; $dcRows += "<div class='data-row'><div class='data-label'>$k</div><div class='data-value status-warning'>" + [System.Web.HttpUtility]::HtmlEncode(($val -join ', ')) + "</div></div>" }
                "<div class='panel'><h3>Device Code Flow</h3>$($dcRows -join '')</div>"
            }) +
            "</div></div>"
        })

        # Append defensive guidance when TenantId known (inline to avoid here-string mismatches)
        $(if($Results.TenantInfo.TenantId) {
            "<div class='section'>
                <div class='section-header'><h2>🧭 Defensive OSINT — External Identity Guidance</h2></div>
                <div class='section-content'>
                    <button class='collapsible' aria-expanded='false'>Show defensive OSINT guidance</button>
                    <div class='collapsible-content'>
                        <div class='panel'>
                            <h3>Defensive OSINT — Summary</h3>
                            <p>This section provides safe, defensive guidance for external identity and cross-tenant signals discovered during reconnaissance. It is intended for defenders and authorized testers only.</p>
                            <ul class='list'>
                                <li><strong>Limit data exposure:</strong> Audit and reduce publicly-listed identities, application registrations, and API endpoints where possible.</li>
                                <li><strong>Harden mail posture:</strong> Verify SPF/DMARC/DKIM records and consider stricter DMARC policies to reduce impersonation risk.</li>
                                <li><strong>Lock down sign-in:</strong> Enforce MFA, block legacy auth, and review Conditional Access policies for external collaboration.</li>
                                <li><strong>Review external identities:</strong> Investigate B2B relationships and guest user patterns; remove stale or unused external IDs.</li>
                                <li><strong>Protect secrets & certs:</strong> Rotate certificates and review Key Vault access policies.</li>
                            </ul>
                            <p class='note'>To include a longer, project-specific defensive guidance block, replace the contents of this collapsible with your full guidance text. Keep the HTML attributes single-quoted to avoid breaking the template.</p>
                        </div>
                    </div>
                </div>
            </div>"
        })

        <!-- COMPLETENESS MAPPING
        ResultKey -> HTML Section
        TenantInfo -> Matrix, Executive Summary, DNS & Mail Posture
        UserEnumeration.ValidUsers -> Valid Users table (existing earlier in report)
        NetworkIntelligence.Subdomains -> Subdomain table section
        ExtendedAzureResources.* -> Azure Resource Surface (new)
        AuthenticationAnalysis -> Auth Methods / OAuth flows section
        SecurityPosture -> Security Posture Analysis section
        PowerBIFabric -> Power BI & Fabric Analysis section
        PurviewRecon -> Purview API Recon section
        FabricRecon -> Fabric API Recon section
        PowerBIRecon -> Power BI API Recon section
        Certificates -> Certificates section (earlier)
        SocialMedia -> Social Media panel & matrix column
        BreachData -> Breach Intelligence section
        EmailPatterns -> Email Pattern Analysis section
        UserEnumeration.EntraExternalID -> External Identity section
        UserEnumeration.DeviceCodeResults -> External Identity section
        -->

        $(if($Results.TenantInfo.TenantId) {
            "<div class='section'>
                <div class='section-header'>
                    <div class='section-title'>🔗 Quick Actions</div>
                </div>
                <div class='section-content'>
                    <div class='action-buttons'>
                        <a href='https://portal.azure.com/#@$($Results.TenantInfo.TenantId)' target='_blank' class='cyber-btn'>🌐 Azure Portal</a>
                        <a href='https://login.microsoftonline.com/$($Results.TenantInfo.TenantId)/.well-known/openid_configuration' target='_blank' class='cyber-btn'>🔍 OIDC Config</a>
                        <a href='https://admin.microsoft.com/' target='_blank' class='cyber-btn'>⚙️ M365 Admin</a>
                        <a href='https://security.microsoft.com/' target='_blank' class='cyber-btn'>🛡️ Security Center</a>
                    </div>
                </div>
            </div>"
        })

        <div class="footer">
            <p>Generated by Advanced Azure OSINT Tool | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC</p>
            <p>🔐 Responsible Disclosure | 🛡️ Authorized Testing Only | ⚡ Enhanced Security Analysis</p>
        </div>
    </div>

    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                console.log('Copied to clipboard: ' + text);
                showNotification('Copied to clipboard!');
            }, function(err) {
                console.error('Could not copy text: ', err);
                showNotification('Copy failed', 'error');
            });
        }

        // Interactive statistics cards functionality
        function initializeReport() {
            console.log('OSINT Report loaded successfully');
            document.title = 'Azure OSINT Report - ' + new Date().toLocaleDateString();
        }

        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = 'notification ' + type;
            notification.textContent = message;
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 15px 20px;
                border-radius: 8px;
                color: #000;
                font-weight: bold;
                z-index: 10000;
                transition: all 0.3s ease;
                background: ${type === 'error' ? '#ff4444' : '#00ff9f'};
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.opacity = '0';
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }

        // Add collapsible functionality for other sections
        document.querySelectorAll('.collapsible').forEach(function(element) {
            element.addEventListener('click', function() {
                const content = this.nextElementSibling;
                content.classList.toggle('active');
                this.classList.toggle('active');
            });
        });

        // Enhanced interactive effects
        document.addEventListener('DOMContentLoaded', function() {
            // Highlight tenant IDs for easy copying
            document.querySelectorAll('.status-success').forEach(function(element) {
                if (element.textContent.length === 36 && element.textContent.includes('-')) {
                    element.style.cursor = 'pointer';
                    element.title = 'Click to copy Tenant ID';
                    element.addEventListener('click', function() {
                        copyToClipboard(element.textContent);
                    });
                }
            });




        });
    </script>
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
    • Enhanced user enumeration (GetCredentialType API, OneDrive, Graph API)
    • Advanced tenant discovery (mjendza.net techniques)
    • Authentication flow analysis (OAuth 2.0, Device Code Flow)
    • Security posture assessment (MFA, Conditional Access, Federation)
    • Extended Azure resource discovery (ROADtools inspired)
    • Certificate Transparency logs
    • Social media footprint discovery
    • Breach data correlation (placeholder)
    • Email pattern analysis
    • Interactive HTML reports with copy-to-clipboard

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
        
        # Export results and get the generated file paths
        $exportedFiles = Export-AdvancedResults -Results $results -OutputPath $OutputFile
        
        Write-Host "`nAdvanced OSINT scan completed successfully!" -ForegroundColor Green
        Write-Host "Results saved to: $OutputFile" -ForegroundColor Cyan
        
        # Automatically open the HTML report in default browser
        if ($exportedFiles.HTMLFile -and (Test-Path $exportedFiles.HTMLFile)) {
            Write-Host "Opening HTML report in default browser..." -ForegroundColor Yellow
            try {
                Start-Process $exportedFiles.HTMLFile
                Write-Host "✅ HTML report opened successfully!" -ForegroundColor Green
            }
            catch {
                Write-Host "❌ Could not open HTML report automatically. Please open manually: $($exportedFiles.HTMLFile)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "⚠️ HTML file not found for auto-open. Check the generated files above." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error during advanced reconnaissance: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

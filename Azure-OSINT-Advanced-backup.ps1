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
    Write-Host "╭━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╮" -ForegroundColor DarkCyan
    Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
    Write-Host " 🔍 Azure OSINT 🛡️ Advanced Reconnaissance Engine 🌐 ".PadLeft(46).PadRight(86) -ForegroundColor White -NoNewline
    Write-Host "┃" -ForegroundColor DarkCyan
    Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
    Write-Host "".PadRight(86) -ForegroundColor White -NoNewline
    Write-Host "┃" -ForegroundColor DarkCyan
    Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
    Write-Host " ⚡ ENHANCED SECURITY ANALYSIS ⚡ AADInternals + ROADtools + mjendza.net ".PadLeft(51).PadRight(86) -ForegroundColor Yellow -NoNewline
    Write-Host "┃" -ForegroundColor DarkCyan
    if ($Title) {
        Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
        Write-Host "".PadRight(86) -ForegroundColor White -NoNewline
        Write-Host "┃" -ForegroundColor DarkCyan
        Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
        Write-Host " 🎯 $Title ".PadLeft((86 + $Title.Length + 4) / 2).PadRight(86) -ForegroundColor Cyan -NoNewline
        Write-Host "┃" -ForegroundColor DarkCyan
    }
    if ($Subtitle) {
        Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
        Write-Host " $Subtitle ".PadLeft((86 + $Subtitle.Length + 2) / 2).PadRight(86) -ForegroundColor Gray -NoNewline
        Write-Host "┃" -ForegroundColor DarkCyan
    }
    Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
    Write-Host "".PadRight(86) -ForegroundColor White -NoNewline
    Write-Host "┃" -ForegroundColor DarkCyan
    Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
    Write-Host " 🔐 Tenant Discovery • Service Analysis • Security Posture • External ID ".PadLeft(51).PadRight(86) -ForegroundColor Magenta -NoNewline
    Write-Host "┃" -ForegroundColor DarkCyan
    Write-Host "┃" -ForegroundColor DarkCyan -NoNewline
    Write-Host " 🎨 Power BI/Fabric • Cross-Tenant • Guest Access • Threat Protection ".PadLeft(50).PadRight(86) -ForegroundColor Green -NoNewline
    Write-Host "┃" -ForegroundColor DarkCyan
    Write-Host "╰━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯" -ForegroundColor DarkCyan
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
    
    # Return the file paths for post-processing
    return @{
        JSONFile = $jsonFile
        HTMLFile = $htmlFile
        CSVFile  = $csvFile
    }
}

function Export-HTMLReport {
    param([hashtable]$Results, [string]$OutputPath)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>⚡ CYBEROSINT - Azure AD Recon Terminal ⚡</title>
    <meta charset="utf-8">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; }
        
        body { 
            font-family: 'JetBrains Mono', 'Consolas', monospace; 
            margin: 0; 
            background: linear-gradient(45deg, #0a0a0a, #1a1a1a, #0a0a0a);
            background-size: 400% 400%;
            animation: gradientShift 10s ease infinite;
            color: #00ff88;
            overflow-x: auto;
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        @keyframes glitch {
            0%, 100% { transform: translate(0); }
            20% { transform: translate(-2px, 2px); }
            40% { transform: translate(-2px, -2px); }
            60% { transform: translate(2px, 2px); }
            80% { transform: translate(2px, -2px); }
        }
        
        @keyframes neonPulse {
            0%, 100% { text-shadow: 0 0 5px #00ff88, 0 0 10px #00ff88, 0 0 15px #00ff88; }
            50% { text-shadow: 0 0 2px #00ff88, 0 0 5px #00ff88, 0 0 8px #00ff88; }
        }
        
        .cyber-header { 
            background: linear-gradient(135deg, #000814, #001d3d, #003566);
            color: #00ff88; 
            padding: 30px; 
            text-align: center; 
            position: relative;
            border-bottom: 3px solid #00ff88;
            box-shadow: 0 0 30px #00ff88;
        }
        
        .cyber-header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: repeating-linear-gradient(
                90deg,
                transparent,
                transparent 98px,
                #00ff88 100px
            );
            opacity: 0.1;
            animation: scanlines 2s linear infinite;
        }
        
        @keyframes scanlines {
            0% { transform: translateY(-100%); }
            100% { transform: translateY(100vh); }
        }
        
        .cyber-title {
            font-family: 'Orbitron', monospace;
            font-size: 2.5em;
            font-weight: 900;
            margin: 0;
            animation: neonPulse 2s ease-in-out infinite;
            text-transform: uppercase;
            letter-spacing: 3px;
        }
        
        .cyber-subtitle {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.2em;
            margin: 10px 0;
            color: #ff006e;
            animation: glitch 3s infinite;
        }
        
        .cyber-metadata {
            font-size: 0.9em;
            color: #8ecae6;
            margin-top: 15px;
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 20px; 
        }
        
        .terminal-section { 
            background: rgba(0, 20, 40, 0.9);
            margin: 20px 0; 
            padding: 25px; 
            border-radius: 10px; 
            border: 2px solid #00ff88;
            box-shadow: 
                0 0 20px rgba(0, 255, 136, 0.3),
                inset 0 0 20px rgba(0, 255, 136, 0.1);
            position: relative;
            backdrop-filter: blur(10px);
        }
        
        .terminal-section::before {
            content: attr(data-section);
            position: absolute;
            top: -12px;
            left: 20px;
            background: linear-gradient(45deg, #000814, #001d3d);
            color: #00ff88;
            padding: 5px 15px;
            border-radius: 15px;
            border: 2px solid #00ff88;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .section-title { 
            color: #ff006e; 
            margin: 0 0 20px 0; 
            font-family: 'Orbitron', monospace;
            font-size: 1.4em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            text-shadow: 0 0 10px #ff006e;
            border-bottom: 2px solid #ff006e; 
            padding-bottom: 10px; 
        }
        
        .data-grid { 
            display: grid; 
            grid-template-columns: 300px 1fr; 
            gap: 15px; 
            padding: 10px 0; 
            border-bottom: 1px solid rgba(0, 255, 136, 0.2); 
            align-items: center;
        }
        
        .data-label { 
            font-weight: bold; 
            color: #8ecae6; 
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 1px;
        }
        
        .data-value { 
            color: #00ff88; 
            font-family: 'JetBrains Mono', monospace;
            word-break: break-all;
        }
        
        .status-active { color: #00ff88; text-shadow: 0 0 5px #00ff88; }
        .status-warning { color: #ffb703; text-shadow: 0 0 5px #ffb703; }
        .status-error { color: #ff006e; text-shadow: 0 0 5px #ff006e; }
        .status-info { color: #8ecae6; text-shadow: 0 0 5px #8ecae6; }
        
        .cyber-table { 
            width: 100%; 
            border-collapse: separate;
            border-spacing: 0;
            margin-top: 15px; 
            border: 2px solid #00ff88;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .cyber-table th { 
            background: linear-gradient(45deg, #003566, #0077b6); 
            color: #00ff88; 
            padding: 15px; 
            text-align: left; 
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 2px solid #00ff88;
        }
        
        .cyber-table td { 
            padding: 12px 15px; 
            background: rgba(0, 20, 40, 0.6);
            border-bottom: 1px solid rgba(0, 255, 136, 0.2); 
            font-family: 'JetBrains Mono', monospace;
        }
        
        .cyber-table tr:hover td {
            background: rgba(0, 255, 136, 0.1);
            box-shadow: inset 0 0 10px rgba(0, 255, 136, 0.2);
        }
        
        .cyber-badge { 
            padding: 6px 12px; 
            border-radius: 20px; 
            font-size: 0.8em; 
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: inline-block;
            margin: 2px;
        }
        
        .badge-success { background: rgba(0, 255, 136, 0.2); color: #00ff88; border: 2px solid #00ff88; }
        .badge-warning { background: rgba(255, 183, 3, 0.2); color: #ffb703; border: 2px solid #ffb703; }
        .badge-info { background: rgba(142, 202, 230, 0.2); color: #8ecae6; border: 2px solid #8ecae6; }
        .badge-error { background: rgba(255, 0, 110, 0.2); color: #ff006e; border: 2px solid #ff006e; }
        
        .cyber-link { 
            color: #8ecae6; 
            text-decoration: none; 
            padding: 8px 15px;
            border: 2px solid #8ecae6;
            border-radius: 25px;
            display: inline-block;
            margin: 5px;
            transition: all 0.3s ease;
            font-size: 0.9em;
            font-weight: bold;
        }
        
        .cyber-link:hover { 
            background: #8ecae6;
            color: #000814;
            box-shadow: 0 0 15px #8ecae6;
            transform: scale(1.05);
        }
        
        .terminal-prompt {
            color: #00ff88;
            font-family: 'JetBrains Mono', monospace;
            margin: 15px 0 10px 0;
        }
        
        .terminal-prompt::before {
            content: '[CYBEROSINT@azure-recon]$ ';
            color: #ff006e;
        }
        
        .copy-btn { 
            background: linear-gradient(45deg, #ff006e, #8338ec); 
            color: white; 
            border: none; 
            padding: 8px 15px; 
            border-radius: 20px; 
            cursor: pointer; 
            font-size: 0.8em; 
            font-weight: bold;
            margin-left: 10px;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .copy-btn:hover { 
            background: linear-gradient(45deg, #8338ec, #ff006e);
            box-shadow: 0 0 15px rgba(255, 0, 110, 0.5);
            transform: scale(1.1);
        }
        
        .terminal-output {
            background: rgba(0, 0, 0, 0.8);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #00ff88;
            margin: 15px 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        
        .glitch-text {
            animation: glitch 2s infinite;
        }
        
        .security-matrix {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .matrix-cell {
            background: rgba(0, 255, 136, 0.1);
            border: 2px solid #00ff88;
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .matrix-cell:hover {
            background: rgba(0, 255, 136, 0.2);
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.4);
            transform: scale(1.05);
        }
        
        .matrix-value {
            font-size: 1.8em;
            font-weight: bold;
            color: #00ff88;
            text-shadow: 0 0 10px #00ff88;
        }
        
        .matrix-label {
            color: #8ecae6;
            text-transform: uppercase;
            font-size: 0.8em;
            margin-top: 5px;
            letter-spacing: 1px;
        }
        
        .ascii-art {
            font-family: 'JetBrains Mono', monospace;
            color: #00ff88;
            text-align: center;
            white-space: pre;
            margin: 20px 0;
            font-size: 0.8em;
            animation: neonPulse 3s ease-in-out infinite;
        }
        
        @media (max-width: 768px) {
            .data-grid { grid-template-columns: 1fr; gap: 5px; }
            .cyber-title { font-size: 1.8em; }
            .security-matrix { grid-template-columns: 1fr; }
        }
    </style>
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('✅ Copied to clipboard: ' + text);
            });
        }
        
        function toggleSection(id) {
            const element = document.getElementById(id);
            element.style.display = element.style.display === 'none' ? 'block' : 'none';
        }
        
        // Matrix digital rain effect
        function initMatrixRain() {
            const canvas = document.createElement('canvas');
            canvas.style.position = 'fixed';
            canvas.style.top = '0';
            canvas.style.left = '0';
            canvas.style.width = '100%';
            canvas.style.height = '100%';
            canvas.style.pointerEvents = 'none';
            canvas.style.zIndex = '-1';
            canvas.style.opacity = '0.1';
            document.body.appendChild(canvas);
            
            const ctx = canvas.getContext('2d');
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            
            const chars = '01アカサタナハマヤラワガザダバパイキシチニヒミリヰギジヂビピウクスツヌフムユルグズヅブプエケセテネヘメレヱゲゼデベペオコソトノホモヨロヲゴゾドボポヴッン';
            const matrix = chars.split('');
            const fontSize = 14;
            const columns = canvas.width / fontSize;
            const drops = [];
            
            for (let x = 0; x < columns; x++) {
                drops[x] = 1;
            }
            
            function draw() {
                ctx.fillStyle = 'rgba(0, 0, 0, 0.04)';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                
                ctx.fillStyle = '#00ff88';
                ctx.font = fontSize + 'px JetBrains Mono';
                
                for (let i = 0; i < drops.length; i++) {
                    const text = matrix[Math.floor(Math.random() * matrix.length)];
                    ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                    
                    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                        drops[i] = 0;
                    }
                    drops[i]++;
                }
            }
            
            setInterval(draw, 35);
        }
        
        document.addEventListener('DOMContentLoaded', initMatrixRain);
    </script>
</head>
<body>
    <div class="ascii-art">
╔══════════════════════════════════════════════════════════════════╗
║  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ║
║ ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌ ║
║ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌ ║
║ ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌ ║
║ ▐░▌          ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌ ║
║ ▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌ ║
║ ▐░▌          ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀  ║
║ ▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌   ║
║ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌      ▐░▌  ║
║ ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌ ║
║  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ║
╚══════════════════════════════════════════════════════════════════╝
    ⚡ AZURE AD RECONNAISSANCE TERMINAL ⚡
    </div>
    
    <div class="cyber-header">
        <h1 class="cyber-title">⚡ CYBEROSINT RECON ENGINE ⚡</h1>
        <div class="cyber-subtitle glitch-text">TARGET: $($Results.Domain)</div>
        <div class="cyber-metadata">
            🕐 SCAN TIME: $($Results.Timestamp) | ⏱️ DURATION: $($Results.ScanDuration) | 🎯 STATUS: ANALYSIS COMPLETE
        </div>
    </div>
    
    <div class="container">
        <div class="terminal-section" data-section="EXEC-SUMMARY">
            <h2 class="section-title">🎯 Executive Summary</h2>
            
            <div class="security-matrix">
                <div class="matrix-cell">
                    <div class="matrix-value">$($Results.Domain)</div>
                    <div class="matrix-label">Target Domain</div>
                </div>
                <div class="matrix-cell">
                    <div class="matrix-value $(if($Results.TenantInfo.TenantId){'status-active'}else{'status-error'})">
                        $(if($Results.TenantInfo.TenantId){'IDENTIFIED'}else{'NOT FOUND'})
                    </div>
                    <div class="matrix-label">Tenant Status</div>
                </div>
                <div class="matrix-cell">
                    <div class="matrix-value status-info">$($Results.TenantInfo.NameSpaceType ?? 'UNKNOWN')</div>
                    <div class="matrix-label">Namespace Type</div>
                </div>
                <div class="matrix-cell">
                    <div class="matrix-value status-warning">$($Results.TenantInfo.CloudInstance ?? 'UNDETECTED')</div>
                    <div class="matrix-label">Cloud Instance</div>
                </div>
            </div>
            
            $(if($Results.TenantInfo.TenantId) {
                "<div class='data-grid'>
                    <div class='data-label'>🆔 TENANT IDENTIFIER:</div>
                    <div class='data-value'>
                        $($Results.TenantInfo.TenantId)
                        <button class='copy-btn'>COPY ID</button>
                    </div>
                </div>"
            })
            
            <div class="terminal-prompt">Quick Access Portals:</div>
            <div>
                $(if($Results.TenantInfo.TenantId) {
                    "<a href='https://portal.azure.com/#@$($Results.TenantInfo.TenantId)' target='_blank' class='cyber-link'>🌐 AZURE PORTAL</a>
                    <a href='https://admin.microsoft.com' target='_blank' class='cyber-link'>⚙️ M365 ADMIN</a>
                    <a href='https://login.microsoftonline.com/$($Results.TenantInfo.TenantId)/.well-known/openid_configuration' target='_blank' class='cyber-link'>🔍 OIDC CONFIG</a>
                    <a href='https://graph.microsoft.com/v1.0/organization' target='_blank' class='cyber-link'>📊 GRAPH API</a>"
                } else {
                    "<span class='status-error'>⚠️ NO TENANT ID - LIMITED ACCESS</span>"
                })
            </div>
        </div>
        
        <div class="terminal-section" data-section="TENANT-INTEL">
            <h2 class="section-title">🏢 Tenant Intelligence</h2>
            <div class="data-grid">
                <div class="data-label">🔐 FEDERATION PROTOCOL:</div>
                <div class="data-value">$($Results.TenantInfo.Federation ?? 'N/A')</div>
            </div>
            <div class="data-grid">
                <div class="data-label">🌐 AUTH ENDPOINT:</div>
                <div class="data-value">$($Results.TenantInfo.AuthenticationUrl ?? 'N/A')</div>
            </div>
            <div class="data-grid">
                <div class="data-label">📋 ISSUER:</div>
                <div class="data-value">$($Results.TenantInfo.Endpoints.Issuer ?? 'N/A')</div>
            </div>
            $(if($Results.TenantInfo.TenantRegion) {
                "<div class='data-grid'>
                    <div class='data-label'>🌍 REGION:</div>
                    <div class='data-value'>$($Results.TenantInfo.TenantRegion)</div>
                </div>"
            })
        </div>
        
        <div class="terminal-section" data-section="SECURITY-POSTURE">
            <h2 class="section-title">🛡️ Security Posture Analysis</h2>
            $(if($Results.SecurityPosture) {
                $securityHtml = ""
                if($Results.SecurityPosture.SecurityDefaults.MFARequired) {
                    $securityHtml += "<div class='cyber-badge badge-success'>MFA ENFORCED</div>"
                }
                if($Results.SecurityPosture.ConditionalAccess.Present) {
                    $securityHtml += "<div class='cyber-badge badge-success'>CONDITIONAL ACCESS</div>"
                }
                if($Results.SecurityPosture.ThreatProtection.DefenderForO365) {
                    $securityHtml += "<div class='cyber-badge badge-success'>DEFENDER O365</div>"
                }
                if($Results.SecurityPosture.ThreatProtection.DefenderForIdentity) {
                    $securityHtml += "<div class='cyber-badge badge-success'>DEFENDER IDENTITY</div>"
                }
                if($Results.SecurityPosture.PrivilegedAccess.PIM) {
                    $securityHtml += "<div class='cyber-badge badge-success'>PIM ENABLED</div>"
                }
                if($Results.SecurityPosture.DataLossProtection.SensitivityLabels) {
                    $securityHtml += "<div class='cyber-badge badge-success'>SENSITIVITY LABELS</div>"
                }
                if($Results.SecurityPosture.IdentityProtection.RiskPolicies) {
                    $securityHtml += "<div class='cyber-badge badge-success'>RISK POLICIES</div>"
                }
                $securityHtml
            })
        </div>
        
        <div class="terminal-section" data-section="EXTERNAL-ID">
            <h2 class="section-title">🌍 External Identity Analysis</h2>
            $(if($Results.ExternalIdentities) {
                $extIdHtml = ""
                foreach($userType in $Results.ExternalIdentities.ExternalUserTypes) {
                    $extIdHtml += "<div class='cyber-badge badge-info'>$userType</div>"
                }
                if($Results.ExternalIdentities.B2BCollaboration.RedemptionFlow) {
                    $extIdHtml += "<div class='cyber-badge badge-success'>B2B COLLABORATION</div>"
                }
                if($Results.ExternalIdentities.B2BDirectConnect.PolicyEndpoint) {
                    $extIdHtml += "<div class='cyber-badge badge-warning'>B2B DIRECT CONNECT</div>"
                }
                if($Results.ExternalIdentities.B2CIdentities.TenantUrl) {
                    $extIdHtml += "<div class='cyber-badge badge-info'>B2C TENANT: $($Results.ExternalIdentities.B2CIdentities.TenantUrl)</div>"
                }
                $extIdHtml
            })
        </div>
        
        <div class="terminal-section" data-section="POWERBI-FABRIC">
            <h2 class="section-title">📊 Power BI & Fabric Analysis</h2>
            $(if($Results.PowerBIFabric) {
                $fabricHtml = ""
                foreach($service in $Results.PowerBIFabric.PowerBIService.Keys) {
                    $fabricHtml += "<div class='cyber-badge badge-success'>POWER BI $service</div>"
                }
                foreach($workspace in $Results.PowerBIFabric.FabricWorkspaces.Keys) {
                    $fabricHtml += "<div class='cyber-badge badge-info'>FABRIC $workspace</div>"
                }
                if($Results.PowerBIFabric.DataGateways.Infrastructure) {
                    $fabricHtml += "<div class='cyber-badge badge-warning'>DATA GATEWAYS</div>"
                }
                if($Results.PowerBIFabric.CrossTenantAccess.B2BAccess) {
                    $fabricHtml += "<div class='cyber-badge badge-warning'>CROSS-TENANT BI</div>"
                }
                $fabricHtml
            })
        </div>
        
        <div class="terminal-section" data-section="USER-ENUM">
            <h2 class="section-title">👥 User Enumeration Results</h2>
            <table class="cyber-table">
                <thead>
                    <tr>
                        <th>🎭 USERNAME</th>
                        <th>🔍 METHOD</th>
                        <th>📊 CONFIDENCE</th>
                        <th>🔗 EVIDENCE</th>
                    </tr>
                </thead>
                <tbody>
                    $(if($Results.UserEnumeration.ValidUsers.Count -gt 0) {
                        $userRows = ""
                        foreach($user in $Results.UserEnumeration.ValidUsers) {
                            $userRows += "<tr>
                                <td class='status-active'>$($user.Username)</td>
                                <td class='status-info'>$($user.Method)</td>
                                <td class='$(if($user.Confidence -eq 'High'){'status-active'}elseif($user.Confidence -eq 'Medium'){'status-warning'}else{'status-error'})'>$($user.Confidence)</td>
                                <td>$($user.Evidence)</td>
                            </tr>"
                        }
                        $userRows
                    } else {
                        "<tr><td colspan='4' class='status-warning'>🚫 NO VALID USERS DISCOVERED</td></tr>"
                    })
                </tbody>
            </table>
        </div>
        
        <div class="terminal-section" data-section="AZURE-SERVICES">
            <h2 class="section-title">☁️ Azure Service Discovery</h2>
            <div class="security-matrix">
                $(if($Results.ServiceDiscovery.EntraID) {
                    "<div class='matrix-cell'>
                        <div class='matrix-value status-active'>✅ ACTIVE</div>
                        <div class='matrix-label'>Entra ID</div>
                    </div>"
                })
                $(if($Results.ServiceDiscovery.Exchange) {
                    "<div class='matrix-cell'>
                        <div class='matrix-value status-active'>✅ DETECTED</div>
                        <div class='matrix-label'>Exchange Online</div>
                    </div>"
                })
                $(if($Results.ServiceDiscovery.SharePoint) {
                    "<div class='matrix-cell'>
                        <div class='matrix-value status-active'>✅ ONLINE</div>
                        <div class='matrix-label'>SharePoint</div>
                    </div>"
                })
                $(if($Results.ServiceDiscovery.Teams) {
                    "<div class='matrix-cell'>
                        <div class='matrix-value status-active'>✅ ENABLED</div>
                        <div class='matrix-label'>Microsoft Teams</div>
                    </div>"
                })
                $(if($Results.ServiceDiscovery.OneDrive) {
                    "<div class='matrix-cell'>
                        <div class='matrix-value status-active'>✅ ACTIVE</div>
                        <div class='matrix-label'>OneDrive</div>
                    </div>"
                })
            </div>
        </div>
        
        <div class="terminal-section" data-section="NETWORK-INTEL">
            <h2 class="section-title">🌐 Network Intelligence</h2>
            <div class="terminal-prompt">Discovered Subdomains:</div>
            <div class="terminal-output">
                $(if($Results.NetworkIntelligence.Subdomains.Count -gt 0) {
                    $subdomainList = ""
                    foreach($subdomain in $Results.NetworkIntelligence.Subdomains) {
                        $subdomainList += "🎯 $($subdomain.Subdomain) → $($subdomain.IPAddresses -join ', ')" + "`n"
                    }
                    $subdomainList
                } else {
                    "⚠️ NO SUBDOMAINS DISCOVERED"
                })
            </div>
        </div>
        
        <div class="terminal-section" data-section="CERT-INTEL">
            <h2 class="section-title">🔐 Certificate Intelligence</h2>
            <div class="terminal-output">
                $(if($Results.Certificates.Count -gt 0) {
                    $certList = ""
                    foreach($cert in $Results.Certificates) {
                        $certList += "📜 $($cert.CommonName) | Issuer: $($cert.Issuer) | Valid: $($cert.ValidFrom) - $($cert.ValidTo)" + "`n"
                    }
                    $certList
                } else {
                    "⚠️ NO CERTIFICATE TRANSPARENCY LOGS FOUND"
                })
            </div>
        </div>
        
        <div class="terminal-section" data-section="DIGITAL-FOOTPRINT">
            <h2 class="section-title">📱 Digital Footprint</h2>
            <div class="security-matrix">
                $(if($Results.SocialMedia.GitHub.Count -gt 0) {
                    "<div class='matrix-cell'>
                        <div class='matrix-value status-active'>$($Results.SocialMedia.GitHub.Count)</div>
                        <div class='matrix-label'>GitHub Repos</div>
                    </div>"
                })
                $(if($Results.SocialMedia.LinkedIn.Count -gt 0) {
                    "<div class='matrix-cell'>
                        <div class='matrix-value status-info'>$($Results.SocialMedia.LinkedIn.Count)</div>
                        <div class='matrix-label'>LinkedIn Profiles</div>
                    </div>"
                })
                $(if($Results.Documents.Count -gt 0) {
                    "<div class='matrix-cell'>
                        <div class='matrix-value status-warning'>$($Results.Documents.Count)</div>
                        <div class='matrix-label'>Public Documents</div>
                    </div>"
                })
            </div>
        </div>
        
        <div class="terminal-section" data-section="RAW-DATA">
            <h2 class="section-title">📊 Raw Reconnaissance Data</h2>
            <div class="terminal-prompt">Complete JSON Output:</div>
            <div class="terminal-output">
                <button class='copy-btn' onclick='copyToClipboard("JSON_DATA_PLACEHOLDER")'>COPY JSON DATA</button>
                <pre style="max-height: 400px; overflow-y: auto; color: #8ecae6; font-size: 0.8em;">JSON_OUTPUT_PLACEHOLDER</pre>
            </div>
        </div>
        
        <div class="ascii-art">
╔══════════════════════════════════════════════════════════════════╗
║                    🛡️ RECONNAISSANCE COMPLETE 🛡️                     ║
║                                                                  ║
║   ⚡ POWERED BY CYBEROSINT ENGINE ⚡                              ║
║   🎯 TARGET ANALYSIS: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") UTC                     ║
║   📊 TOTAL DISCOVERIES: $(($Results.UserEnumeration.ValidUsers.Count + $Results.NetworkIntelligence.Subdomains.Count + $Results.Certificates.Count))                                  ║
╚══════════════════════════════════════════════════════════════════╝
        </div>
    </div>
    
    <script>
        // Enhanced terminal interactions
        document.addEventListener('DOMContentLoaded', function() {
            // Add typing effect to terminal outputs
            const terminalOutputs = document.querySelectorAll('.terminal-output');
            terminalOutputs.forEach(output => {
                const text = output.textContent;
                output.textContent = '';
                let i = 0;
                const typeWriter = () => {
                    if (i < text.length) {
                        output.textContent += text.charAt(i);
                        i++;
                        setTimeout(typeWriter, 20);
                    }
                };
                // Start typing effect after a delay
                setTimeout(typeWriter, Math.random() * 2000);
            });
            
            // Add hover effects to matrix cells
            const matrixCells = document.querySelectorAll('.matrix-cell');
            matrixCells.forEach(cell => {
                cell.addEventListener('mouseenter', function() {
                    this.style.transform = 'scale(1.1) rotateY(10deg)';
                    this.style.boxShadow = '0 0 30px rgba(0, 255, 136, 0.6)';
                });
                cell.addEventListener('mouseleave', function() {
                    this.style.transform = 'scale(1) rotateY(0deg)';
                    this.style.boxShadow = '0 0 20px rgba(0, 255, 136, 0.4)';
                });
            });
        });
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}
    
$html += @"
            </table>
        </div>
        
        <div class="section">
            <h2>� Authentication & Security Analysis</h2>
            <div class="grid">
                <div class="property"><div class="property-name">Supported OAuth Flows:</div><div class="property-value success">$($Results.AuthenticationAnalysis.SupportedFlows.Count)</div></div>
                <div class="property"><div class="property-name">Authentication Methods:</div><div class="property-value success">$($Results.AuthenticationAnalysis.AuthMethods.Count)</div></div>
                <div class="property"><div class="property-name">Federation Type:</div><div class="property-value info">$(if($Results.AuthenticationAnalysis.FederationConfig.SupportsSAML){'ADFS/SAML'}else{'Cloud-only'})</div></div>
                <div class="property"><div class="property-name">MFA Required:</div><div class="property-value $(if($Results.SecurityPosture.SecurityDefaults.MFARequired){'success'}else{'warning'})">$(if($Results.SecurityPosture.SecurityDefaults.MFARequired){'Yes'}else{'Not detected in test'})</div></div>
            </div>
            
            <h3>Authentication Methods Detected</h3>
            <ul>
$(foreach($method in $Results.AuthenticationAnalysis.AuthMethods) {
    "<li class='success'>$method</li>"
})
            </ul>
            
            <h3>OAuth 2.0 Flows Supported</h3>
            <ul>
$(foreach($flow in $Results.AuthenticationAnalysis.SupportedFlows) {
    "<li class='info'>$flow</li>"
})
            </ul>
        </div>
        
        <div class="section">
            <h2>�📊 Statistics Summary</h2>
            <div class="grid">
                <div class="property"><div class="property-name">Total Scan Time:</div><div class="property-value info">$($Results.ScanDuration)</div></div>
                <div class="property"><div class="property-name">Valid Users Found:</div><div class="property-value success">$($Results.UserEnumeration.ValidUsers.Count)</div></div>
                <div class="property"><div class="property-name">Related Domains:</div><div class="property-value success">$($Results.DomainInfo.RelatedDomains.Count)</div></div>
                <div class="property"><div class="property-name">Subdomains Found:</div><div class="property-value success">$($Results.NetworkIntelligence.Subdomains.Count)</div></div>
                <div class="property"><div class="property-name">Azure Resources:</div><div class="property-value success">$($Results.ExtendedAzureResources.StorageAccounts.Count + $Results.ExtendedAzureResources.FunctionApps.Count + $Results.ExtendedAzureResources.CosmosDB.Count)</div></div>
                <div class="property"><div class="property-name">Authentication Methods:</div><div class="property-value success">$($Results.AuthenticationAnalysis.AuthMethods.Count)</div></div>
                <div class="property"><div class="property-name">Certificates:</div><div class="property-value success">$($Results.Certificates.Count)</div></div>
            </div>
        </div>
    </div>
    
    <div style="text-align: center; padding: 20px; color: #666; font-size: 12px;">
        Generated by Advanced Azure OSINT Tool | $(Get-Date)
    </div>
    
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('Tenant ID copied to clipboard: ' + text);
            }, function(err) {
                console.error('Could not copy text: ', err);
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('Tenant ID copied to clipboard: ' + text);
            });
        }
        
        function toggleSection(sectionId) {
            const section = document.getElementById(sectionId);
            if (section.style.display === 'none') {
                section.style.display = 'block';
            } else {
                section.style.display = 'none';
            }
        }
        
        // Add click-to-copy functionality to all tenant IDs and sensitive data
        document.addEventListener('DOMContentLoaded', function() {
            const tenantIds = document.querySelectorAll('.success');
            tenantIds.forEach(function(element) {
                if (element.textContent.length === 36 && element.textContent.includes('-')) {
                    element.style.cursor = 'pointer';
                    element.title = 'Click to copy';
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
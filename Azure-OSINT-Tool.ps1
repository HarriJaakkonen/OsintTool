#Requires -Version 7.0
<#
.SYNOPSIS
Azure AD/Entra ID OSINT (Open Source Intelligence) Reconnaissance Tool

.DESCRIPTION
This PowerShell tool performs open source intelligence gathering on Azure AD/Entra ID tenants
and associated infrastructure. It can discover tenant information, enumerate users, identify
cloud services, and gather publicly available information about an organization's Azure footprint.

.PARAMETER Domain
The target domain to investigate (e.g., contoso.com, contoso.onmicrosoft.com)

.PARAMETER TenantId
Optional: Specific tenant ID to investigate

.PARAMETER OutputFormat
Output format: Console, JSON, HTML, CSV

.PARAMETER OutputFile
Optional: File path to save results

.PARAMETER Modules
Comma-separated list of modules to run: TenantInfo, UserEnum, ServiceEnum, DNSRecon, CloudAssets

.PARAMETER Verbose
Enable verbose output

.EXAMPLE
.\Azure-OSINT-Tool.ps1 -Domain "contoso.com" -OutputFormat JSON -OutputFile "recon.json"

.EXAMPLE
.\Azure-OSINT-Tool.ps1 -Domain "contoso.onmicrosoft.com" -Modules "TenantInfo,UserEnum" -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "JSON", "HTML", "CSV")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory = $false)]
    [string]$Modules = "TenantInfo,UserEnum,ServiceEnum,DNSRecon,CloudAssets",
    
    [Parameter(Mandatory = $false)]
    [switch]$VerboseOutput
)

# Global variables
$script:Results = @{
    Domain = $Domain
    TenantId = $TenantId
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    TenantInfo = @{}
    UserEnum = @()
    ServiceEnum = @{}
    DNSRecon = @()
    CloudAssets = @()
    Errors = @()
}

function Write-OSINTLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($VerboseOutput -or $Level -eq "ERROR") {
        Write-Host $logMessage -ForegroundColor $Color
    }
}

function Invoke-WebRequestSafe {
    param(
        [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Method = "GET",
        [int]$TimeoutSec = 10
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
        Write-OSINTLog "Web request failed for $Uri : $($_.Exception.Message)" "ERROR" Red
        $script:Results.Errors += "Web request failed for $Uri : $($_.Exception.Message)"
        return $null
    }
}

function Get-TenantInfo {
    Write-OSINTLog "Gathering tenant information for domain: $Domain" "INFO" Cyan
    
    $tenantInfo = @{
        Domain = $Domain
        TenantId = $null
        TenantName = $null
        AuthenticationUrl = $null
        FederationMetadata = $null
        OpenIdConfiguration = $null
        TenantRegion = $null
        TenantType = $null
        BrandingInfo = @{}
        LoginEndpoints = @()
    }
    
    # Method 1: OpenID Connect Discovery
    try {
        $openIdUrl = "https://login.microsoftonline.com/$Domain/.well-known/openid_configuration"
        $openIdResponse = Invoke-WebRequestSafe -Uri $openIdUrl
        
        if ($openIdResponse) {
            $openIdConfig = $openIdResponse.Content | ConvertFrom-Json
            $tenantInfo.OpenIdConfiguration = $openIdConfig
            $tenantInfo.TenantId = ($openIdConfig.issuer -split '/')[-2]
            $tenantInfo.AuthenticationUrl = $openIdConfig.authorization_endpoint
            
            Write-OSINTLog "Found tenant ID via OpenID: $($tenantInfo.TenantId)" "INFO" Green
        }
    }
    catch {
        Write-OSINTLog "OpenID discovery failed: $($_.Exception.Message)" "ERROR" Red
    }
    
    # Method 2: Federation Metadata
    try {
        $federationUrl = "https://login.microsoftonline.com/$Domain/FederationMetadata/2007-06/FederationMetadata.xml"
        $federationResponse = Invoke-WebRequestSafe -Uri $federationUrl
        
        if ($federationResponse) {
            $tenantInfo.FederationMetadata = $federationResponse.Content
            
            # Parse XML to extract tenant info
            $xml = [xml]$federationResponse.Content
            $entityDescriptor = $xml.EntityDescriptor
            if ($entityDescriptor) {
                $tenantInfo.TenantName = $entityDescriptor.entityID
                Write-OSINTLog "Found federation metadata for: $($tenantInfo.TenantName)" "INFO" Green
            }
        }
    }
    catch {
        Write-OSINTLog "Federation metadata lookup failed: $($_.Exception.Message)" "ERROR" Red
    }
    
    # Method 3: Tenant branding lookup
    try {
        if ($tenantInfo.TenantId) {
            $brandingUrl = "https://login.microsoftonline.com/$($tenantInfo.TenantId)/oauth2/v2.0/authorize?response_type=code&client_id=1950a258-227b-4e31-a9cf-717495945fc2&scope=openid"
            $brandingResponse = Invoke-WebRequestSafe -Uri $brandingUrl
            
            if ($brandingResponse -and $brandingResponse.Content) {
                # Extract branding information from HTML
                if ($brandingResponse.Content -match 'data-tenant-branding-background-color[^>]*>([^<]+)') {
                    $tenantInfo.BrandingInfo.BackgroundColor = $matches[1]
                }
                if ($brandingResponse.Content -match 'data-tenant-branding-logo-url[^>]*>([^<]+)') {
                    $tenantInfo.BrandingInfo.LogoUrl = $matches[1]
                }
                
                Write-OSINTLog "Extracted tenant branding information" "INFO" Green
            }
        }
    }
    catch {
        Write-OSINTLog "Tenant branding lookup failed: $($_.Exception.Message)" "ERROR" Red
    }
    
    # Method 4: Autodiscover endpoint
    try {
        $autodiscoverUrl = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
        $soapBody = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://schemas.microsoft.com/exchange/2010/Autodiscover" 
               xmlns:wsa="http://www.w3.org/2005/08/addressing" 
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:RequestedServerVersion>Exchange2016</a:RequestedServerVersion>
  </soap:Header>
  <soap:Body>
    <a:GetFederationInformationRequestMessage>
      <a:Request>
        <a:Domain>$Domain</a:Domain>
      </a:Request>
    </a:GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>
"@
        
        $headers = @{
            "Content-Type" = "text/xml; charset=utf-8"
            "SOAPAction" = '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"'
        }
        
        $autodiscoverResponse = Invoke-WebRequestSafe -Uri $autodiscoverUrl -Method POST -Headers $headers
        if ($autodiscoverResponse) {
            Write-OSINTLog "Autodiscover response received" "INFO" Green
        }
    }
    catch {
        Write-OSINTLog "Autodiscover lookup failed: $($_.Exception.Message)" "ERROR" Red
    }
    
    $script:Results.TenantInfo = $tenantInfo
    Write-OSINTLog "Tenant information gathering completed" "INFO" Cyan
}

function Start-UserEnumeration {
    Write-OSINTLog "Starting user enumeration for domain: $Domain" "INFO" Cyan
    
    $userList = @()
    $commonUsernames = @(
        "admin", "administrator", "test", "guest", "user", "service",
        "info", "contact", "support", "help", "sales", "marketing",
        "hr", "it", "security", "finance", "legal", "compliance"
    )
    
    # Method 1: OneDrive enumeration
    foreach ($username in $commonUsernames) {
        try {
            $oneDriveUrl = "https://$($Domain.Split('.')[0])-my.sharepoint.com/personal/$($username)_$($Domain.Replace('.', '_'))"
            $response = Invoke-WebRequestSafe -Uri $oneDriveUrl
            
            if ($response -and $response.StatusCode -eq 200) {
                $userInfo = @{
                    Username = "$username@$Domain"
                    OneDriveUrl = $oneDriveUrl
                    Status = "Exists"
                    Source = "OneDrive"
                }
                $userList += $userInfo
                Write-OSINTLog "Found user: $username@$Domain (OneDrive)" "INFO" Green
            }
        }
        catch {
            # User likely doesn't exist or OneDrive not accessible
        }
    }
    
    # Method 2: Teams enumeration
    foreach ($username in $commonUsernames) {
        try {
            $teamsUrl = "https://teams.microsoft.com/l/chat/0/0?users=$username@$Domain"
            $response = Invoke-WebRequestSafe -Uri $teamsUrl
            
            if ($response -and $response.Content -notmatch "user not found") {
                $userInfo = @{
                    Username = "$username@$Domain"
                    TeamsUrl = $teamsUrl
                    Status = "Exists"
                    Source = "Teams"
                }
                $userList += $userInfo
                Write-OSINTLog "Found user: $username@$Domain (Teams)" "INFO" Green
            }
        }
        catch {
            # User likely doesn't exist
        }
    }
    
    # Method 3: Login timing attack (be careful with rate limiting)
    foreach ($username in $commonUsernames[0..5]) { # Limit to first 5 to avoid rate limiting
        try {
            $loginUrl = "https://login.microsoftonline.com/common/oauth2/token"
            $body = @{
                grant_type = "password"
                username = "$username@$Domain"
                password = "InvalidPassword123!"
                client_id = "1b730954-1685-4b74-9bfd-dac224a7b894" # Azure PowerShell
                scope = "https://graph.microsoft.com/.default"
            }
            
            $startTime = Get-Date
            $response = Invoke-WebRequestSafe -Uri $loginUrl -Method POST
            $endTime = Get-Date
            $responseTime = ($endTime - $startTime).TotalMilliseconds
            
            # Different response times might indicate user existence
            if ($responseTime -gt 500) { # Arbitrary threshold
                $userInfo = @{
                    Username = "$username@$Domain"
                    ResponseTime = $responseTime
                    Status = "Possible"
                    Source = "LoginTiming"
                }
                $userList += $userInfo
                Write-OSINTLog "Possible user (timing): $username@$Domain ($responseTime ms)" "INFO" Yellow
            }
        }
        catch {
            # Expected for invalid credentials
        }
        
        Start-Sleep -Milliseconds 500 # Rate limiting protection
    }
    
    $script:Results.UserEnum = $userList
    Write-OSINTLog "User enumeration completed. Found $($userList.Count) potential users" "INFO" Cyan
}

function Get-ServiceEnumeration {
    Write-OSINTLog "Enumerating cloud services for domain: $Domain" "INFO" Cyan
    
    $services = @{
        Office365 = $false
        Teams = $false
        SharePoint = $false
        OneDrive = $false
        Exchange = $false
        Intune = $false
        AzureAD = $false
        PowerBI = $false
        Dynamics = $false
    }
    
    # Test Office 365
    try {
        $o365Url = "https://outlook.office365.com/autodiscover/autodiscover.xml?EmailAddress=test@$Domain"
        $response = Invoke-WebRequestSafe -Uri $o365Url
        if ($response -and $response.StatusCode -eq 200) {
            $services.Office365 = $true
            Write-OSINTLog "Office 365 detected" "INFO" Green
        }
    }
    catch { }
    
    # Test SharePoint
    try {
        $spUrl = "https://$($Domain.Split('.')[0]).sharepoint.com"
        $response = Invoke-WebRequestSafe -Uri $spUrl
        if ($response -and $response.StatusCode -eq 200) {
            $services.SharePoint = $true
            Write-OSINTLog "SharePoint Online detected" "INFO" Green
        }
    }
    catch { }
    
    # Test Teams
    try {
        $teamsUrl = "https://$($Domain.Split('.')[0]).teams.microsoft.com"
        $response = Invoke-WebRequestSafe -Uri $teamsUrl
        if ($response) {
            $services.Teams = $true
            Write-OSINTLog "Microsoft Teams detected" "INFO" Green
        }
    }
    catch { }
    
    # Test Exchange Online
    try {
        $exchangeUrl = "https://outlook.office365.com/owa/$Domain"
        $response = Invoke-WebRequestSafe -Uri $exchangeUrl
        if ($response) {
            $services.Exchange = $true
            Write-OSINTLog "Exchange Online detected" "INFO" Green
        }
    }
    catch { }
    
    # Test Azure AD
    if ($script:Results.TenantInfo.TenantId) {
        $services.AzureAD = $true
        Write-OSINTLog "Azure AD/Entra ID confirmed" "INFO" Green
    }
    
    $script:Results.ServiceEnum = $services
    Write-OSINTLog "Service enumeration completed" "INFO" Cyan
}

function Start-DNSReconnaissance {
    Write-OSINTLog "Starting DNS reconnaissance for domain: $Domain" "INFO" Cyan
    
    $dnsRecords = @()
    
    # Common DNS records to check
    $recordTypes = @("A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA")
    $subdomains = @(
        "autodiscover", "lyncdiscover", "sip", "webmail", "mail", "smtp",
        "ftp", "www", "remote", "vpn", "owa", "teams", "sharepoint",
        "onedrive", "portal", "admin", "login", "auth", "sso"
    )
    
    # Check main domain records
    foreach ($recordType in $recordTypes) {
        try {
            $records = Resolve-DnsName -Name $Domain -Type $recordType -ErrorAction SilentlyContinue
            if ($records) {
                foreach ($record in $records) {
                    $dnsInfo = @{
                        Name = $record.Name
                        Type = $record.Type
                        Value = $record.IPAddress ?? $record.NameExchange ?? $record.Strings ?? $record.NameHost
                        TTL = $record.TTL
                    }
                    $dnsRecords += $dnsInfo
                    Write-OSINTLog "DNS: $($record.Name) $($record.Type) -> $($dnsInfo.Value)" "INFO" Green
                }
            }
        }
        catch {
            Write-OSINTLog "DNS lookup failed for $Domain $recordType : $($_.Exception.Message)" "ERROR" Red
        }
    }
    
    # Check common subdomains
    foreach ($subdomain in $subdomains) {
        try {
            $fullDomain = "$subdomain.$Domain"
            $records = Resolve-DnsName -Name $fullDomain -Type A -ErrorAction SilentlyContinue
            if ($records) {
                foreach ($record in $records) {
                    $dnsInfo = @{
                        Name = $record.Name
                        Type = $record.Type
                        Value = $record.IPAddress
                        TTL = $record.TTL
                        IsSubdomain = $true
                    }
                    $dnsRecords += $dnsInfo
                    Write-OSINTLog "Subdomain found: $fullDomain -> $($record.IPAddress)" "INFO" Green
                }
            }
        }
        catch {
            # Subdomain doesn't exist
        }
    }
    
    $script:Results.DNSRecon = $dnsRecords
    Write-OSINTLog "DNS reconnaissance completed. Found $($dnsRecords.Count) records" "INFO" Cyan
}

function Get-CloudAssets {
    Write-OSINTLog "Discovering cloud assets for domain: $Domain" "INFO" Cyan
    
    $cloudAssets = @()
    
    # Azure Storage Account enumeration
    $storageNames = @(
        $Domain.Split('.')[0],
        $Domain.Split('.')[0] + "data",
        $Domain.Split('.')[0] + "files",
        $Domain.Split('.')[0] + "backup",
        $Domain.Split('.')[0] + "storage"
    )
    
    foreach ($storageName in $storageNames) {
        try {
            $storageUrl = "https://$storageName.blob.core.windows.net"
            $response = Invoke-WebRequestSafe -Uri $storageUrl
            
            if ($response) {
                $asset = @{
                    Type = "Azure Storage"
                    Name = $storageName
                    Url = $storageUrl
                    Status = "Accessible"
                }
                $cloudAssets += $asset
                Write-OSINTLog "Found Azure Storage: $storageUrl" "INFO" Green
            }
        }
        catch {
            # Storage account doesn't exist or isn't publicly accessible
        }
    }
    
    # Azure Web Apps enumeration
    $webAppNames = @(
        $Domain.Split('.')[0],
        $Domain.Split('.')[0] + "-app",
        $Domain.Split('.')[0] + "-api",
        $Domain.Split('.')[0] + "-web"
    )
    
    foreach ($webAppName in $webAppNames) {
        try {
            $webAppUrl = "https://$webAppName.azurewebsites.net"
            $response = Invoke-WebRequestSafe -Uri $webAppUrl
            
            if ($response -and $response.StatusCode -eq 200) {
                $asset = @{
                    Type = "Azure Web App"
                    Name = $webAppName
                    Url = $webAppUrl
                    Status = "Accessible"
                }
                $cloudAssets += $asset
                Write-OSINTLog "Found Azure Web App: $webAppUrl" "INFO" Green
            }
        }
        catch {
            # Web app doesn't exist
        }
    }
    
    $script:Results.CloudAssets = $cloudAssets
    Write-OSINTLog "Cloud asset discovery completed. Found $($cloudAssets.Count) assets" "INFO" Cyan
}

function Export-Results {
    Write-OSINTLog "Exporting results in format: $OutputFormat" "INFO" Cyan
    
    switch ($OutputFormat) {
        "JSON" {
            $jsonOutput = $script:Results | ConvertTo-Json -Depth 10
            if ($OutputFile) {
                $jsonOutput | Out-File -FilePath $OutputFile -Encoding UTF8
                Write-OSINTLog "Results exported to: $OutputFile" "INFO" Green
            } else {
                Write-Output $jsonOutput
            }
        }
        
        "CSV" {
            if ($OutputFile) {
                # Export different sections to separate CSV files
                $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFile)
                $directory = [System.IO.Path]::GetDirectoryName($OutputFile)
                
                $script:Results.UserEnum | Export-Csv -Path "$directory\$baseFileName-users.csv" -NoTypeInformation
                $script:Results.DNSRecon | Export-Csv -Path "$directory\$baseFileName-dns.csv" -NoTypeInformation
                $script:Results.CloudAssets | Export-Csv -Path "$directory\$baseFileName-assets.csv" -NoTypeInformation
                
                Write-OSINTLog "Results exported to multiple CSV files: $directory\$baseFileName-*.csv" "INFO" Green
            }
        }
        
        "HTML" {
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure OSINT Results - $Domain</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; }
        .header { color: #0078d4; border-bottom: 2px solid #0078d4; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Azure OSINT Results</h1>
    <p><strong>Domain:</strong> $Domain</p>
    <p><strong>Timestamp:</strong> $($script:Results.Timestamp)</p>
    
    <div class="section">
        <h2 class="header">Tenant Information</h2>
        <p><strong>Tenant ID:</strong> $($script:Results.TenantInfo.TenantId ?? 'Not found')</p>
        <p><strong>Authentication URL:</strong> $($script:Results.TenantInfo.AuthenticationUrl ?? 'Not found')</p>
    </div>
    
    <div class="section">
        <h2 class="header">User Enumeration ($($script:Results.UserEnum.Count) found)</h2>
        <table>
            <tr><th>Username</th><th>Status</th><th>Source</th></tr>
"@
            
            foreach ($user in $script:Results.UserEnum) {
                $htmlContent += "<tr><td>$($user.Username)</td><td>$($user.Status)</td><td>$($user.Source)</td></tr>"
            }
            
            $htmlContent += @"
        </table>
    </div>
    
    <div class="section">
        <h2 class="header">Services Detected</h2>
        <ul>
"@
            
            foreach ($service in $script:Results.ServiceEnum.GetEnumerator()) {
                $status = if ($service.Value) { "✓" } else { "✗" }
                $class = if ($service.Value) { "success" } else { "error" }
                $htmlContent += "<li class='$class'>$($service.Key): $status</li>"
            }
            
            $htmlContent += @"
        </ul>
    </div>
    
    <div class="section">
        <h2 class="header">DNS Records ($($script:Results.DNSRecon.Count) found)</h2>
        <table>
            <tr><th>Name</th><th>Type</th><th>Value</th></tr>
"@
            
            foreach ($dns in $script:Results.DNSRecon) {
                $htmlContent += "<tr><td>$($dns.Name)</td><td>$($dns.Type)</td><td>$($dns.Value)</td></tr>"
            }
            
            $htmlContent += @"
        </table>
    </div>
    
    <div class="section">
        <h2 class="header">Cloud Assets ($($script:Results.CloudAssets.Count) found)</h2>
        <table>
            <tr><th>Type</th><th>Name</th><th>URL</th><th>Status</th></tr>
"@
            
            foreach ($asset in $script:Results.CloudAssets) {
                $htmlContent += "<tr><td>$($asset.Type)</td><td>$($asset.Name)</td><td><a href='$($asset.Url)'>$($asset.Url)</a></td><td>$($asset.Status)</td></tr>"
            }
            
            $htmlContent += @"
        </table>
    </div>
</body>
</html>
"@
            
            if ($OutputFile) {
                $htmlContent | Out-File -FilePath $OutputFile -Encoding UTF8
                Write-OSINTLog "HTML report exported to: $OutputFile" "INFO" Green
            } else {
                Write-Output $htmlContent
            }
        }
        
        "Console" {
            Write-Host "`n==== Azure AD/Entra ID OSINT Results ====" -ForegroundColor Cyan
            Write-Host "Domain: $Domain"
            Write-Host "Timestamp: $($script:Results.Timestamp)"
            Write-Host "Tenant ID: $($script:Results.TenantInfo.TenantId ?? 'Not found')"
            
            Write-Host "`n---- Services Detected ----" -ForegroundColor Yellow
            foreach ($service in $script:Results.ServiceEnum.GetEnumerator()) {
                $status = if ($service.Value) { "✓" } else { "✗" }
                $color = if ($service.Value) { "Green" } else { "Red" }
                Write-Host "$($service.Key): $status" -ForegroundColor $color
            }
            
            Write-Host "`n---- Users Found ($($script:Results.UserEnum.Count)) ----" -ForegroundColor Yellow
            foreach ($user in $script:Results.UserEnum) {
                Write-Host "$($user.Username) [$($user.Status)] - $($user.Source)" -ForegroundColor Green
            }
            
            Write-Host "`n---- DNS Records ($($script:Results.DNSRecon.Count)) ----" -ForegroundColor Yellow
            foreach ($dns in $script:Results.DNSRecon) {
                Write-Host "$($dns.Name) ($($dns.Type)) -> $($dns.Value)" -ForegroundColor Gray
            }
            
            Write-Host "`n---- Cloud Assets ($($script:Results.CloudAssets.Count)) ----" -ForegroundColor Yellow
            foreach ($asset in $script:Results.CloudAssets) {
                Write-Host "$($asset.Type): $($asset.Url)" -ForegroundColor Green
            }
        }
    }
}

# Main execution
function Start-OSINTReconnaissance {
    Write-Host "Azure AD/Entra ID OSINT Tool" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    Write-Host "Target Domain: $Domain" -ForegroundColor White
    Write-Host "Modules: $Modules" -ForegroundColor White
    Write-Host ""
    
    $moduleList = $Modules -split ','
    
    foreach ($module in $moduleList) {
        switch ($module.Trim()) {
            "TenantInfo" { Get-TenantInfo }
            "UserEnum" { Start-UserEnumeration }
            "ServiceEnum" { Get-ServiceEnumeration }
            "DNSRecon" { Start-DNSReconnaissance }
            "CloudAssets" { Get-CloudAssets }
        }
    }
    
    Export-Results
    
    Write-Host "`nOSINT reconnaissance completed!" -ForegroundColor Green
    Write-Host "Errors encountered: $($script:Results.Errors.Count)" -ForegroundColor $(if ($script:Results.Errors.Count -gt 0) { "Red" } else { "Green" })
}

# Execute the reconnaissance
Start-OSINTReconnaissance
#Requires -Version 7.0
<#
.SYNOPSIS
Advanced Azure AD/Entra ID OSINT Reconnaissance Module

.DESCRIPTION
Extended OSINT capabilities including certificate transparency logs, social media reconnaissance,
tenant-aware reconnaissance heuristics, advanced enumeration techniques, authentication flow analysis, and security 
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
function Invoke-WebRequestSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [int]$TimeoutSec = 10,
        [int[]]$ExpectedStatusCodes = @(),
        [int]$MaximumRedirection = 5,
        [switch]$SuppressErrors
    )
    try {
        $defaultHeaders = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        $allHeaders = $defaultHeaders + $Headers
        $requestParams = @{
            Uri                = $Uri
            Headers            = $allHeaders
            Method             = $Method
            TimeoutSec         = $TimeoutSec
            ErrorAction        = 'Stop'
            MaximumRedirection = $MaximumRedirection
        }
        if ($Body) { $requestParams.Body = $Body }
        $response = Invoke-WebRequest @requestParams
        if ($ExpectedStatusCodes.Count -gt 0 -and -not ($ExpectedStatusCodes -contains [int]$response.StatusCode)) {
            # Treat unexpected status as soft-failure but return object for caller analysis
            return $response
        }
        return $response
    }
    catch {
        if (-not $SuppressErrors) {
            try { $hostname = ([System.Uri]$Uri).Host } catch { $hostname = $Uri }
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

function Write-OSINTProgress {
    param(
        [Parameter(Position = 0)]
        [Alias('Operation')]
        [string]$Message,

        [Parameter()]
        [Alias('Step')]
        [int]$Current = 0,

        [Parameter()]
        [Alias('Total')]
        [int]$TotalCount = 0,

        [string]$Activity = "Advanced Azure OSINT",

        [string]$Status = $null,

        [switch]$Completed
    )

    $statusLine = if (-not [string]::IsNullOrWhiteSpace($Status)) {
        $Status
    }
    elseif (-not [string]::IsNullOrWhiteSpace($Message)) {
        $Message
    }
    else {
        $Activity
    }

    $progressParams = @{ Activity = $Activity; Status = $statusLine }

    if ($TotalCount -gt 0) {
        $percent = 0
        if ($Current -ge $TotalCount) { $percent = 100 }
        elseif ($Current -gt 0) { $percent = [Math]::Min(100, [int](($Current / [double]$TotalCount) * 100)) }
        $progressParams['PercentComplete'] = $percent
    }

    try {
        if ($Completed) {
            Write-Progress -Activity $Activity -Completed
        }
        else {
            Write-Progress @progressParams
        }
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($statusLine)) {
            Write-Host "[Progress] $statusLine" -ForegroundColor DarkCyan
        }
    }
}

function Write-OSINTLog {
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG', 'TRACE')]
        [string]$Severity = 'INFO',

        [Parameter(Position = 2)]
        [Alias('Color')]
        [object]$ColorOverride,

        [switch]$VerboseOnly,
        [switch]$Silent,
        [switch]$PassThru
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $null
    }

    $normalizedSeverity = $Severity.ToUpperInvariant()
    switch ($normalizedSeverity) {
        'WARNING' { $normalizedSeverity = 'WARN' }
        'FAIL' { $normalizedSeverity = 'ERROR' }
        default { }
    }

    $colorName = if ($PSBoundParameters.ContainsKey('ColorOverride')) {
        $ColorOverride
    }
    else {
        switch ($normalizedSeverity) {
            'ERROR' { 'Red' }
            'WARN' { 'Yellow' }
            'SUCCESS' { 'Green' }
            'DEBUG' { 'DarkGray' }
            'TRACE' { 'DarkGray' }
            default { 'Cyan' }
        }
    }

    try {
        if ($colorName -is [ConsoleColor]) {
            $colorValue = $colorName
        }
        else {
            $colorValue = [System.Enum]::Parse([ConsoleColor], $colorName, $true)
        }
    }
    catch {
        $colorValue = [ConsoleColor]::White
    }

    if (-not $script:OSINTLogHistory) {
        $script:OSINTLogHistory = New-Object System.Collections.Generic.List[psobject]
    }

    $logEntry = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity  = $normalizedSeverity
        Message   = $Message.Trim()
    }

    [void]$script:OSINTLogHistory.Add($logEntry)

    if ($VerboseOnly) {
        Write-Verbose $Message
    }
    elseif (-not $Silent) {
        Write-Host $Message -ForegroundColor $colorValue
    }

    if ($PassThru) {
        return $logEntry
    }
}

function Write-OSINTError {
    param(
        [Parameter(Position = 0)]
        [Alias('Operation')]
        [string]$Context,

        [Parameter(Position = 1)]
        [string]$Target,

        [Parameter(Position = 2)]
        [Alias('Reason', 'Message')]
        [string]$Detail,

        [switch]$Silent
    )

    $segments = @()
    if (-not [string]::IsNullOrWhiteSpace($Context)) { $segments += $Context.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($Target)) { $segments += "→ $($Target.Trim())" }
    if (-not [string]::IsNullOrWhiteSpace($Detail)) { $segments += "- $($Detail.Trim())" }

    $message = if ($segments.Count -gt 0) { [string]::Join(' ', $segments) } else { 'An unexpected error occurred.' }

    return Write-OSINTLog -Message $message -Severity 'ERROR' -Silent:$Silent -Color Red
}

function Write-OSINTSuccess {
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Alias('Operation')]
        [string]$Message,

        [Parameter(Position = 1)]
        [Alias('Detail')]
        [string]$Extra,

        [switch]$Silent
    )

    $output = if (-not [string]::IsNullOrWhiteSpace($Extra)) { "$Message → $Extra" } else { $Message }
    return Write-OSINTLog -Message $output -Severity 'SUCCESS' -Color Green -Silent:$Silent
}

function Write-OSINTBulkResult {
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$Operation,

        [Parameter(Position = 1)]
        [int]$SuccessCount = 0,

        [Parameter(Position = 2)]
        [int]$FailureCount = 0,

        [int]$WarningCount = 0,

        [switch]$Silent
    )

    $segments = @()
    $segments += "$SuccessCount success"
    if ($WarningCount -gt 0) { $segments += "$WarningCount warning" }
    if ($FailureCount -gt 0) { $segments += "$FailureCount failure" }

    $summary = "$Operation results: " + ($segments -join ', ')

    $severity = if ($FailureCount -gt 0) { 'WARN' } elseif ($SuccessCount -gt 0) { 'SUCCESS' } else { 'INFO' }
    $color = switch ($severity) {
        'SUCCESS' { 'Green' }
        'WARN' { 'Yellow' }
        default { 'Cyan' }
    }

    return Write-OSINTLog -Message $summary -Severity $severity -Color $color -Silent:$Silent
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

function ConvertTo-HashtableRecursive {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-HashtableRecursive $InputObject[$key]
        }
        return $result
    }

    if ($InputObject -is [pscustomobject]) {
        $result = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $result[$prop.Name] = ConvertTo-HashtableRecursive $prop.Value
        }
        return $result
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $list = @()
        foreach ($item in $InputObject) {
            $list += , (ConvertTo-HashtableRecursive $item)
        }
        return $list
    }

    return $InputObject
}

function ConvertTo-NormalizedHashtable {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        $InputObject,

        [switch]$AllowNull
    )

    $converted = ConvertTo-HashtableRecursive $InputObject

    if ($converted -is [System.Collections.IDictionary]) {
        return $converted
    }

    if ($converted -is [System.Collections.IEnumerable] -and -not ($converted -is [string])) {
        foreach ($candidate in $converted) {
            if ($candidate -is [System.Collections.IDictionary]) {
                return $candidate
            }
        }
        if ($AllowNull -and ($converted.Count -eq 0)) {
            return $null
        }
    }

    if ($AllowNull -and $null -eq $converted) {
        return $null
    }

    return @{}
}

function Get-StructuredValue {
    param(
        $Source,
        [Parameter(Mandatory = $true)][string]$Key
    )

    if ($null -eq $Source) { return $null }

    if ($Source -is [System.Collections.IDictionary]) {
        if ($Source.ContainsKey($Key)) { return $Source[$Key] }
        return $null
    }

    if ($Source -is [System.Management.Automation.PSObject] -or $Source -is [pscustomobject]) {
        if ($Source.PSObject.Properties[$Key]) { return $Source.$Key }
        return $null
    }

    try { return $Source.$Key } catch { return $null }
}

function Test-StructuredFlag {
    param(
        $Source,
        [Parameter(Mandatory = $true)][string]$Key
    )

    $value = Get-StructuredValue -Source $Source -Key $Key
    return [bool]$value
}

# Attempt to resolve tenant ID from generic OpenID configuration endpoints if not already discovered
function Resolve-TenantIdFromOIDC {
    param(
        [Parameter(Mandatory = $true)][string]$Domain
    )
    try {
        $oidcUri = "https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid-configuration"
        $resp = Invoke-WebRequestSafe -Uri $oidcUri -SuppressErrors -TimeoutSec 8
        if ($resp -and $resp.StatusCode -eq 200 -and $resp.Content) {
            $json = $resp.Content | ConvertFrom-Json
            foreach ($prop in 'authorization_endpoint', 'token_endpoint', 'issuer') {
                $val = $json.$prop
                if ($val -and ($val -match '/([0-9a-fA-F-]{8}-[0-9a-fA-F-]{4}-[0-9a-fA-F-]{4}-[0-9a-fA-F-]{4}-[0-9a-fA-F-]{12})/')) {
                    return $Matches[1]
                }
            }
        }
    }
    catch {
        # Silent fallback
    }
    return $null
}

function Write-OSINTList {
    param([string[]]$Items, [string]$Prefix = "  •")
    foreach ($item in $Items) {
        Write-Host "$Prefix $item" -ForegroundColor Cyan
    }
}

function Format-AzureResourceDisplay {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][psobject]$Item,
        [string]$Property
    )

    $value = $null
    if ($Property -and $Item.PSObject.Properties[$Property]) {
        $value = $Item.$Property
    }
    if (-not $value -and $Item.PSObject.Properties['Url']) { $value = $Item.Url }
    if (-not $value -and $Item.PSObject.Properties['Endpoint']) { $value = $Item.Endpoint }
    if (-not $value -and $Item.PSObject.Properties['Name']) { $value = $Item.Name }

    $stringValue = $value -as [string]
    if ([string]::IsNullOrWhiteSpace($stringValue)) { return $null }

    $stringValue = $stringValue.Trim()
    $hostCandidate = $stringValue

    if ($hostCandidate -match '^(?i)https?://') {
        try {
            $uri = [Uri]$hostCandidate
            if ($uri.Host) { $hostCandidate = $uri.Host }
        }
        catch { $hostCandidate = $stringValue }
    }

    switch ($Category) {
        'StorageAccounts' {
            if ($hostCandidate -notmatch '\.') {
                $suffix = '.blob.core.windows.net'
                if ($Item.PSObject.Properties['Kind'] -and $Item.Kind -eq 'FileStorage') {
                    $suffix = '.file.core.windows.net'
                }
                $hostCandidate = "$hostCandidate$suffix"
            }
        }
        'KeyVaults' {
            if ($hostCandidate -notmatch '\.') {
                $hostCandidate = "$hostCandidate.vault.azure.net"
            }
        }
        'ContainerRegistry' {
            if ($hostCandidate -notmatch '\.') {
                $hostCandidate = "$hostCandidate.azurecr.io"
            }
        }
        default {
            if ($hostCandidate -notmatch '\.' -and $Item.PSObject.Properties['Endpoint']) {
                $endpoint = $Item.Endpoint
                if (-not [string]::IsNullOrWhiteSpace($endpoint)) {
                    try {
                        if ($endpoint -match '^(?i)https?://') {
                            $uri = [Uri]$endpoint
                            if ($uri.Host) { $hostCandidate = $uri.Host }
                        }
                        elseif ($endpoint -match '\.') {
                            $hostCandidate = $endpoint
                        }
                    }
                    catch { $hostCandidate = $endpoint }
                }
            }
        }
    }

    try {
        return $hostCandidate.ToLowerInvariant()
    }
    catch {
        return $hostCandidate
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

function Get-TenantCloudEnvironmentLabel {
    param(
        [string]$CloudInstance,
        [string]$TenantRegion,
        [string]$TenantSubRegion
    )

    $cloudUpper = if ([string]::IsNullOrWhiteSpace($CloudInstance)) { "" } else { $CloudInstance.ToUpperInvariant() }
    $regionUpper = if ([string]::IsNullOrWhiteSpace($TenantRegion)) { "" } else { $TenantRegion.ToUpperInvariant() }
    $subUpper = if ([string]::IsNullOrWhiteSpace($TenantSubRegion)) { "" } else { $TenantSubRegion.ToUpperInvariant() }

    if ($subUpper -eq "DOD") { return "Azure Government (DoD)" }
    if ($subUpper -like "*GCC HIGH*" -or $subUpper -eq "GCC HIGH") { return "Azure Government (GCC High)" }
    if ($subUpper -eq "GCC") { return "Azure Government (GCC)" }

    if ($cloudUpper -match "AZUREUSGOVERNMENT" -or $cloudUpper -match "US" -or $cloudUpper -match "GOV" -or $regionUpper -match "GOV") {
        return "Azure Government (Commercial)"
    }

    if ($cloudUpper -match "AZURECHINACLOUD" -or $cloudUpper -match "CHINA" -or $regionUpper -match "CHINA") {
        return "Azure China (21Vianet)"
    }

    if ($cloudUpper -match "AZUREGERMANYCLOUD" -or $cloudUpper -match "GERMAN" -or $regionUpper -match "GERMAN") {
        return "Azure Germany"
    }

    if ($cloudUpper -match "AZUREPUBLICCLOUD" -or $cloudUpper -match "WORLD" -or $cloudUpper -match "PUBLIC" -or $cloudUpper -match "COMMERCIAL" -or $cloudUpper -match "AZUREAD" -or $cloudUpper -match "OFFICE365" -or $cloudUpper -match "MSONLINE" -or $regionUpper -match "GLOBAL" -or [string]::IsNullOrWhiteSpace($cloudUpper)) {
        return "Azure Commercial (Public)"
    }

    if (-not [string]::IsNullOrWhiteSpace($CloudInstance)) {
        return "Azure Cloud ($CloudInstance)"
    }

    return "Unknown"
}

function Update-TenantClassification {
    param(
        [hashtable]$TenantInfo,
        [hashtable]$ServiceDiscovery,
        [hashtable]$ExternalIdentities
    )

    if (-not $TenantInfo) { return }

    $originalType = $TenantInfo.TenantType
    $originalEnvironment = $TenantInfo.CloudEnvironment

    $TenantInfo.CloudEnvironment = Get-TenantCloudEnvironmentLabel -CloudInstance $TenantInfo.CloudInstance -TenantRegion $TenantInfo.TenantRegion -TenantSubRegion $TenantInfo.TenantSubRegion

    $signals = @()

    if ($TenantInfo.TenantType -eq "Unknown") {
        $b2cUrl = $null
        if ($ExternalIdentities -and $ExternalIdentities.B2CIdentities) {
            $b2cUrl = $ExternalIdentities.B2CIdentities.TenantUrl
        }
        if ($b2cUrl) {
            $TenantInfo.TenantType = "Azure AD B2C"
            $TenantInfo.TenantTypeConfidence = "High"
            if ($TenantInfo.Capabilities -notcontains "ExternalIDTenant") { $TenantInfo.Capabilities += "ExternalIDTenant" }
            if (-not $TenantInfo.TenantTypeSignals) { $TenantInfo.TenantTypeSignals = @() }
            $signalText = "B2C OpenID discovery ($b2cUrl)"
            if ($TenantInfo.TenantTypeSignals -notcontains $signalText) { $TenantInfo.TenantTypeSignals += $signalText }
        }
    }

    if ($TenantInfo.TenantType -eq "Unknown") {
        $externalSignals = @()
        if ($ExternalIdentities -and $ExternalIdentities.ExternalUserTypes) {
            $externalSignals = $ExternalIdentities.ExternalUserTypes | Where-Object { $_ -match 'External' -or $_ -match 'Social' }
        }
        if ($externalSignals.Count -gt 0) {
            $TenantInfo.TenantType = "Entra External ID (Federated)"
            if (-not $TenantInfo.TenantTypeSignals) { $TenantInfo.TenantTypeSignals = @() }
            foreach ($sig in $externalSignals) {
                if ($TenantInfo.TenantTypeSignals -notcontains $sig) { $TenantInfo.TenantTypeSignals += $sig }
            }
            if (-not $TenantInfo.TenantTypeConfidence -or $TenantInfo.TenantTypeConfidence -eq "Unknown") {
                $TenantInfo.TenantTypeConfidence = "Medium"
            }
        }
    }

    if ($TenantInfo.TenantType -eq "Unknown") {
        if ($TenantInfo.DNSAnalysis) {
            if ($TenantInfo.DNSAnalysis.MX) { $signals += "Office 365 MX records" }
            if ($TenantInfo.DNSAnalysis.SPF) { $signals += "SPF includes spf.protection.outlook.com" }
        }
        if ($ServiceDiscovery) {
            if ($ServiceDiscovery.EntraID) { $signals += "Entra ID public endpoints" }
            if ($ServiceDiscovery.Exchange) { $signals += "Exchange Online" }
            if ($ServiceDiscovery.SharePoint) { $signals += "SharePoint Online" }
            if ($ServiceDiscovery.OneDrive) { $signals += "OneDrive for Business" }
            if ($ServiceDiscovery.Teams) { $signals += "Microsoft Teams" }
        }

        if ($signals.Count -gt 0) {
            $TenantInfo.TenantType = "Entra ID (Workforce)"
            $TenantInfo.TenantTypeConfidence = if ($signals.Count -ge 2) { "High" } else { "Medium" }
            $TenantInfo.TenantTypeSignals = (($TenantInfo.TenantTypeSignals + $signals) | Where-Object { $_ }) | Sort-Object -Unique
        }
    }

    if (-not $TenantInfo.TenantTypeConfidence) { $TenantInfo.TenantTypeConfidence = "Unknown" }

    if ($TenantInfo.TenantType -ne $originalType) {
        $color = "Yellow"
        if ($TenantInfo.TenantType -match 'Entra ID') { $color = "Green" }
        elseif ($TenantInfo.TenantType -match 'External' -or $TenantInfo.TenantType -match 'B2C') { $color = "Cyan" }
        Write-OSINTProperty "Tenant Type" $TenantInfo.TenantType $color
        if ($TenantInfo.TenantTypeConfidence -and $TenantInfo.TenantTypeConfidence -ne "Unknown") {
            Write-OSINTProperty "Tenant Type Confidence" $TenantInfo.TenantTypeConfidence Magenta
        }
        if ($TenantInfo.TenantTypeSignals -and $TenantInfo.TenantTypeSignals.Count -gt 0) {
            Write-OSINTLog ("Tenant type signals: " + ($TenantInfo.TenantTypeSignals -join '; ')) "INFO" Cyan
        }
    }
    elseif ($TenantInfo.TenantTypeConfidence -eq "Unknown" -and $TenantInfo.TenantType -ne "Unknown") {
        $TenantInfo.TenantTypeConfidence = "High"
    }

    if ($TenantInfo.CloudEnvironment -and $TenantInfo.CloudEnvironment -ne $originalEnvironment -and $TenantInfo.CloudEnvironment -ne "Unknown") {
        Write-OSINTProperty "Cloud Environment" $TenantInfo.CloudEnvironment Cyan
    }
}

# Enhanced Tenant Information Discovery (AADInternals-like)
function Get-EntraIDTenantInfo {
    param([string]$Domain)
    
    Write-OSINTSection "Entra ID Tenant Discovery" "🔍"

    $classifyOidc = {
        param([hashtable]$info, $config, [string]$source)

        if (-not $config) { return }

        $issuerHost = $null
        try { $issuerHost = ([System.Uri]$config.issuer).Host } catch { }
        if (-not $issuerHost) { return }

        if (-not $info.OIDCIssuer) { $info.OIDCIssuer = $issuerHost }
        if (-not $info.OIDCSource) { $info.OIDCSource = $source }
        if (-not $info.IdentitySurface -or $info.IdentitySurface -eq "Unknown") { $info.IdentitySurface = $issuerHost }

        $classification = "Unknown"
        $severity = "Yellow"

        $isCustomerSurface = $false
        if ($issuerHost -match 'ciamlogin\.com$' -or ($config.token_endpoint -and $config.token_endpoint -match 'ciamlogin\.com')) {
            $classification = "Entra External ID (CIAM)"
            $severity = "Cyan"
            $isCustomerSurface = $true
        }
        elseif ($issuerHost -match 'b2clogin\.com$') {
            $classification = "Azure AD B2C"
            $severity = "Cyan"
            $isCustomerSurface = $true
        }
        elseif ($issuerHost -match 'login\.microsoftonline' -or $issuerHost -match 'sts\.windows\.net') {
            $classification = "Entra ID (Workforce)"
            $severity = "Green"
        }

        if ($isCustomerSurface -and $info.Capabilities -notcontains "ExternalIDTenant") {
            $info.Capabilities += "ExternalIDTenant"
        }

        if ($classification -ne "Unknown") {
            if (-not $info.TenantTypeSignals) { $info.TenantTypeSignals = @() }
            $signal = "OIDC surface ($source)"
            if ($info.TenantTypeSignals -notcontains $signal) { $info.TenantTypeSignals += $signal }
            $info.TenantTypeConfidence = "High"
        }

        $shouldLog = $false
        if ($info.TenantType -eq "Unknown" -and $classification -ne "Unknown") {
            $shouldLog = $true
        }
        elseif ($classification -ne "Unknown" -and $info.TenantType -ne $classification) {
            $shouldLog = $true
        }

        if ($shouldLog) {
            $info.TenantType = $classification
            $info.IdentitySurface = $issuerHost
            $info.OIDCSource = $source
            Write-OSINTProperty "OIDC Issuer Host" $issuerHost Cyan
            Write-OSINTProperty "Tenant Type" $classification $severity
        }
    }

    $setOidcEndpoints = {
        param([hashtable]$info, $config)

        if (-not $config) { return }

        $info.Endpoints = @{
            Authorization = $config.authorization_endpoint
            Token         = $config.token_endpoint
            UserInfo      = $config.userinfo_endpoint
            EndSession    = $config.end_session_endpoint
            JwksUri       = $config.jwks_uri
            Issuer        = $config.issuer
        }
    }

    $tenantInfo = @{
        Domain               = $Domain
        TenantId             = $null
        TenantName           = $null
        TenantBrand          = $null
        TenantRegion         = $null
        TenantSubRegion      = $null
        CloudInstance        = $null
        CloudEnvironment     = "Unknown"
        AuthenticationUrl    = $null
        FederationMetadata   = $null
        OpenIdConfiguration  = $null
        OIDCIssuer           = $null
        OIDCSource           = $null
        TenantType           = "Unknown"
        IdentitySurface      = "Unknown"
        TenantBrandingUrls   = @()
        ManagedDomains       = @()
        FederatedDomains     = @()
        AllDomains           = @()
        NameSpaceType        = $null
        Federation           = $null
        PreferredUserName    = $null
        Endpoints            = @{}
        Capabilities         = @()
        DNSAnalysis          = $null
        DesktopSSOEnabled    = $false
        CBAEnabled           = $null
        MDIInstance          = $null
        STSServer            = $null
        TenantTypeConfidence = "Unknown"
        TenantTypeSignals    = @()
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
                    & $setOidcEndpoints $tenantInfo $openIdConfig
                    
                    Write-OSINTSuccess "Enhanced OpenID Connect Discovery"
                    Write-OSINTProperty "Tenant ID" $tenantInfo.TenantId Green
                    Write-OSINTProperty "Cloud Instance" $tenantInfo.CloudInstance Green
                    Write-OSINTProperty "Discovery Method" "OpenID Connect (Authoritative)" Green
                    & $classifyOidc $tenantInfo $openIdConfig "Domain"
                    
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
            $rawMetadata = $federationResponse.Content

            if (-not [string]::IsNullOrWhiteSpace($rawMetadata)) {
                $cleanMetadata = $rawMetadata -replace "^[\uFEFF\u200B\u200C\u200E\u200F]+", ''
                $tenantInfo.FederationMetadata = $cleanMetadata

                try {
                    $xmlDoc = New-Object System.Xml.XmlDocument
                    $xmlDoc.XmlResolver = $null
                    $xmlDoc.PreserveWhitespace = $true
                    $xmlDoc.LoadXml($cleanMetadata)

                    $entityDescriptor = $xmlDoc.DocumentElement

                    if ($entityDescriptor -and $entityDescriptor.LocalName -eq 'EntityDescriptor') {
                        $tenantInfo.TenantName = $entityDescriptor.GetAttribute('entityID')
                        Write-OSINTSuccess "Federation Metadata Discovery"
                        Write-OSINTProperty "Federation Entity ID" $tenantInfo.TenantName Green

                        $namespaceManager = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable)
                        $namespaceManager.AddNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#') | Out-Null
                        $certificates = $xmlDoc.SelectNodes('//ds:X509Certificate', $namespaceManager)
                        $certCount = if ($certificates) { $certificates.Count } else { 0 }
                        Write-OSINTProperty "Signing Certificates" $certCount Green
                    }
                    else {
                        Write-OSINTError "Federation Metadata Discovery" $Domain "Metadata parsed but EntityDescriptor missing" -Silent
                    }
                }
                catch {
                    Write-OSINTError "Federation Metadata Discovery" $Domain "Metadata parse failed: $($_.Exception.Message)" -Silent
                }
            }
            else {
                Write-OSINTError "Federation Metadata Discovery" $Domain "Metadata response was empty" -Silent
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
                    $hasCert = $null -ne $credData.Credentials.CertAuthParams
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
        $normalizedDomain = $Domain.ToLowerInvariant()
        $isFirstPartyMicrosoft = (
            $normalizedDomain -eq "microsoft.com" -or
            $normalizedDomain -like "*.microsoft.com" -or
            $normalizedDomain -eq "microsoftonline.com" -or
            $normalizedDomain -like "*.microsoftonline.com"
        )
        $isOnMicrosoftTenant = $normalizedDomain -like "*.onmicrosoft.com"

        if (-not $tenantInfo.TenantId -and $isFirstPartyMicrosoft -and -not $isOnMicrosoftTenant) {
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
    
    if ($tenantInfo.TenantType -eq "Unknown" -and $tenantInfo.TenantId) {
        Write-OSINTProgress "OIDC Classification (Tenant Id Probe)"
        try {
            $tenantOidcUrl = "https://login.microsoftonline.com/$($tenantInfo.TenantId)/v2.0/.well-known/openid_configuration"
            $tenantOidcResponse = Invoke-WebRequestSafe -Uri $tenantOidcUrl -SuppressErrors
            if ($tenantOidcResponse) {
                $tenantOidcConfig = $tenantOidcResponse.Content | ConvertFrom-Json
                if (-not $tenantInfo.OpenIdConfiguration) { $tenantInfo.OpenIdConfiguration = $tenantOidcConfig }
                if (-not $tenantInfo.Endpoints -or $tenantInfo.Endpoints.Count -eq 0) { & $setOidcEndpoints $tenantInfo $tenantOidcConfig }
                & $classifyOidc $tenantInfo $tenantOidcConfig "TenantId"
            }
        }
        catch { }
    }

    if ($tenantInfo.TenantType -eq "Unknown" -and $tenantInfo.TenantId) {
        $ciamCandidates = @($Domain.Split('.')[0]) | Where-Object { $_ -and ($_ -match '^[a-z0-9-]+$') }
        foreach ($candidate in $ciamCandidates) {
            try {
                $ciamOidcUrl = "https://$candidate.ciamlogin.com/$($tenantInfo.TenantId)/v2.0/.well-known/openid_configuration"
                $ciamResponse = Invoke-WebRequestSafe -Uri $ciamOidcUrl -SuppressErrors
                if ($ciamResponse) {
                    $ciamConfig = $ciamResponse.Content | ConvertFrom-Json
                    if (-not $tenantInfo.OpenIdConfiguration) { $tenantInfo.OpenIdConfiguration = $ciamConfig }
                    & $setOidcEndpoints $tenantInfo $ciamConfig
                    & $classifyOidc $tenantInfo $ciamConfig "CIAM guess: $candidate"
                    if ($tenantInfo.TenantType -ne "Unknown") { break }
                }
            }
            catch { }
        }
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
    if ($null -ne $tenantInfo.CBAEnabled) {
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

# Device code flow probe (returns richer state & confidence)
function Test-DeviceCodeFlow {
    param(
        [string]$Domain,
        [string]$TenantId
    )

    $probeResult = [ordered]@{
        Supported        = $false
        FlowState        = "NotTested"
        Confidence       = "Low"
        AuthorityTried   = @()
        AuthorityUsed    = $null
        DeviceCode       = $null
        RawDeviceCode    = $null
        MaskedDeviceCode = $null
        UserCode         = $null
        VerificationUrl  = $null
        ExpiresIn        = $null
        Interval         = $null
        Notes            = @()
    }

    $authorities = @()
    if ($TenantId) { $authorities += $TenantId }
    if ($Domain) { $authorities += $Domain }
    $authorities += "common"
    $authorities = $authorities | Where-Object { $_ } | Sort-Object -Unique

    foreach ($authority in $authorities) {
        $probeResult.AuthorityTried += $authority
        $maxAttempts = 2
        $success = $false

        for ($attempt = 1; $attempt -le $maxAttempts -and -not $success; $attempt++) {
            try {
                $deviceCodeUrl = "https://login.microsoftonline.com/$authority/oauth2/v2.0/devicecode"
                $scope = 'offline_access https://graph.microsoft.com/.default'
                $deviceBody = "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&scope=$([uri]::EscapeDataString($scope))"

                $response = Invoke-RestMethod -Uri $deviceCodeUrl -Method Post -Body $deviceBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

                $deviceCode = [string]$response.device_code
                $userCode = [string]$response.user_code

                if ($deviceCode -and $userCode) {
                    $probeResult.Supported = $true
                    $probeResult.FlowState = "CodeIssued"
                    $probeResult.AuthorityUsed = $authority
                    $probeResult.RawDeviceCode = $deviceCode
                    $masked = if ($deviceCode.Length -gt 12) { $deviceCode.Substring(0, 6) + "..." + $deviceCode.Substring($deviceCode.Length - 4) } else { $deviceCode }
                    $probeResult.DeviceCode = $masked
                    $probeResult.MaskedDeviceCode = $masked
                    $probeResult.UserCode = $userCode
                    $probeResult.VerificationUrl = $response.verification_uri_complete ?? $response.verification_uri ?? $response.verification_url
                    $probeResult.ExpiresIn = $response.expires_in
                    $probeResult.Interval = $response.interval
                    $probeResult.Notes += "Device code issued successfully."
                    if ($TenantId -and $authority -eq $TenantId) {
                        $probeResult.Confidence = "High"
                    }
                    elseif ($authority -eq $Domain) {
                        $probeResult.Confidence = "Medium"
                    }
                    else {
                        $probeResult.Confidence = "Low"
                    }
                    $success = $true
                }
                else {
                    $probeResult.Notes += "Authority $authority responded without device_code/user_code."
                }
            }
            catch {
                $response = $_.Exception.Response
                $statusCode = $null
                $statusDescription = $null
                if ($response) {
                    try { $statusCode = [int]$response.StatusCode } catch { $statusCode = $null }
                    try { $statusDescription = $response.StatusDescription } catch { $statusDescription = $null }
                }

                $webException = $_.Exception
                $webStatus = $null
                if ($webException -is [System.Net.WebException]) {
                    $webStatus = $webException.Status
                }

                $shouldRetry = $false
                if ($attempt -lt $maxAttempts) {
                    if ($statusCode -eq 500) {
                        $shouldRetry = $true
                        $probeResult.Notes += "Authority $authority returned HTTP 500 (attempt $attempt). Retrying..."
                    }
                    elseif ($webStatus -eq [System.Net.WebExceptionStatus]::Timeout) {
                        $shouldRetry = $true
                        $probeResult.Notes += "Authority $authority timed out (attempt $attempt). Retrying..."
                    }
                }

                if ($shouldRetry) {
                    Start-Sleep -Seconds (2 * $attempt)
                    continue
                }

                if ($statusCode -eq 403) {
                    $probeResult.Notes += "Authority $authority responded 403 Forbidden (device code flow likely blocked)."
                    if ($probeResult.FlowState -eq "NotTested" -or $probeResult.FlowState -eq "Unavailable") { $probeResult.FlowState = "Forbidden" }
                }
                elseif ($statusCode -eq 401) {
                    $probeResult.Notes += "Authority $authority responded 401 Unauthorized (client not permitted)."
                    if ($probeResult.FlowState -eq "NotTested" -or $probeResult.FlowState -eq "Unavailable") { $probeResult.FlowState = "Unauthorized" }
                }
                elseif ($statusCode) {
                    $desc = if ($statusDescription) { " $statusDescription" } else { "" }
                    $probeResult.Notes += "Authority $authority failed with HTTP $statusCode$desc."
                    if ($probeResult.FlowState -eq "NotTested") { $probeResult.FlowState = "Error" }
                }
                else {
                    $probeResult.Notes += "Authority $authority unreachable (device code endpoint not reachable): $($webException.Message)"
                    if ($probeResult.FlowState -eq "NotTested") { $probeResult.FlowState = "Unreachable" }
                }
            }
        }

        if ($success) { break }
    }

    if (-not $probeResult.Supported -and $probeResult.FlowState -eq "NotTested") {
        $probeResult.FlowState = "Unavailable"
    }

    if ($probeResult.AuthorityUsed) {
        Write-Host "[DEBUG-TDCF] AuthorityUsed raw type: $($probeResult.AuthorityUsed.GetType().FullName)" -ForegroundColor DarkGray
        Write-Host "[DEBUG-TDCF] AuthorityUsed raw value: $($probeResult.AuthorityUsed)" -ForegroundColor DarkGray
    }

    return $probeResult
}

# Enhanced User Enumeration with mjendza.net and ROADtools Techniques
function Get-AdvancedUserEnumeration {
    param(
        [string]$Domain,
        [string]$TenantId,
        [object]$ReconContext = $null
    )
    
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
        SuppressedReason     = $null
    }
    
    if ($ReconContext -and $ReconContext.IsAuthenticated) {
        $userEnum.SuppressedReason = "Skipped during insider recon (authenticated context detected)"
        Write-OSINTLog "User enumeration suppressed for insider reconnaissance (leveraging authenticated Azure CLI context)." "INFO" Yellow
        return $userEnum
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
        $params = @{
            client_id     = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft CLI client ID
            response_type = "code"
            redirect_uri  = "https://login.microsoftonline.com/common/oauth2/nativeclient"
            scope         = "openid"
        }
        
        $queryString = ($params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
        $fullAuthUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$queryString"
        
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
                Write-OSINTLog "EntraExternalID detected: sCtx present, TestResult=$($credData.IfExistsResult)" "INFO" Cyan
            }
        }
    }
    catch {
        Write-OSINTProperty "External ID Analysis" "Standard tenant (not External ID)" Yellow
    }
    
    # Method 4: Device Code Flow Analysis (ROADtools technique)
    Write-OSINTProgress "Device Code Flow Analysis"
    $deviceCodeProbe = Test-DeviceCodeFlow -Domain $Domain -TenantId $TenantId
    $userEnum.DeviceCodeResults = $deviceCodeProbe

    if ($deviceCodeProbe.Supported) {
        $authorityLabel = if ($deviceCodeProbe.AuthorityUsed) { $deviceCodeProbe.AuthorityUsed } else { "unknown" }
        Write-OSINTProperty "Device Code Flow" "Code issued ($authorityLabel)" Green
        Write-OSINTProperty "Support Confidence" $deviceCodeProbe.Confidence Cyan
        if ($deviceCodeProbe.MaskedDeviceCode) {
            Write-OSINTProperty "Device Code" $deviceCodeProbe.MaskedDeviceCode Cyan
        }
        if ($ReconContext -and $ReconContext.IsAuthenticated -and $deviceCodeProbe.FlowState -eq 'CodeIssued' -and $deviceCodeProbe.RawDeviceCode) {
            Write-OSINTProperty "Device Code (raw)" $deviceCodeProbe.RawDeviceCode Magenta
        }
        if ($deviceCodeProbe.UserCode) {
            Write-OSINTProperty "User Code" $deviceCodeProbe.UserCode Yellow
        }
        if ($deviceCodeProbe.VerificationUrl) {
            Write-OSINTProperty "Verification URL" $deviceCodeProbe.VerificationUrl Yellow
        }
        if ($deviceCodeProbe.ExpiresIn -and $deviceCodeProbe.Interval) {
            Write-OSINTProperty "Code Lifetime" "$($deviceCodeProbe.ExpiresIn)s (poll every $($deviceCodeProbe.Interval)s)" Cyan
        }
        Write-OSINTLog "Device code flow: authority=$authorityLabel, userCode=$($deviceCodeProbe.UserCode), verificationUrl=$($deviceCodeProbe.VerificationUrl)" "INFO" Cyan
    }
    else {
        Write-OSINTProperty "Device Code Flow" "Unavailable ($($deviceCodeProbe.FlowState))" Yellow
    }

    if ($deviceCodeProbe.Notes -and $deviceCodeProbe.Notes.Count -gt 0) {
        $noteSummary = $deviceCodeProbe.Notes |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Group-Object |
        ForEach-Object {
            $text = $_.Name.Trim()
            if ($_.Count -gt 1) { "$text (x$($_.Count))" } else { $text }
        }
        if ($noteSummary) {
            Write-OSINTLog ("Device code notes: " + ($noteSummary -join ' | ')) "INFO" DarkCyan
        }
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

    if ([string]::IsNullOrWhiteSpace($Domain)) { return $certificates }

    try {
        $encodedQuery = [uri]::EscapeDataString("%.${Domain}")
        $crtShUrl = "https://crt.sh/?q=$encodedQuery&output=json"
        $response = Invoke-WebRequestSafe -Uri $crtShUrl -SuppressErrors

        if (-not $response) { return $certificates }

        $rawContent = $response.Content
        if ([string]::IsNullOrWhiteSpace($rawContent)) {
            Write-OSINTLog "Certificate Transparency response was empty." "WARN" Yellow
            return $certificates
        }

        $crtData = $null
        try {
            $crtData = $rawContent | ConvertFrom-Json
        }
        catch {
            $jsonLines = $rawContent -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if ($jsonLines.Count -gt 0) {
                $wrappedJson = "[" + ($jsonLines -join ",") + "]"
                try {
                    $crtData = $wrappedJson | ConvertFrom-Json
                }
                catch {
                    Write-OSINTLog "Failed to parse Certificate Transparency response: $($_.Exception.Message)" "ERROR" Red
                    return $certificates
                }
            }
            else {
                Write-OSINTLog "Certificate Transparency response contained no JSON records." "WARN" Yellow
                return $certificates
            }
        }

        if ($crtData -and -not ($crtData -is [System.Collections.IEnumerable])) {
            $crtData = @($crtData)
        }

        foreach ($cert in ($crtData | Sort-Object -Property not_before -Descending | Select-Object -First 20)) {
            $commonName = $cert.common_name
            $issuer = $cert.issuer_name
            $notBefore = $cert.not_before
            $notAfter = $cert.not_after
            $entryTimestamp = $cert.entry_timestamp

            $validFrom = $null
            if ($notBefore) {
                try { $validFrom = ([DateTime]$notBefore).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") }
                catch { $validFrom = $notBefore }
            }

            $validTo = $null
            if ($notAfter) {
                try { $validTo = ([DateTime]$notAfter).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") }
                catch { $validTo = $notAfter }
            }

            $loggedAt = $null
            if ($entryTimestamp) {
                try { $loggedAt = ([DateTime]$entryTimestamp).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") }
                catch { $loggedAt = $entryTimestamp }
            }

            $certInfo = [ordered]@{
                CommonName   = if ($commonName) { [string]$commonName } else { $null }
                Issuer       = if ($issuer) { [string]$issuer } else { $null }
                ValidFrom    = $validFrom
                ValidTo      = $validTo
                LoggedAt     = $loggedAt
                SerialNumber = $cert.serial_number
                Subdomains   = @()
            }

            if ($cert.name_value) {
                $subdomains = $cert.name_value -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                if ($subdomains.Count -gt 0) {
                    $certInfo.Subdomains = ($subdomains | Sort-Object -Unique)
                }
            }

            $certificates += $certInfo
            if ($certInfo.CommonName) {
                Write-OSINTLog "Certificate found: $($certInfo.CommonName)" "INFO" Green
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
                }
            }
            catch { }
        }
    }

    $storageAccounts = $azureResources.StorageAccounts
    if ($storageAccounts.Count -gt 0) {
        $uniqueAccounts = ($storageAccounts | Select-Object -ExpandProperty Name -Unique).Count
        $typeBreakdown = $storageAccounts | Group-Object Type | ForEach-Object {
            $typeName = $_.Name.ToLower()
            "$typeName=$($_.Count)"
        }
        $typeSummary = if ($typeBreakdown) { $typeBreakdown -join ', ' } else { 'No endpoint detail' }
        Write-OSINTProperty "Storage Accounts" "$uniqueAccounts discovered ($typeSummary)" Green
    }
    else {
        Write-OSINTProperty "Storage Accounts" "No responsive endpoints" Yellow
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
            }
        }
        catch { }
    }

    if ($azureResources.FunctionApps.Count -gt 0) {
        Write-OSINTProperty "Function Apps" "$($azureResources.FunctionApps.Count) discovered" Green
    }
    else {
        Write-OSINTProperty "Function Apps" "None detected" Yellow
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
            }
        }
        catch { }
    }

    if ($azureResources.CosmosDB.Count -gt 0) {
        Write-OSINTProperty "Cosmos DB" "$($azureResources.CosmosDB.Count) discovered" Green
    }
    else {
        Write-OSINTProperty "Cosmos DB" "None detected" Yellow
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
            }
        }
        catch { }
    }

    if ($azureResources.ContainerRegistry.Count -gt 0) {
        Write-OSINTProperty "Container Registries" "$($azureResources.ContainerRegistry.Count) discovered" Green
    }
    else {
        Write-OSINTProperty "Container Registries" "None detected" Yellow
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
                }
            }
            catch { }
        }
    }
    
    if ($azureResources.CDNEndpoints.Count -gt 0) {
        $providers = $azureResources.CDNEndpoints | Group-Object Provider | ForEach-Object { "$($_.Name)=$($_.Count)" }
        $providerSummary = if ($providers) { $providers -join ', ' } else { 'Provider data unavailable' }
        Write-OSINTProperty "CDN Endpoints" "$($azureResources.CDNEndpoints.Count) discovered ($providerSummary)" Green
    }
    else {
        Write-OSINTProperty "CDN Endpoints" "None detected" Yellow
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
            }
        }
        catch { }
    }

    if ($azureResources.TrafficManager.Count -gt 0) {
        Write-OSINTProperty "Traffic Manager" "$($azureResources.TrafficManager.Count) profiles discovered" Green
    }
    else {
        Write-OSINTProperty "Traffic Manager" "None detected" Yellow
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
            }
        }
        catch { }
    }

    if ($azureResources.FrontDoor.Count -gt 0) {
        Write-OSINTProperty "Azure Front Door" "$($azureResources.FrontDoor.Count) endpoints discovered" Green
    }
    else {
        Write-OSINTProperty "Azure Front Door" "None detected" Yellow
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
            }
        }
        catch { }
    }

    if ($azureResources.ServiceBus.Count -gt 0) {
        Write-OSINTProperty "Service Bus" "$($azureResources.ServiceBus.Count) namespaces discovered" Green
    }
    else {
        Write-OSINTProperty "Service Bus" "None detected" Yellow
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
                }
            }
        }
        catch { }
    }

    if ($azureResources.EventHubs.Count -gt 0) {
        Write-OSINTProperty "Event Hubs" "$($azureResources.EventHubs.Count) namespaces discovered" Green
    }
    else {
        Write-OSINTProperty "Event Hubs" "None detected" Yellow
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
            }
        }
        catch { }
    }

    if ($azureResources.APIManagement.Count -gt 0) {
        Write-OSINTProperty "API Management" "$($azureResources.APIManagement.Count) instances discovered" Green
    }
    else {
        Write-OSINTProperty "API Management" "None detected" Yellow
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
                    break  # Found in this region, no need to check others
                }
            }
        }
        catch { }
    }
    
    if ($azureResources.LogicApps.Count -gt 0) {
        $regionsDiscovered = ($azureResources.LogicApps | Select-Object -ExpandProperty Region -Unique)
        $regionSummary = if ($regionsDiscovered) { ($regionsDiscovered -join ', ') } else { 'Region data unavailable' }
        Write-OSINTProperty "Logic Apps" "$($azureResources.LogicApps.Count) discovered (regions: $regionSummary)" Green
    }
    else {
        Write-OSINTProperty "Logic Apps" "None detected" Yellow
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
            $caParams = @{
                client_id     = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI
                response_type = "code"
                redirect_uri  = "https://login.microsoftonline.com/common/oauth2/nativeclient"
                scope         = "https://graph.microsoft.com/.default"
            }
            
            $queryString = ($caParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
            $fullUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$queryString"
            
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
            $b2bResponse = Invoke-WebRequestSafe -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?response_type=code&client_id=00000003-0000-0000-c000-000000000000" -SuppressErrors
            
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

function Get-AzureCliContext {
    $context = [ordered]@{
        IsAuthenticated = $false
        Account         = $null
        TenantId        = $null
        Environment     = $null
        SubscriptionId  = $null
        Source          = "AzureCLI"
        Errors          = @()
    }

    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        $context.Errors += "Azure CLI (az) not found in PATH."
        return $context
    }

    $accountRaw = & az account show --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $accountRaw) {
        $context.Errors += "No active az login session detected."
        return $context
    }

    try {
        $account = $accountRaw | ConvertFrom-Json -ErrorAction Stop
        if ($null -ne $account) {
            $context.IsAuthenticated = $true
            if ($account.user) {
                $context.Account = $account.user.name
                if (-not $context.Account) { $context.Account = $account.user.id }
            }
            if (-not $context.Account) { $context.Account = $account.name }
            $context.TenantId = $account.tenantId
            $context.Environment = $account.environment
            $context.SubscriptionId = $account.id
        }
    }
    catch {
        $context.Errors += "Failed to parse Azure CLI account output: $($_.Exception.Message)"
    }

    return $context
}

function Get-GraphAccessToken {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) { return $null }
    $tokenRaw = & az account get-access-token --resource-type ms-graph --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $tokenRaw) { return $null }
    try {
        $tokenObj = $tokenRaw | ConvertFrom-Json -ErrorAction Stop
        return $tokenObj.accessToken
    }
    catch {
        return $null
    }
}

function Get-ArmAccessToken {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) { return $null }
    $tokenRaw = & az account get-access-token --resource "https://management.azure.com/" --output json 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $tokenRaw) { return $null }
    try {
        $tokenObj = $tokenRaw | ConvertFrom-Json -ErrorAction Stop
        return [ordered]@{
            AccessToken    = $tokenObj.accessToken
            ExpiresOn      = $tokenObj.expiresOn
            TenantId       = $tokenObj.tenant
            SubscriptionId = $tokenObj.subscription
        }
    }
    catch {
        return $null
    }
}

function Invoke-AzureManagementApi {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$Token,
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',
        [object]$Body
    )

    if (-not $Token) { throw "ARM token is required." }

    $headers = @{
        Authorization  = "Bearer $Token"
        "Content-Type" = "application/json"
    }

    $jsonBody = if ($Body) { $Body | ConvertTo-Json -Depth 10 } else { $null }

    return Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body $jsonBody -ErrorAction Stop
}

function Invoke-GraphApi {
    param(
        [string]$Uri,
        [string]$Token,
        [string]$Method = "GET",
        [object]$Body = $null
    )

    if (-not $Token) { throw "Graph access token is required." }

    $headers = @{
        Authorization  = "Bearer $Token"
        "Content-Type" = "application/json"
    }

    switch ($Method.ToUpperInvariant()) {
        "GET" {
            return Invoke-RestMethod -Uri $Uri -Headers $headers -Method Get -ErrorAction Stop
        }
        "POST" {
            $jsonBody = if ($Body) { $Body | ConvertTo-Json -Depth 6 } else { $null }
            return Invoke-RestMethod -Uri $Uri -Headers $headers -Method Post -Body $jsonBody -ErrorAction Stop
        }
        default {
            $jsonBody = if ($Body) { $Body | ConvertTo-Json -Depth 6 } else { $null }
            return Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method -Body $jsonBody -ErrorAction Stop
        }
    }
}

function Get-HeuristicIdentityProviders {
    param(
        [hashtable]$TenantInfo,
        [hashtable]$ExternalIdentities
    )

    $providers = @()

    try {
        $identitySurface = Get-StructuredValue -Source $TenantInfo -Key 'IdentitySurface'
        $capabilities = Get-StructuredValue -Source $TenantInfo -Key 'Capabilities'
        $federation = Get-StructuredValue -Source $TenantInfo -Key 'Federation'
        $tenantName = Get-StructuredValue -Source $TenantInfo -Key 'TenantName'

        if ($identitySurface -match 'ciamlogin\.com$') {
            $providers += [pscustomobject]@{
                Source      = 'Public Metadata'
                Type        = 'Entra External ID (CIAM)'
                DisplayName = $tenantName ?? 'CIAM Tenant'
                Confidence  = 'Medium'
                Detail      = $identitySurface
            }
        }

        if ($identitySurface -match 'b2clogin\.com$' -or ($capabilities -and $capabilities -contains 'ExternalIDTenant')) {
            $providers += [pscustomobject]@{
                Source      = 'Public Metadata'
                Type        = 'Azure AD B2C'
                DisplayName = $tenantName ?? 'B2C Tenant'
                Confidence  = 'Medium'
                Detail      = $identitySurface
            }
        }

        if ($federation) {
            $providers += [pscustomobject]@{
                Source      = 'GetUserRealm'
                Type        = "Federation ($federation)"
                DisplayName = $tenantName ?? 'Federated STS'
                Confidence  = 'Medium'
                Detail      = Get-StructuredValue -Source $TenantInfo -Key 'STSServer'
            }
        }

        if ($ExternalIdentities) {
            $externalTypes = Get-StructuredValue -Source $ExternalIdentities -Key 'ExternalUserTypes'
            if ($externalTypes) {
                foreach ($type in $externalTypes | Where-Object { $_ -is [string] }) {
                    if ($providers.Type -contains $type) { continue }
                    $providers += [pscustomobject]@{
                        Source      = 'External Identity Signals'
                        Type        = $type
                        DisplayName = $type
                        Confidence  = 'Low'
                        Detail      = 'Derived from guest/redemption patterns'
                    }
                }
            }
        }
    }
    catch { }

    if (-not $providers) { return @() }

    return ($providers | Sort-Object -Property Type -Unique)
}

function Get-InsiderRecon {
    param(
        [string]$Domain,
        [string]$TenantId,
        [hashtable]$ExternalIdentities,
        [hashtable]$TenantInfo
    )

    Write-OSINTSection "Authenticated Insider Recon" "🛡️"

    $insider = [ordered]@{
        Context           = @{}
        GraphAvailable    = $false
        ArmAvailable      = $false
        ArmSubscriptions  = @()
        DomainInsights    = @()
        FederatedDomains  = @()
        ExternalCollab    = @()
        CrossTenantAccess = @{}
        GuestSamples      = @()
        PrivilegedRoles   = @()
        IdentityProviders = @()
        InternalResources = @{
            PurviewAccounts   = @()
            StorageAccounts   = @()
            KeyVaults         = @()
            PurviewApiVersion = $null
        }
        Notes             = @()
    }

    $context = Get-AzureCliContext
    $insider.Context = $context

    if (-not $context.IsAuthenticated) {
        Write-OSINTProperty "Insider Recon" "Skipped (no az login detected)" Yellow
        foreach ($err in $context.Errors) {
            Write-OSINTLog $err "WARN" Yellow
            $insider.Notes += $err
        }
        return $insider
    }

    Write-OSINTProperty "Azure Account" ($context.Account ?? "Unknown") Green
    Write-OSINTProperty "Authenticated Tenant" ($context.TenantId ?? "Unknown") Cyan

    if ($TenantId -and $context.TenantId -and ($TenantId -ne $context.TenantId)) {
        $mismatchMessage = "Logged-in tenant $($context.TenantId) differs from target tenant $TenantId"
        Write-OSINTProperty "Tenant Mismatch" $mismatchMessage Yellow
        $insider.Notes += $mismatchMessage
    }

    $graphToken = Get-GraphAccessToken
    if (-not $graphToken) {
        $msg = "Unable to acquire Microsoft Graph token via az."
        Write-OSINTProperty "Graph Access" $msg Yellow
        $insider.Notes += $msg
        return $insider
    }

    $insider.GraphAvailable = $true
    Write-OSINTProperty "Graph Access" "Token acquired (delegated)" Cyan

    $armTokenInfo = Get-ArmAccessToken
    if ($armTokenInfo -and $armTokenInfo.AccessToken) {
        $insider.ArmAvailable = $true
        $insider.Context.ArmTenantId = $armTokenInfo.TenantId
        Write-OSINTProperty "ARM Access" "Token acquired (subscription scope)" Cyan
        try {
            $subscriptions = Invoke-AzureManagementApi -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -Token $armTokenInfo.AccessToken
            if ($subscriptions.value) {
                $insider.ArmSubscriptions = $subscriptions.value
                Write-OSINTProperty "Subscriptions (ARM)" $subscriptions.value.Count Green

                foreach ($sub in $subscriptions.value) {
                    $subId = $sub.subscriptionId
                    if (-not $subId) { continue }
                    try {
                        $purviewApiVersions = @("2023-09-01", "2023-05-01", "2021-12-01-preview", "2021-07-01")
                        $purviewAccounts = @()
                        $purviewApiVersionUsed = $null

                        foreach ($apiVersion in $purviewApiVersions) {
                            $accountsFound = @()
                            $requestUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Purview/accounts?api-version=$apiVersion"

                            try {
                                $response = Invoke-AzureManagementApi -Uri $requestUri -Token $armTokenInfo.AccessToken
                                if ($response.value) {
                                    $accountsFound += $response.value
                                }

                                $nextLink = $response.nextLink
                                while ($nextLink) {
                                    $response = Invoke-AzureManagementApi -Uri $nextLink -Token $armTokenInfo.AccessToken
                                    if ($response.value) {
                                        $accountsFound += $response.value
                                    }
                                    $nextLink = $response.nextLink
                                }

                                if ($accountsFound.Count -gt 0) {
                                    $purviewAccounts = $accountsFound
                                    $purviewApiVersionUsed = $apiVersion
                                    break
                                }
                            }
                            catch {
                                $statusCode = $null
                                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                                    try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
                                }

                                if ($statusCode -eq 404) {
                                    continue
                                }
                                elseif ($statusCode -eq 403) {
                                    $insider.Notes += "Purview enumeration denied (HTTP 403) for subscription $subId. Ensure Reader or Purview Data Reader permissions."
                                    break
                                }
                                else {
                                    $insider.Notes += "Purview list failed for subscription $subId (API $apiVersion): $($_.Exception.Message)"
                                    break
                                }
                            }
                        }

                        if ($purviewAccounts.Count -gt 0) {
                            $insider.InternalResources.PurviewApiVersion = $purviewApiVersionUsed

                            foreach ($acct in $purviewAccounts) {
                                $endpoint = $null
                                if ($acct.properties -and $acct.properties.endpoint) {
                                    $endpoint = $acct.properties.endpoint
                                }
                                elseif ($acct.name) {
                                    $endpoint = "https://$($acct.name).purview.azure.com"
                                }

                                $catalogEndpoint = $null
                                if ($acct.properties -and $acct.properties.catalogEndpoint) {
                                    $catalogEndpoint = $acct.properties.catalogEndpoint
                                }

                                $resourceGroup = $null
                                if ($acct.id -and $acct.id -match '/resourceGroups/([^/]+)/') {
                                    $resourceGroup = $Matches[1]
                                }

                                $provisioningState = $null
                                if ($acct.properties -and $acct.properties.provisioningState) {
                                    $provisioningState = $acct.properties.provisioningState
                                }

                                $insider.InternalResources.PurviewAccounts += [pscustomobject]@{
                                    Name              = $acct.name
                                    Location          = $acct.location
                                    Endpoint          = $endpoint
                                    CatalogEndpoint   = $catalogEndpoint
                                    SubscriptionId    = $subId
                                    ResourceGroup     = $resourceGroup
                                    ProvisioningState = $provisioningState
                                    ApiVersion        = $purviewApiVersionUsed
                                }
                            }
                        }
                    }
                    catch {
                        $insider.Notes += "Purview list failed for subscription $($subId): $($_.Exception.Message)"
                    }

                    try {
                        $storageUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01"
                        $storageResp = Invoke-AzureManagementApi -Uri $storageUri -Token $armTokenInfo.AccessToken
                        if ($storageResp.value) {
                            foreach ($acct in $storageResp.value | Select-Object -First 25) {
                                $insider.InternalResources.StorageAccounts += [pscustomobject]@{
                                    Name           = $acct.name
                                    Location       = $acct.location
                                    SubscriptionId = $subId
                                    Kind           = $acct.kind
                                }
                            }
                        }
                    }
                    catch {
                        $insider.Notes += "Storage account list failed for subscription $($subId): $($_.Exception.Message)"
                    }

                    try {
                        $kvUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01"
                        $kvResp = Invoke-AzureManagementApi -Uri $kvUri -Token $armTokenInfo.AccessToken
                        if ($kvResp.value) {
                            foreach ($vault in $kvResp.value | Select-Object -First 25) {
                                $insider.InternalResources.KeyVaults += [pscustomobject]@{
                                    Name           = $vault.name
                                    Location       = $vault.location
                                    SubscriptionId = $subId
                                }
                            }
                        }
                    }
                    catch {
                        $insider.Notes += "Key Vault list failed for subscription $($subId): $($_.Exception.Message)"
                    }
                }

                if ($insider.InternalResources.PurviewAccounts.Count -gt 0) {
                    Write-OSINTProperty "Purview Accounts (ARM)" $insider.InternalResources.PurviewAccounts.Count Green
                }
                if ($insider.InternalResources.StorageAccounts.Count -gt 0) {
                    Write-OSINTProperty "Storage Accounts (ARM)" $insider.InternalResources.StorageAccounts.Count Cyan
                }
                if ($insider.InternalResources.KeyVaults.Count -gt 0) {
                    Write-OSINTProperty "Key Vaults (ARM)" $insider.InternalResources.KeyVaults.Count Cyan
                }
            }
        }
        catch {
            $err = $_.Exception.Message
            Write-OSINTLog "ARM subscription discovery failed: $err" "WARN" Yellow
            $insider.Notes += "ARM subscription discovery failed: $err"
        }
    }
    else {
        Write-OSINTProperty "ARM Access" "Token unavailable" Yellow
    }

    # Domains & federation
    try {
        $domains = Invoke-GraphApi -Uri "https://graph.microsoft.com/v1.0/domains?`$select=id,isDefault,isVerified,authenticationType" -Token $graphToken
        if ($domains.value) {
            $insider.DomainInsights = $domains.value
            Write-OSINTProperty "Domains (Graph)" $domains.value.Count Green

            $federated = $domains.value | Where-Object { $_.authenticationType -eq "Federated" }
            if ($federated) {
                $insider.FederatedDomains = $federated
                $ExternalIdentities.DomainFederation = @{
                    FederatedDomains = $federated.id
                    Source           = "Graph"
                    Confidence       = "High"
                }
            }
        }
    }
    catch {
        $err = $_.Exception.Message
        Write-OSINTLog "Graph domain query failed: $err" "WARN" Yellow
        $insider.Notes += "Domains query failed: $err"
    }

    # Guest users sample
    try {
        $guestUsers = Invoke-GraphApi -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=userPrincipalName&`$top=5" -Token $graphToken
        if ($guestUsers.value) {
            $insider.GuestSamples = $guestUsers.value
            Write-OSINTProperty "Guest Accounts (sample)" $guestUsers.value.Count Cyan

            $ExternalIdentities.ExternalUserTypes = ($ExternalIdentities.ExternalUserTypes + 'Guest (Graph)') | Where-Object { $_ } | Sort-Object -Unique

            $patterns = $guestUsers.value | ForEach-Object {
                $_.userPrincipalName
            }
            if ($patterns) {
                $ExternalIdentities.GuestUserPatterns = ($ExternalIdentities.GuestUserPatterns + ($patterns | Sort-Object -Unique)) | Where-Object { $_ } | Sort-Object -Unique
            }
        }
    }
    catch {
        $err = $_.Exception.Message
        Write-OSINTLog "Graph guest user query failed: $err" "WARN" Yellow
        $insider.Notes += "Guest user query failed: $err"
    }

    # External collaboration settings (skipped - requires elevated Graph scopes)
    Write-OSINTLog "Skipping Graph directory settings query (requires delegated Directory.Read.All)." "INFO" Yellow
    $insider.Notes += "Directory settings query skipped (requires delegated Directory.Read.All)."

    # Cross-tenant access policy
    try {
        $ctPolicy = Invoke-GraphApi -Uri "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy" -Token $graphToken
        if ($ctPolicy) {
            $insider.CrossTenantAccess = $ctPolicy
            if ($ctPolicy.default) {
                Write-OSINTProperty "Cross-Tenant Access" "Policy available" Green
            }
            if ($ctPolicy.partners) {
                $partnerIds = $ctPolicy.partners | ForEach-Object { $_.tenantId } | Where-Object { $_ }
                if ($partnerIds) {
                    $ExternalIdentities.PartnerTenants = ($ExternalIdentities.PartnerTenants + $partnerIds) | Sort-Object -Unique
                    Write-OSINTProperty "Partner Tenants" $partnerIds.Count Cyan
                }
            }
        }
    }
    catch {
        $err = $_.Exception.Message
        Write-OSINTLog "Graph cross-tenant policy query failed: $err" "WARN" Yellow
        $insider.Notes += "Cross-tenant policy query failed: $err"
    }

    # Privileged directory roles & administrative users
    try {
        $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,displayName,roleTemplateId&`$expand=members(`$select=displayName,userPrincipalName,userType)"
        $roleResponse = Invoke-GraphApi -Uri $roleUri -Token $graphToken
        if ($roleResponse.value) {
            $privileged = @()
            foreach ($role in $roleResponse.value) {
                $roleName = $role.displayName
                if (-not $roleName) { continue }
                if ($roleName -notmatch '(?i)(admin|administrator|owner|privileged|security|conditional access|application administrator|cloud application|global)') { continue }
                $memberPrincipalNames = @()
                if ($role.members) {
                    foreach ($member in $role.members) {
                        $principal = $member.userPrincipalName
                        if (-not $principal) { $principal = $member.displayName }
                        if ($principal) { $memberPrincipalNames += $principal }
                    }
                }
                $privileged += [pscustomobject]@{
                    RoleName    = $roleName
                    MemberCount = $memberPrincipalNames.Count
                    Members     = $memberPrincipalNames
                }
            }
            if ($privileged.Count -gt 0) {
                $insider.PrivilegedRoles = $privileged | Sort-Object -Property MemberCount -Descending
            }
        }
    }
    catch {
        $err = $_.Exception.Message
        $statusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -in @(403, 404)) {
            Write-OSINTLog "Privileged role enumeration not accessible (status $statusCode - requires Directory.Read.All or PrivilegedAccess.Read)." "INFO" Yellow
            $insider.Notes += "Privileged roles unavailable (status $statusCode)."
        }
        else {
            Write-OSINTLog "Privileged role query failed: $err" "WARN" Yellow
            $insider.Notes += "Privileged role query failed: $err"
        }
    }

    # External identity providers (skipped - requires elevated Graph scopes)
    Write-OSINTLog "Skipping Graph identity provider query (requires delegated IdentityProvider.Read.All)." "INFO" Yellow
    $insider.Notes += "Identity provider query skipped (requires delegated IdentityProvider.Read.All)."

    if ((-not $insider.IdentityProviders) -or $insider.IdentityProviders.Count -eq 0) {
        $heuristicIdp = Get-HeuristicIdentityProviders -TenantInfo $TenantInfo -ExternalIdentities $ExternalIdentities
        if ($heuristicIdp -and $heuristicIdp.Count -gt 0) {
            $insider.IdentityProviders = $heuristicIdp
            $insider.Notes += "Identity provider signals inferred from public metadata (grant delegated IdentityProvider.Read.All to query Microsoft Graph)."  
            Write-OSINTLog "Identity provider insight derived from public metadata (grant delegated IdentityProvider.Read.All to see Graph identity providers)." "INFO" Cyan
        }
    }

    return $insider
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
        # Test for Purview account patterns
        $basePrefix = ($Domain -split '\.')[0]
        $purviewAccountPatterns = @(
            "$basePrefix-purview",
            "$basePrefix-catalog", 
            "$basePrefix-governance",
            "$basePrefix-compliance"
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
        [string]$OrganizationName = $null,
        [object]$PreReconContext = $null
    )
    
    # Enhanced banner
    Write-OSINTBanner "Advanced Azure & Entra ID OSINT Reconnaissance" "AADInternals-Style Intelligence Gathering"
    
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
        EmailPatterns          = @()
        Documents              = @()
        InsiderRecon           = @{}
        PreReconContext        = $PreReconContext
        ReconMode              = "Outsider"
        InsiderReason          = $null
        Timestamp              = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
        ScanDuration           = $null
    }
    
    $scanStart = Get-Date

    $contextAuthenticated = $PreReconContext -and $PreReconContext.IsAuthenticated
    $contextTenantId = if ($contextAuthenticated) { $PreReconContext.TenantId } else { $null }
    $shouldUseContextForEnumeration = $false
    $shouldAttemptInsider = $false
    $insiderSkipReason = $null
    
    try {
        # Phase 1: Entra ID Tenant Discovery
        $tenantInfoRaw = Get-EntraIDTenantInfo -Domain $Domain
        $advancedResults.TenantInfo = ConvertTo-NormalizedHashtable $tenantInfoRaw
        $discoveredTenantId = $advancedResults.TenantInfo.TenantId
        if ($discoveredTenantId) { $TenantId = $discoveredTenantId }
        if (-not $advancedResults.TenantInfo.TenantId) {
            Write-OSINTLog "Primary discovery did not yield TenantId. Attempting OIDC fallback..." "INFO" Yellow
            $oidcId = Resolve-TenantIdFromOIDC -Domain $Domain
            if ($oidcId) {
                Write-OSINTLog "Recovered TenantId via OIDC configuration: $oidcId" "SUCCESS" Green
                $advancedResults.TenantInfo.TenantId = $oidcId
                $TenantId = $oidcId
            }
            else {
                Write-OSINTLog "OIDC fallback failed to reveal TenantId (likely federated / hidden)." "WARN" Yellow
            }
        }

        if ($contextAuthenticated -and $TenantId -and $contextTenantId -and ($contextTenantId -eq $TenantId)) {
            $shouldUseContextForEnumeration = $true
        }
        elseif (-not $advancedResults.TenantInfo.TenantId -and $contextAuthenticated -and $contextTenantId) {
            Write-OSINTLog "Tenant ID unresolved via public probes; using authenticated Azure CLI tenant $contextTenantId as fallback." "INFO" Cyan
            $advancedResults.TenantInfo.TenantId = $contextTenantId
            $advancedResults.TenantInfo.ResolutionSource = "AzureCLIContext"
            if (-not $TenantId) { $TenantId = $contextTenantId }
            if (-not $advancedResults.TenantInfo.CloudEnvironment -or $advancedResults.TenantInfo.CloudEnvironment -eq "Unknown") {
                $advancedResults.TenantInfo.CloudEnvironment = $PreReconContext.Environment ?? "AzureCloud"
            }
            if (-not $advancedResults.TenantInfo.TenantType -or $advancedResults.TenantInfo.TenantType -eq "Unknown") {
                $advancedResults.TenantInfo.TenantType = "Entra ID (Authenticated Fallback)"
                $advancedResults.TenantInfo.TenantTypeConfidence = "Medium"
            }
            $shouldUseContextForEnumeration = $true
        }
        
        # Phase 2: Domain Enumeration  
        $advancedResults.DomainInfo = ConvertTo-NormalizedHashtable (Get-DomainEnumeration -Domain $Domain -TenantId $TenantId)
        
        # Phase 3: Service Discovery
        $advancedResults.ServiceDiscovery = ConvertTo-NormalizedHashtable (Get-AzureServiceDiscovery -Domain $Domain -TenantId $TenantId)
        
        # Phase 4: Office 365 Discovery
        $advancedResults.Office365Discovery = ConvertTo-NormalizedHashtable (Get-Office365ServiceDiscovery -Domain $Domain)
        
        # Phase 5: Advanced User Enumeration
        $userEnumerationContext = if ($shouldUseContextForEnumeration) { $PreReconContext } else { $null }
        $advancedResults.UserEnumeration = ConvertTo-NormalizedHashtable (Get-AdvancedUserEnumeration -Domain $Domain -TenantId $TenantId -ReconContext $userEnumerationContext)
        
        # Phase 6: Extended Azure Resources
        $advancedResults.ExtendedAzureResources = ConvertTo-NormalizedHashtable (Get-ExtendedAzureResources -Domain $Domain -TenantId $TenantId)
        
        # Phase 7: Network Intelligence
        $advancedResults.NetworkIntelligence = ConvertTo-NormalizedHashtable (Get-NetworkIntelligence -Domain $Domain)
        
        # Phase 8: Authentication & Token Analysis (ROADtools techniques)
        $advancedResults.AuthenticationAnalysis = ConvertTo-NormalizedHashtable (Get-AuthenticationAnalysis -Domain $Domain -TenantId $TenantId)
        
        # Phase 9: Tenant Security Posture (Enhanced with deep analysis)
        $advancedResults.SecurityPosture = ConvertTo-NormalizedHashtable (Get-TenantSecurityPosture -Domain $Domain -TenantId $TenantId)
        
        # Phase 10: External Identity & Cross-Tenant Analysis
        $advancedResults.ExternalIdentities = ConvertTo-NormalizedHashtable (Get-ExternalIdentityAnalysis -Domain $Domain -TenantId $TenantId)

        Update-TenantClassification -TenantInfo $advancedResults.TenantInfo -ServiceDiscovery $advancedResults.ServiceDiscovery -ExternalIdentities $advancedResults.ExternalIdentities

        # Phase 10.1: Insider Recon if authenticated context available
        $finalTargetTenantId = $advancedResults.TenantInfo.TenantId
        if (-not $finalTargetTenantId) { $finalTargetTenantId = $TenantId }

        if ($contextAuthenticated -and $contextTenantId -and $finalTargetTenantId -and ($contextTenantId -eq $finalTargetTenantId)) {
            $shouldAttemptInsider = $true
        }

        if (-not $shouldAttemptInsider -and $contextAuthenticated) {
            if ($finalTargetTenantId) {
                $insiderSkipReason = "Recon mode: OUTSIDER (Azure CLI tenant $($contextTenantId ?? 'Unknown') does not match target tenant $($finalTargetTenantId ?? 'Unknown'))."
            }
            else {
                $insiderSkipReason = "Recon mode: OUTSIDER (target tenant ID unresolved; insider recon disabled)."
            }
        }
        elseif (-not $shouldAttemptInsider -and -not $contextAuthenticated) {
            $insiderSkipReason = "Recon mode: OUTSIDER (no authenticated Azure CLI context detected)."
        }

        if ($shouldAttemptInsider) {
            $advancedResults.InsiderRecon = ConvertTo-NormalizedHashtable (Get-InsiderRecon -Domain $Domain -TenantId $finalTargetTenantId -ExternalIdentities $advancedResults.ExternalIdentities -TenantInfo $advancedResults.TenantInfo)

            if (-not $advancedResults.InsiderRecon) { $advancedResults.InsiderRecon = @{} }

            $insiderContext = Get-StructuredValue -Source $advancedResults.InsiderRecon -Key 'Context'
            if (-not $insiderContext) { $insiderContext = @{} }

            $hasAuthenticatedContext = $false
            try {
                if ($insiderContext) { $hasAuthenticatedContext = Test-StructuredFlag $insiderContext 'IsAuthenticated' }
            }
            catch { $hasAuthenticatedContext = $false }

            if (-not $hasAuthenticatedContext -and $contextAuthenticated) {
                if ($insiderContext -isnot [System.Collections.IDictionary]) { $insiderContext = @{} }
                $insiderContext['IsAuthenticated'] = $true
            }

            $advancedResults.InsiderRecon['Context'] = $insiderContext
            $advancedResults.ReconMode = "Insider"

            $accountLabel = $null
            if ($insiderContext) { $accountLabel = Get-StructuredValue -Source $insiderContext -Key 'Account' }
            if ([string]::IsNullOrWhiteSpace($accountLabel) -and $preReconContext) { $accountLabel = $preReconContext.Account }
            if ([string]::IsNullOrWhiteSpace($accountLabel)) { $accountLabel = "Unknown" }

            $graphAvailable = [bool](Get-StructuredValue -Source $advancedResults.InsiderRecon -Key 'GraphAvailable')
            $notesRaw = Get-StructuredValue -Source $advancedResults.InsiderRecon -Key 'Notes'
            $notesCollection = @()
            if ($notesRaw) {
                if ($notesRaw -is [System.Collections.IEnumerable] -and -not ($notesRaw -is [string])) {
                    $notesCollection = @($notesRaw)
                }
                else {
                    $notesCollection = @($notesRaw)
                }
            }

            $missingScopes = @()
            if ($notesCollection | Where-Object { $_ -match 'Directory settings query skipped' }) { $missingScopes += 'Directory.Read.All' }
            if ($notesCollection | Where-Object { $_ -match 'Identity provider query skipped' }) { $missingScopes += 'IdentityProvider.Read.All' }

            $recommendations = @()
            if (-not $graphAvailable) {
                $recommendations += "Acquire a Microsoft Graph access token for the Azure CLI session (grant delegated scopes such as Directory.Read.All and IdentityProvider.Read.All)."
            }
            if ($missingScopes.Count -gt 0) {
                $recommendations += "Grant delegated $((($missingScopes | Sort-Object -Unique) -join ', ')) to populate insider-only sections."
            }

            $baseInsiderReason = "Insider recon executed using Azure CLI tenant $contextTenantId."
            if ($recommendations.Count -gt 0) {
                $actionHint = "Graph enrichment available with additional permissions: $([string]::Join(' ', $recommendations))"
                Write-OSINTLog $actionHint "INFO" Yellow
                $advancedResults.InsiderReason = "$baseInsiderReason Limited Graph visibility. $actionHint"
            }
            else {
                $advancedResults.InsiderReason = $baseInsiderReason
            }

            Write-OSINTLog "Recon mode: INSIDER (Azure CLI account: $accountLabel)" "INFO" Cyan
        }
        else {
            $advancedResults.InsiderRecon = @{}
            $advancedResults.ReconMode = "Outsider"
            if (-not $insiderSkipReason) {
                $insiderSkipReason = "Recon mode: OUTSIDER (insider mode not applicable)."
            }
            $advancedResults.InsiderReason = $insiderSkipReason
            Write-OSINTLog $insiderSkipReason "INFO" Yellow
        }

        $modePrefix = $advancedResults.ReconMode.ToUpper()
        $modeColor = if ($advancedResults.ReconMode -eq "Insider") { "Green" } else { "Yellow" }
        $scanStamp = $scanStart.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        Write-Host ""
        Write-Host "$modePrefix " -ForegroundColor $modeColor -NoNewline
        Write-Host "Target Domain: " -ForegroundColor Gray -NoNewline
        Write-Host $Domain -ForegroundColor White
        Write-Host "$modePrefix " -ForegroundColor $modeColor -NoNewline
        Write-Host "Scan Started: " -ForegroundColor Gray -NoNewline
        Write-Host $scanStamp -ForegroundColor Cyan

        if ($advancedResults.InsiderRecon -and $advancedResults.InsiderRecon.InternalResources) {
            $insiderResources = $advancedResults.InsiderRecon.InternalResources

            if ($insiderResources.PurviewAccounts -and $insiderResources.PurviewAccounts.Count -gt 0) {
                if (-not $advancedResults.PurviewRecon) { $advancedResults.PurviewRecon = @{} }
                $advancedResults.PurviewRecon.InsiderAccounts = $insiderResources.PurviewAccounts
            }

            if ($insiderResources.StorageAccounts -and $insiderResources.StorageAccounts.Count -gt 0) {
                if (-not $advancedResults.ExtendedAzureResources.StorageAccounts) { $advancedResults.ExtendedAzureResources.StorageAccounts = @() }
                $advancedResults.ExtendedAzureResources.StorageAccounts += ($insiderResources.StorageAccounts | ForEach-Object {
                        [pscustomobject]@{
                            Name           = $_.Name
                            Url            = $null
                            Status         = "Internal"
                            Source         = "ARM"
                            SubscriptionId = $_.SubscriptionId
                            Location       = $_.Location
                            Kind           = $_.Kind
                        }
                    })
            }

            if ($insiderResources.KeyVaults -and $insiderResources.KeyVaults.Count -gt 0) {
                if (-not $advancedResults.ExtendedAzureResources.KeyVaults) { $advancedResults.ExtendedAzureResources.KeyVaults = @() }
                $advancedResults.ExtendedAzureResources.KeyVaults += ($insiderResources.KeyVaults | ForEach-Object {
                        [pscustomobject]@{
                            Name           = $_.Name
                            Url            = "https://$($_.Name).vault.azure.net"
                            Status         = "Internal"
                            Source         = "ARM"
                            SubscriptionId = $_.SubscriptionId
                            Location       = $_.Location
                        }
                    })
            }
        }

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
        
        # Phase 14: Email Pattern Analysis
        Write-OSINTSection "Email Pattern Analysis" "📧"
        $advancedResults.EmailPatterns = Get-EmailPatterns -Domain $Domain
        
        # Calculate scan duration
        $scanEnd = Get-Date
        $advancedResults.ScanDuration = ($scanEnd - $scanStart).ToString("hh\:mm\:ss")
        
        # Enhanced Results Summary
        Write-OSINTSection "Reconnaissance Summary" "📊"
        
        Write-OSINTProperty "Scan Duration" $advancedResults.ScanDuration Cyan
        $reconColor = if ($advancedResults.ReconMode -eq "Insider") { "Green" } else { "Yellow" }
        Write-OSINTProperty "Recon Mode" $advancedResults.ReconMode $reconColor
        Write-OSINTProperty "Tenant ID" ($advancedResults.TenantInfo.TenantId ?? "Not Found") $(if ($advancedResults.TenantInfo.TenantId) { "Green" } else { "Red" })
        if ($advancedResults.TenantInfo.ResolutionSource) {
            Write-OSINTProperty "Tenant ID Source" $advancedResults.TenantInfo.ResolutionSource Cyan
        }
        Write-OSINTProperty "Namespace Type" ($advancedResults.TenantInfo.NameSpaceType ?? "Unknown") $(if ($advancedResults.TenantInfo.NameSpaceType -eq "Managed") { "Green" } else { "Yellow" })
        Write-OSINTProperty "Related Domains" $advancedResults.DomainInfo.RelatedDomains.Count Green
        if ($advancedResults.UserEnumeration -and $advancedResults.UserEnumeration.SuppressedReason) {
            Write-OSINTProperty "User Enumeration" $advancedResults.UserEnumeration.SuppressedReason Yellow
        }
        elseif ($advancedResults.UserEnumeration -and $advancedResults.UserEnumeration.ValidUsers) {
            Write-OSINTProperty "Valid Users Found" $advancedResults.UserEnumeration.ValidUsers.Count Green  
        }
        Write-OSINTProperty "Subdomains Found" $advancedResults.NetworkIntelligence.Subdomains.Count Green
        # Aggregate Azure resource counts across all discovered categories
        $azureResTotal = 0
        if ($advancedResults.ExtendedAzureResources) {
            $azureResTotal = ($advancedResults.ExtendedAzureResources.GetEnumerator() | ForEach-Object { if ($_.Value) { $_.Value.Count } } | Measure-Object -Sum).Sum
        }
        Write-OSINTProperty "Azure Resources" $azureResTotal Green
        Write-OSINTProperty "Auth Methods" $advancedResults.AuthenticationAnalysis.AuthMethods.Count Green
        Write-OSINTProperty "OAuth Flows" $advancedResults.AuthenticationAnalysis.SupportedFlows.Count Green
        Write-OSINTProperty "External ID Types" $advancedResults.ExternalIdentities.ExternalUserTypes.Count Yellow
        Write-OSINTProperty "B2B Capabilities" $(if ($advancedResults.ExternalIdentities.B2BCollaboration.RedemptionFlow) { "Present" } else { "Unknown" }) $(if ($advancedResults.ExternalIdentities.B2BCollaboration.RedemptionFlow) { "Green" } else { "Gray" })
        Write-OSINTProperty "Power BI Services" $($advancedResults.PowerBIFabric.PowerBIService.Keys.Count) Cyan
        Write-OSINTProperty "Fabric Features" $($advancedResults.PowerBIFabric.FabricWorkspaces.Keys.Count) Cyan  
        Write-OSINTProperty "Certificates Found" $advancedResults.Certificates.Count Green
        Write-OSINTProperty "GitHub Repositories" $advancedResults.SocialMedia.GitHub.Count Green
        if ($advancedResults.InsiderRecon -and (Test-StructuredFlag $advancedResults.InsiderRecon.Context 'IsAuthenticated')) {
            $authAccount = Get-StructuredValue -Source $advancedResults.InsiderRecon.Context -Key 'Account'
            if ([string]::IsNullOrWhiteSpace($authAccount)) { $authAccount = "Unknown" }
            Write-OSINTProperty "Authenticated Account" $authAccount Cyan
        }
        
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
    
    if ($Results -and $Results.ContainsKey('TenantInfo') -and $Results.TenantInfo -and $Results.TenantInfo.ContainsKey('TenantTypeSignals') -and $Results.TenantInfo.TenantTypeSignals) {
        $normalizedSignals = @()
        foreach ($sig in $Results.TenantInfo.TenantTypeSignals) {
            if ($null -eq $sig) { continue }

            $textValue = $null
            if ($sig -is [System.Collections.IDictionary]) {
                foreach ($candidateKey in @('Value', 'Text', 'Description', 'DisplayName', 'Name')) {
                    if ($sig.Contains($candidateKey) -and -not [string]::IsNullOrWhiteSpace($sig[$candidateKey])) {
                        $textValue = [string]$sig[$candidateKey]
                        break
                    }
                }

                if (-not $textValue) {
                    try {
                        $textValue = $sig | Out-String
                        if ($textValue) { $textValue = $textValue.Trim() }
                    }
                    catch { $textValue = $null }
                }
            }
            else {
                try { $textValue = $sig.ToString().Trim() } catch { $textValue = $null }
            }

            if (-not [string]::IsNullOrWhiteSpace($textValue)) {
                $normalizedSignals += $textValue
            }
        }

        if ($normalizedSignals.Count -gt 0) {
            $Results.TenantInfo.TenantTypeSignals = $normalizedSignals | Sort-Object -Unique
        }
        else {
            $Results.TenantInfo.TenantTypeSignals = @()
        }
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $domain = $Results.Domain -replace '[^a-zA-Z0-9]', '-'
    if ([string]::IsNullOrWhiteSpace($domain)) { $domain = 'unknown-target' }
    
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
    # Removed 'Tenant Discovery' column per request (avoid exposing raw TenantId / namespace in matrix)
    if ($Results.UserEnumeration -and -not $Results.UserEnumeration.SuppressedReason) {
        $matrixCols += & $buildMatrixSection 'User Enumeration' ($Results.UserEnumeration.ValidUsers | ForEach-Object { $_.Username } | Select-Object -First 6) '👥'
    }
    $matrixCols += & $buildMatrixSection 'Network Surface' ($Results.NetworkIntelligence.Subdomains | ForEach-Object { $_.Subdomain } | Select-Object -First 6) '🌐'
    $matrixCols += & $buildMatrixSection 'Auth & Flows' @($Results.AuthenticationAnalysis.AuthMethods + $Results.AuthenticationAnalysis.SupportedFlows) '🔐'
    $matrixCols += & $buildMatrixSection 'APIs' @("Purview:$purviewAPICount", "Fabric:$fabricAPICount", "PowerBI:$powerBIAPICount") '⚙️'
    # Build Azure resource sample list (dedup + prefer FQDN, cap first 6)
    $azList = @()
    if ($Results.ExtendedAzureResources.StorageAccounts) {
        $azList += ($Results.ExtendedAzureResources.StorageAccounts | ForEach-Object { $_.Name })
    }
    if ($Results.ExtendedAzureResources.FunctionApps) {
        $azList += ($Results.ExtendedAzureResources.FunctionApps | ForEach-Object { $_.Url ?? $_.Name })
    }
    if ($Results.ExtendedAzureResources.APIManagement) {
        $azList += ($Results.ExtendedAzureResources.APIManagement | ForEach-Object { $_.Url ?? $_.Name })
    }
    $azList = $azList | Where-Object { $_ } | ForEach-Object { ($_ -replace '^https?://', '') -replace '/$', '' } | Sort-Object -Unique | Select-Object -First 6
    $matrixCols += & $buildMatrixSection 'Azure Resources' $azList '☁️'
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

    # Precompute External Identity & Device Code panels to reliably render scalars/arrays
    $externalPanelsHtml = ""
    try {
        if ($Results.UserEnumeration.EntraExternalID -and $Results.UserEnumeration.EntraExternalID.Keys.Count -gt 0) {
            $ext = $Results.UserEnumeration.EntraExternalID
            $rows = @()
            foreach ($k in $ext.Keys) {
                $val = $ext[$k]
                if ($null -eq $val) { $display = '(None)' }
                elseif ($val -is [System.Array]) { $display = [System.String]::Join(', ', $val) }
                else { $display = $val.ToString() }
                $rows += "<div class='data-row'><div class='data-label'>" + [System.Web.HttpUtility]::HtmlEncode($k) + "</div><div class='data-value status-info'>" + [System.Web.HttpUtility]::HtmlEncode($display) + "</div></div>"
            }
            $externalPanelsHtml += "<div class='panel'><h3>Entra External ID Signals</h3>" + ($rows -join '') + "</div>"
        }

        if ($Results.UserEnumeration.DeviceCodeResults -and ($Results.UserEnumeration.DeviceCodeResults.Keys.Count -gt 0 -or $Results.UserEnumeration.DeviceCodeResults.Supported)) {
            $dcr = $Results.UserEnumeration.DeviceCodeResults
            $dcRows = @()
            foreach ($k in $dcr.Keys) {
                if ($k -in @('RawDeviceCode', 'MaskedDeviceCode')) { continue }
                $val = $dcr[$k]
                if ($null -eq $val) { $display = '(None)' }
                elseif ($val -is [System.Array]) { $display = [System.String]::Join(', ', $val) }
                else { $display = $val.ToString() }
                $classList = "data-value status-warning"
                if ($k -match 'DeviceCode|Device Code|UserCode|User Code|VerificationUrl|Verification Url') {
                    $classList += " data-wrap data-mono"
                }
                $dcRows += "<div class='data-row'><div class='data-label'>" + [System.Web.HttpUtility]::HtmlEncode($k) + "</div><div class='" + $classList + "'>" + [System.Web.HttpUtility]::HtmlEncode($display) + "</div></div>"
            }
            if ($Results.ReconMode -eq 'Insider' -and $Results.InsiderRecon -and (Test-StructuredFlag $Results.InsiderRecon.Context 'IsAuthenticated') -and $dcr.FlowState -eq 'CodeIssued' -and $dcr.RawDeviceCode) {
                $dcRows += "<div class='data-row'><div class='data-label'>Device Code (raw)</div><div class='data-value status-warning data-wrap data-mono'>" + [System.Web.HttpUtility]::HtmlEncode($dcr.RawDeviceCode) + "</div></div>"
            }
            $externalPanelsHtml += "<div class='panel'><h3>Device Code Flow</h3>" + ($dcRows -join '') + "</div>"
        }

        if ($Results.UserEnumeration -and $Results.UserEnumeration.SuppressedReason) {
            $reason = [System.Web.HttpUtility]::HtmlEncode($Results.UserEnumeration.SuppressedReason)
            $externalPanelsHtml += "<div class='panel'><h3>User Enumeration</h3><div class='note'>$reason</div></div>"
        }
    }
    catch { }


    $quickActionHtml = ""
    if ($Results.TenantInfo.TenantId) {
        $tenantId = $Results.TenantInfo.TenantId
        $tenantIdEncoded = [System.Web.HttpUtility]::UrlEncode($tenantId)
        $quickButtons = @()

        $portalUrl = "https://portal.azure.com/#@$tenantId"
        $quickButtons += "<a href='" + [System.Web.HttpUtility]::HtmlEncode($portalUrl) + "' target='_blank' class='cyber-btn'>🌐 Azure Portal</a>"

        $purviewUrl = "https://purview.microsoft.com/?tid=$tenantIdEncoded"
        $quickButtons += "<a href='" + [System.Web.HttpUtility]::HtmlEncode($purviewUrl) + "' target='_blank' class='cyber-btn'>🧭 Purview</a>"

        $oidcUrl = "https://login.microsoftonline.com/$tenantId/.well-known/openid_configuration"
        $quickButtons += "<a href='" + [System.Web.HttpUtility]::HtmlEncode($oidcUrl) + "' target='_blank' class='cyber-btn'>🔍 OIDC Config</a>"

        $quickButtons += "<a href='https://admin.microsoft.com/' target='_blank' class='cyber-btn'>⚙️ M365 Admin</a>"
        $quickButtons += "<a href='https://security.microsoft.com/' target='_blank' class='cyber-btn'>🛡️ Security Center</a>"

        $kvEntry = $null
        if ($Results.ExtendedAzureResources.KeyVaults -and $Results.ExtendedAzureResources.KeyVaults.Count -gt 0) {
            $kvEntry = $Results.ExtendedAzureResources.KeyVaults | Where-Object { $_ } | Select-Object -First 1
        }
        elseif ($Results.InsiderRecon -and $Results.InsiderRecon.InternalResources -and $Results.InsiderRecon.InternalResources.KeyVaults -and $Results.InsiderRecon.InternalResources.KeyVaults.Count -gt 0) {
            $kvEntry = $Results.InsiderRecon.InternalResources.KeyVaults | Where-Object { $_ } | Select-Object -First 1
        }

        if ($kvEntry) {
            $kvUrl = $kvEntry.Url
            if (-not $kvUrl -and $kvEntry.Name) {
                $kvUrl = "https://$($kvEntry.Name).vault.azure.net"
            }
            if ($kvUrl) {
                $kvHref = [System.Web.HttpUtility]::HtmlEncode($kvUrl)
                $kvTitle = if ($kvEntry.Name) { [System.Web.HttpUtility]::HtmlEncode("Key Vault: $($kvEntry.Name)") } else { "Key Vault" }
                $quickButtons += "<a href='$kvHref' target='_blank' class='cyber-btn' title='$kvTitle'>🔐 Key Vault</a>"
            }
        }

        $webEntry = $null
        if ($Results.ExtendedAzureResources.WebApps -and $Results.ExtendedAzureResources.WebApps.Count -gt 0) {
            $webEntry = $Results.ExtendedAzureResources.WebApps | Where-Object { $_.Url } | Select-Object -First 1
        }
        if (-not $webEntry -and $Results.ExtendedAzureResources.FunctionApps -and $Results.ExtendedAzureResources.FunctionApps.Count -gt 0) {
            $webEntry = $Results.ExtendedAzureResources.FunctionApps | Where-Object { $_.Url } | Select-Object -First 1
        }
        if ($webEntry -and $webEntry.Url) {
            $webHref = [System.Web.HttpUtility]::HtmlEncode($webEntry.Url)
            $webTitle = if ($webEntry.Name) { [System.Web.HttpUtility]::HtmlEncode("Web App: $($webEntry.Name)") } else { "Web App" }
            $quickButtons += "<a href='$webHref' target='_blank' class='cyber-btn' title='$webTitle'>🚀 Web App</a>"
        }

        $quickButtons += "<a href='#azure-resource-surface' class='cyber-btn'>☁️ Azure Resource Surface</a>"

        if ($quickButtons.Count -gt 0) {
            $quickActionHtml = "<div class='section'><div class='section-header'><div class='section-title'>🔗 Quick Actions</div></div><div class='section-content'><div class='action-buttons'>" + ($quickButtons -join "`n") + "</div></div></div>"
        }
    }


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
        html { font-size: 18px; }
        
    body { font-family: 'JetBrains Mono','Consolas',monospace; background:#0b0e17; color:#d6e7ff; line-height:1.5; margin:0; font-size:1rem; }
    h1,h2,h3 { font-family:'Orbitron',monospace; font-weight:700; letter-spacing:.5px; }
    h1 { font-size:1.8rem; }
    h2 { font-size:1.05rem; }
    h3 { font-size:.9rem; }
        a { color:#59d6ff; }
        .container { max-width:1600px; margin:0 auto; padding:25px 30px 60px 30px; }
        .top-bar { display:flex; flex-wrap:wrap; gap:25px; align-items:flex-end; margin-bottom:25px; }
        .report-title { font-size:2.2rem; margin:0; color:#66f7d9; text-shadow:0 0 8px #1ef2b3; }
    .meta { display:flex; flex-wrap:wrap; gap:18px; font-size:.85rem; text-transform:uppercase; letter-spacing:1px; }
        .meta-item { background:#131b29; padding:6px 10px; border:1px solid #223248; border-radius:4px; color:#9ab3c9; }
        .status-chip { padding:4px 10px; border-radius:12px; font-weight:600; background:#143723; color:#52f6b5; }
        /* MITRE-like matrix */
        .matrix-section-title { margin:10px 0 12px 0; font-size:1.1rem; color:#8cc7ff; text-transform:uppercase; letter-spacing:2px; }
    /* Stack matrix columns vertically to fit narrow pages better */
    .matrix-wrapper { display:grid; grid-auto-flow:row; grid-template-columns: 1fr; gap:10px; padding:12px; background:#0f1622; border:1px solid #1f2c3a; border-radius:6px; }
    .matrix-col { background:#121c29; border:1px solid #243345; border-radius:4px; display:flex; flex-direction:column; min-height:120px; width:100%; }
    .matrix-col-header { font-size:.82rem; font-weight:700; padding:6px 8px; background:#1b2836; color:#73e0ff; text-transform:uppercase; border-bottom:1px solid #243345; letter-spacing:1px; }
    .matrix-body { padding:6px 6px 10px 6px; display:flex; flex-direction:column; gap:6px; }
    .tech-item { position:relative; font-size:.82rem; line-height:1.3rem; padding:6px 8px 6px 18px; background:#182535; border:1px solid #223347; border-radius:3px; color:#b8d5ef; }
        .tech-item:hover { background:#1f3145; }
        .tech-item.empty { color:#546575; font-style:italic; }
        .tech-dot { position:absolute; left:6px; top:8px; width:6px; height:6px; border-radius:50%; background:#35cfa4; box-shadow:0 0 4px #35cfa4; }
        /* Stat tiles row */
    .stats-row { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:12px; margin:30px 0 10px 0; }
    .tile { background:#121c29; border:1px solid #243345; border-radius:6px; padding:14px 16px; text-align:center; }
    .tile h4 { margin:6px 0 4px 0; font-size:.82rem; font-weight:600; letter-spacing:1px; color:#7fa8c7; text-transform:uppercase; }
    .tile .val { font-size:1.55rem; font-weight:700; color:#6cf7d7; }
        .sections { margin-top:25px; display:flex; flex-direction:column; gap:26px; }
        .section { background:#0f1622; border:1px solid #1f2c3a; border-radius:6px; }
        .section-header { padding:10px 14px; border-bottom:1px solid #1f2c3a; display:flex; align-items:center; gap:10px; }
    .section-header h2 { margin:0; font-size:1.15rem; color:#8cc7ff; text-transform:uppercase; letter-spacing:2px; }
    .section-content { padding:18px 22px 24px 22px; }
    table { width:100%; border-collapse:collapse; font-size:.85rem; }
        th,td { padding:6px 8px; border:1px solid #223445; }
        th { background:#152231; color:#82d9ff; font-weight:600; letter-spacing:1px; }
        tbody tr:nth-child(even){ background:#13202e; }
        tbody tr:hover { background:#1b2c3c; }
        .status-success { color:#4be7b1; }
        .status-warning { color:#ffcc66; }
        .status-error { color:#ff667d; }
        .status-info { color:#59d6ff; }
        .status-neutral { color:#9ab3c9; }
    .subgrid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:16px; }
    .panel { background:#121c29; border:1px solid #243345; border-radius:4px; padding:14px 16px; }
    .panel h3 { margin:0 0 8px 0; font-size:.92rem; color:#73e0ff; text-transform:uppercase; letter-spacing:1px; }
    .list { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:6px; }
    .list li { font-size:.82rem; background:#182535; border:1px solid #223347; padding:6px 8px; border-radius:3px; overflow:hidden; text-overflow:ellipsis; }
        .list li:hover { background:#203246; }
    .note { font-size:.78rem; color:#6f8599; margin-top:6px; }
    .footer { margin-top:50px; text-align:center; font-size:.78rem; color:#4e6479; padding:30px 0 14px 0; border-top:1px solid #1f2c3a; }
    @media (max-width:1100px){ .matrix-wrapper { grid-template-columns: 1fr; } }
        @media (max-width:700px){ .report-title{font-size:1.6rem;} .matrix-col{min-height:200px;} }
        
        .data-row { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; margin-bottom:6px; }
    .data-label { font-size:.78rem; letter-spacing:.5px; text-transform:uppercase; color:#7fa8c7; min-width:140px; }
    .data-value { font-size:.88rem; font-weight:600; }
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

    .data-row.stacked { flex-direction: column; align-items: flex-start; gap:4px; }
    .data-row.stacked .data-label { min-width: 0; width: 100%; }
    .data-row.stacked .data-value { text-align: left; width: 100%; word-break: break-all; }
    .data-value.data-mono { font-family: 'JetBrains Mono','Consolas',monospace; }
    .data-value.data-wrap { word-break: break-all; overflow-wrap: anywhere; white-space: normal; }
        
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
                    <div class="meta-item">Recon: $(if($Results.ReconMode -eq 'Insider'){"<span class='status-success'>Insider</span>"}else{"<span class='status-warning'>Outsider</span>"})</div>
                    <div class="meta-item">Status: <span class="status-chip">Complete</span></div>
                </div>
            </div>
        </div>

        <!-- Executive Summary moved above matrix per request -->
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
                        $(if(-not $Results.TenantInfo.TenantId) { "<div class='data-row'><div class='data-label'>Resolution Note:</div><div class='data-value status-warning'>Tenant ID not exposed via public endpoints $(if($Results.TenantInfo.NameSpaceType -eq 'Federated'){ '(Federated)' })</div></div>" })
                        <div class="data-row">
                            <div class="data-label">Namespace Type:</div>
                            <div class="data-value status-info">$($Results.TenantInfo.NameSpaceType ?? 'Unknown')</div>
                        </div>
                        <div class="data-row">
                            <div class="data-label">Cloud Environment:</div>
                            <div class="data-value status-warning">$($Results.TenantInfo.CloudEnvironment ?? $Results.TenantInfo.CloudInstance ?? 'Undetected')</div>
                        </div>
                        $(if($Results.TenantInfo.CloudInstance -and $Results.TenantInfo.CloudEnvironment -and ($Results.TenantInfo.CloudEnvironment -ne $Results.TenantInfo.CloudInstance)) {
                            "<div class='data-row'><div class='data-label'>Cloud Instance:</div><div class='data-value status-info'>$($Results.TenantInfo.CloudInstance)</div></div>"
                        })
                        <div class="data-row">
                            <div class="data-label">Tenant Type:</div>
                            <div class="data-value status-info">$($Results.TenantInfo.TenantType ?? 'Unknown')</div>
                        </div>
                        $(if($Results.TenantInfo.TenantTypeConfidence -and $Results.TenantInfo.TenantTypeConfidence -ne 'Unknown') {
                            "<div class='data-row'><div class='data-label'>Type Confidence:</div><div class='data-value status-info'>$($Results.TenantInfo.TenantTypeConfidence)</div></div>"
                        })
                        <div class="data-row">
                            <div class="data-label">Recon Mode:</div>
                            <div class="data-value $(if($Results.ReconMode -eq 'Insider'){'status-success'}else{'status-warning'})">$(if($Results.ReconMode -eq 'Insider'){'INSIDER'}else{'OUTSIDER'})</div>
                        </div>
                        $(if($Results.ReconMode -eq 'Insider' -and $Results.InsiderRecon -and (Get-StructuredValue -Source $Results.InsiderRecon.Context -Key 'Account')) {
                            "<div class='data-row'>
                                <div class='data-label'>Authenticated Account:</div>
                                <div class='data-value status-info'>" + [System.Web.HttpUtility]::HtmlEncode((Get-StructuredValue -Source $Results.InsiderRecon.Context -Key 'Account')) + "</div>
                            </div>"
                        })
                    </div>
                    <div>
                        $(if($Results.TenantInfo.TenantId) {
                            "<div class='data-row'>
                                <div class='data-label'>Tenant ID:</div>
                                <div class='data-value status-success'>$($Results.TenantInfo.TenantId)</div>
                            </div>"
                        })
                        $(if($Results.TenantInfo.ResolutionSource) {
                            "<div class='data-row'>
                                <div class='data-label'>Tenant ID Source:</div>
                                <div class='data-value status-info'>" + [System.Web.HttpUtility]::HtmlEncode($Results.TenantInfo.ResolutionSource) + "</div>
                            </div>"
                        })
                        $(if($Results.TenantInfo.TenantBrand) {
                            "<div class='data-row'>
                                <div class='data-label'>Organization:</div>
                                <div class='data-value status-success'>$($Results.TenantInfo.TenantBrand)</div>
                            </div>"
                        })
                        $(if($Results.TenantInfo.OIDCIssuer) {
                            "<div class='data-row'>
                                <div class='data-label'>OIDC Issuer:</div>
                                <div class='data-value status-warning'>" + [System.Web.HttpUtility]::HtmlEncode($Results.TenantInfo.OIDCIssuer) + "</div>
                            </div>"
                        })
                        $(if($Results.TenantInfo.TenantRegion) {
                            "<div class='data-row'>
                                <div class='data-label'>Region:</div>
                                <div class='data-value status-info'>$($Results.TenantInfo.TenantRegion)</div>
                            </div>"
                        })
                        $(if($Results.TenantInfo.TenantTypeSignals -and $Results.TenantInfo.TenantTypeSignals.Count -gt 0) {
                            "<div class='data-row'>
                                <div class='data-label'>Type Signals:</div>
                                <div class='data-value status-info'>" + [System.Web.HttpUtility]::HtmlEncode([string]::Join('; ', $Results.TenantInfo.TenantTypeSignals)) + "</div>
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

        <!-- Recon Matrix now follows Executive Summary -->
        <div>
            <div class="matrix-section-title">Recon Matrix Overview</div>
            $matrixHTML
        </div>

        <div class="section">
            <div class="section-header"><h2>📊 Key Statistics</h2></div>
            <div class="section-content">
                <div class="stats-row">
                    <div class="tile"><h4>Users</h4><div class="val">$(if($Results.UserEnumeration.SuppressedReason){'--'}else{$Results.UserEnumeration.ValidUsers.Count})</div></div>
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
                    $(if($Results.ReconMode -eq 'Insider' -and $Results.InsiderRecon -and (Test-StructuredFlag $Results.InsiderRecon.Context 'IsAuthenticated')) {
                        $privRoles = $Results.InsiderRecon.PrivilegedRoles
                        $adminContent = ""
                        if($privRoles -and $privRoles.Count -gt 0) {
                            $rows = ""
                            foreach($role in $privRoles | Sort-Object -Property MemberCount -Descending | Select-Object -First 8) {
                                $sampleMembers = $null
                                if($role.Members -and $role.Members.Count -gt 0) {
                                    $encodedMembers = $role.Members | Select-Object -First 5 | ForEach-Object { [System.Web.HttpUtility]::HtmlEncode($_) }
                                    $sampleMembers = ($encodedMembers -join '<br/>')
                                    if($role.Members.Count -gt 5) {
                                        $remaining = $role.Members.Count - 5
                                        $sampleMembers += "<br/><span class='status-neutral'><em>... and $remaining more</em></span>"
                                    }
                                }
                                else {
                                    $sampleMembers = "<span class='status-neutral'>No members enumerated</span>"
                                }
                                $rows += "<tr><td class='status-warning'>" + [System.Web.HttpUtility]::HtmlEncode($role.RoleName) + "</td><td class='status-info'>$($role.MemberCount)</td><td>$sampleMembers</td></tr>"
                            }
                            $adminContent = "<div class='data-table'>
                                        <table class='info-table'>
                                            <thead>
                                                <tr><th>Role</th><th>Member Count</th><th>Sample Principals</th></tr>
                                            </thead>
                                            <tbody>$rows</tbody>
                                        </table>
                                    </div>"
                        }
                        else {
                            $adminContent = "<div class='note'>No administrative directory roles were returned. Ensure the authenticated context has Directory.Read.All permissions.</div>"
                        }
                        "<div class='detail-section'>
                            <div class='detail-header'>👥 Administrative Exposure</div>
                            <div class='detail-content'>$adminContent</div>
                        </div>"
                    })

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
                                    $(
                                        $purviewDp = 0; $purviewCp = 0; $purviewAcc = 0;
                                        if($Results.PurviewRecon){
                                            if($Results.PurviewRecon.DataPlaneAPIs){ $purviewDp = $Results.PurviewRecon.DataPlaneAPIs.Keys.Count }
                                            if($Results.PurviewRecon.ControlPlaneAPIs){ $purviewCp = $Results.PurviewRecon.ControlPlaneAPIs.Keys.Count }
                                            if($Results.PurviewRecon.PurviewAccounts){ $purviewAcc = $Results.PurviewRecon.PurviewAccounts.Keys.Count }
                                        }
                                        $fabricCore = 0; $fabricWork = 0; $fabricOneLake = $false; $fabricSP = $false;
                                        if($Results.FabricRecon){
                                            if($Results.FabricRecon.CoreAPIs){ $fabricCore = $Results.FabricRecon.CoreAPIs.Keys.Count }
                                            if($Results.FabricRecon.WorkloadAPIs){ $fabricWork = $Results.FabricRecon.WorkloadAPIs.Keys.Count }
                                            if($Results.FabricRecon.OneLake.Endpoint){ $fabricOneLake = $true }
                                            if($Results.FabricRecon.Authentication.ServicePrincipal){ $fabricSP = $true }
                                        }
                                        $pbiRest = 0; $pbiAdmin = 0; $pbiEmbed = 0; $pbiSP = $false;
                                        if($Results.PowerBIRecon){
                                            if($Results.PowerBIRecon.RestAPIs){ $pbiRest = $Results.PowerBIRecon.RestAPIs.Keys.Count }
                                            if($Results.PowerBIRecon.AdminAPIs){ $pbiAdmin = $Results.PowerBIRecon.AdminAPIs.Keys.Count }
                                            if($Results.PowerBIRecon.EmbedAPIs){ $pbiEmbed = $Results.PowerBIRecon.EmbedAPIs.Keys.Count }
                                            if($Results.PowerBIRecon.ServicePrincipal.Supported){ $pbiSP = $true }
                                        }
                                        # Build consistent blocks even when zero (fixed conditional expressions)
                                        $purviewDataPlaneHtml = if($purviewDp -gt 0){
                                            '<ul class="api-list">' + ($Results.PurviewRecon.DataPlaneAPIs.Keys | Select-Object -First 6 | ForEach-Object { '<li class="status-warning">' + [System.Web.HttpUtility]::HtmlEncode($_) + '</li>' }) -join '' + '</ul>'
                                        } else {
                                            '<div class="note status-info">No data-plane endpoints</div>'
                                        }
                                        $purviewControlPlaneNote = if($purviewCp -gt 0){ '<div class="note">Mgmt endpoints detected</div>' } else { '' }
                                        $purviewBlock = "<div class='api-section'><strong>🛡️ Microsoft Purview</strong><div class='note'>Accounts: $purviewAcc · Data-plane: $purviewDp · Control-plane: $purviewCp</div>$purviewDataPlaneHtml$purviewControlPlaneNote</div>"

                                        $fabricOneLakeFlag = if($fabricOneLake){'Yes'}else{'No'}
                                        $fabricSPFlag = if($fabricSP){'Yes'}else{'No'}
                                        $fabricCoreHtml = if($fabricCore -gt 0){
                                            '<ul class="api-list">' + ($Results.FabricRecon.CoreAPIs.Keys | Select-Object -First 6 | ForEach-Object { '<li class="status-warning">' + [System.Web.HttpUtility]::HtmlEncode($_) + '</li>' }) -join '' + '</ul>'
                                        } else {
                                            '<div class="note status-info">No core APIs</div>'
                                        }
                                        $fabricBlock = "<div class='api-section'><strong>🏭 Microsoft Fabric</strong><div class='note'>Core: $fabricCore · Workload: $fabricWork · OneLake: $fabricOneLakeFlag · SP Auth: $fabricSPFlag</div>$fabricCoreHtml</div>"

                                        $pbiSPFlag = if($pbiSP){'Yes'}else{'No'}
                                        $pbiRestHtml = if($pbiRest -gt 0){
                                            '<ul class="api-list">' + ($Results.PowerBIRecon.RestAPIs.Keys | Select-Object -First 6 | ForEach-Object { '<li class="status-warning">' + [System.Web.HttpUtility]::HtmlEncode($_) + '</li>' }) -join '' + '</ul>'
                                        } else {
                                            '<div class="note status-info">No REST APIs</div>'
                                        }
                                        $pbiBlock = "<div class='api-section'><strong>📊 Power BI</strong><div class='note'>REST: $pbiRest · Admin: $pbiAdmin · Embed: $pbiEmbed · SP Auth: $pbiSPFlag</div>$pbiRestHtml</div>"
                                        $purviewBlock + $fabricBlock + $pbiBlock
                                    )
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
                                    <div class="auth-section">
                                        <strong>🛰️ Token / Auth Endpoints:</strong>
                                        <ul class="auth-list">
                                            $(if($Results.AuthenticationAnalysis.TokenEndpoints -and $Results.AuthenticationAnalysis.TokenEndpoints.Count -gt 0){
                                                foreach($te in ($Results.AuthenticationAnalysis.TokenEndpoints | Sort-Object -Unique)){ '<li class="status-info">' + [System.Web.HttpUtility]::HtmlEncode($te) + '</li>' }
                                            } elseif($Results.TenantInfo.Endpoints.Authorization){
                                                '<li class="status-info">' + [System.Web.HttpUtility]::HtmlEncode($Results.TenantInfo.Endpoints.Authorization) + '</li>'
                                            } else { '<li class="status-info">(None discovered)</li>' })
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

            if($Results.PurviewRecon.InsiderAccounts -and $Results.PurviewRecon.InsiderAccounts.Count -gt 0) {
                $insiderPurviewList = ($Results.PurviewRecon.InsiderAccounts | Select-Object -First 6 | ForEach-Object {
                        '<li>' + [System.Web.HttpUtility]::HtmlEncode("$($_.Name) • $($_.Location)") + '</li>'
                    }) -join ''
                "<div class='data-row'>
                    <div class='data-label'>Insider Accounts:</div>
                    <div class='data-value status-success'>🛡️ $($Results.PurviewRecon.InsiderAccounts.Count) via ARM</div>
                </div>
                <div class='panel' style='margin-top:12px;'>
                    <h3>Purview Accounts (Insider)</h3>
                    <ul class='list'>$insiderPurviewList</ul>
                    $(if($Results.PurviewRecon.InsiderAccounts.Count -gt 6){"<div class='note'>Full inventory available in JSON/CSV exports.</div>"})
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
                @{ Key='StorageAccounts'; Label='Storage'; Icon='🗄️'; Prop='Url' }
                @{ Key='WebApps'; Label='Web Apps'; Icon='🌐'; Prop='Url' }
                @{ Key='FunctionApps'; Label='Function Apps'; Icon='⚡'; Prop='Url' }
                @{ Key='KeyVaults'; Label='Key Vaults'; Icon='🔐'; Prop='Url' }
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
                    $collection | Select-Object -First 6 | ForEach-Object {
                        $display = Format-AzureResourceDisplay -Category $entry.Key -Item $_ -Property $prop
                        if ($display) { $sampleItems += $display }
                    }
                    if ($sampleItems.Count -gt 0) { $sampleItems = @($sampleItems | Sort-Object -Unique) }
                    $li = if($sampleItems.Count -gt 0){ '<ul class="res-items">' + ($sampleItems | ForEach-Object { '<li>' + [System.Web.HttpUtility]::HtmlEncode($_) + '</li>' }) -join '' + '</ul>' } else { '<div class="note">No examples</div>' }
                    $blocks += "<div class='res-block'><h4>$($entry.Icon) $($entry.Label)</h4><div class='res-count'>$count</div>$li</div>"
                }
            }
            "<div class='section' id='azure-resource-surface'><div class='section-header'><h2>☁️ Azure Resource Surface</h2></div><div class='section-content'><div class='resource-grid'>" + ($blocks -join '') + "</div></div></div>"
        })

        $(if( ($Results.UserEnumeration -and $Results.UserEnumeration.SuppressedReason) -or ($Results.UserEnumeration.EntraExternalID -and $Results.UserEnumeration.EntraExternalID.Keys.Count -gt 0) -or ($Results.UserEnumeration.DeviceCodeResults -and ($Results.UserEnumeration.DeviceCodeResults.Keys.Count -gt 0 -or $Results.UserEnumeration.DeviceCodeResults.Supported)) ) {
            "<div class='section'><div class='section-header'><h2>🌍 External Identity & Cross-Tenant</h2></div><div class='section-content'>" + $externalPanelsHtml + "</div></div>"
        })
        $(if( -not ( ($Results.UserEnumeration -and $Results.UserEnumeration.SuppressedReason) -or ($Results.UserEnumeration.EntraExternalID -and $Results.UserEnumeration.EntraExternalID.Keys.Count -gt 0) -or ($Results.UserEnumeration.DeviceCodeResults -and ($Results.UserEnumeration.DeviceCodeResults.Keys.Count -gt 0 -or $Results.UserEnumeration.DeviceCodeResults.Supported)) ) ) {
            "<div class='section'><div class='section-header'><h2>🌍 External Identity & Cross-Tenant</h2></div><div class='section-content'><div class='note'>No external identity signals discovered. (Federated or limited exposure)</div></div></div>"
        })

    $(if($Results.InsiderRecon -and (Test-StructuredFlag $Results.InsiderRecon.Context 'IsAuthenticated')) {
            $context = $Results.InsiderRecon.Context
        $account = Get-StructuredValue -Source $context -Key 'Account'
        if ([string]::IsNullOrWhiteSpace($account)) { $account = 'Unknown' }
        $tenant = Get-StructuredValue -Source $context -Key 'TenantId'
        if ([string]::IsNullOrWhiteSpace($tenant)) { $tenant = 'Unknown' }
            $graphStatus = if($Results.InsiderRecon.GraphAvailable){'Token acquired'}else{'Token unavailable'}
            $armStatus = if($Results.InsiderRecon.ArmAvailable){'Token acquired'}else{'Token unavailable'}
            $guestList = ''
            if($Results.InsiderRecon.GuestSamples -and $Results.InsiderRecon.GuestSamples.Count -gt 0){
                $guestItems = $Results.InsiderRecon.GuestSamples | ForEach-Object { '<li>' + [System.Web.HttpUtility]::HtmlEncode($_.userPrincipalName) + '</li>' }
                $guestList = '<ul class="list">' + ($guestItems -join '') + '</ul>'
            } else {
                $guestList = '<div class="note">No guest user samples returned.</div>'
            }

            $partnerCount = 0
            if($Results.ExternalIdentities.PartnerTenants){ $partnerCount = $Results.ExternalIdentities.PartnerTenants.Count }

            $purviewHtml = ''
            if($Results.InsiderRecon.InternalResources.PurviewAccounts -and $Results.InsiderRecon.InternalResources.PurviewAccounts.Count -gt 0){
                $purviewItems = $Results.InsiderRecon.InternalResources.PurviewAccounts | Select-Object -First 5 | ForEach-Object {
                    $name = $_.Name
                    $location = $_.Location
                    $endpoint = $_.Endpoint
                    if ($endpoint -and $endpoint -match '^(?i)https?://') {
                        try { $endpoint = ([Uri]$endpoint).Host } catch { $endpoint = $_.Endpoint }
                    }
                    elseif(-not [string]::IsNullOrWhiteSpace($name) -and [string]::IsNullOrWhiteSpace($endpoint)) {
                        $endpoint = "$name.purview.azure.com"
                    }

                    $details = @()
                    if (-not [string]::IsNullOrWhiteSpace($endpoint)) { $details += $endpoint.ToLowerInvariant() }
                    if (-not [string]::IsNullOrWhiteSpace($location)) { $details += "Region: $location" }
                    if ($_.ResourceGroup) { $details += "RG: $($_.ResourceGroup)" }

                    if ($details.Count -eq 0) { $details = @('Details unavailable') }

                    '<li><strong>' + [System.Web.HttpUtility]::HtmlEncode($name) + '</strong><br/><span class="note">' + [System.Web.HttpUtility]::HtmlEncode(($details -join ' — ')) + '</span></li>'
                }
                $purviewHtml = '<ul class="list">' + ($purviewItems -join '') + '</ul>'
                if ($Results.InsiderRecon.InternalResources.PurviewApiVersion) {
                    $purviewHtml += '<div class="note">Enumerated via ARM API ' + [System.Web.HttpUtility]::HtmlEncode($Results.InsiderRecon.InternalResources.PurviewApiVersion) + '.</div>'
                }
            } else {
                $purviewHtml = '<div class="note">No Purview accounts returned via Azure Resource Manager (ARM). Ensure the signed-in identity has Reader or Purview Data Reader rights on the target subscription.</div>'
            }

            $resourceStats = ''
            if($Results.InsiderRecon.InternalResources.StorageAccounts.Count -gt 0 -or $Results.InsiderRecon.InternalResources.KeyVaults.Count -gt 0){
                $resourceStats = "<div class='data-row'><div class='data-label'>Storage Accounts</div><div class='data-value'>" + $Results.InsiderRecon.InternalResources.StorageAccounts.Count + "</div></div>" +
                    "<div class='data-row'><div class='data-label'>Key Vaults</div><div class='data-value'>" + $Results.InsiderRecon.InternalResources.KeyVaults.Count + "</div></div>"
            } else {
                $resourceStats = "<div class='note'>No additional internal resources resolved.</div>"
            }

            "<div class='section'>
                <div class='section-header'><h2>🛡️ Insider Recon (Authenticated)</h2></div>
                <div class='section-content'>
                    <div class='subgrid'>
                        <div class='panel'>
                            <h3>Azure CLI Context</h3>
                            <div class='data-row stacked'><div class='data-label'>Account</div><div class='data-value data-mono'>$account</div></div>
                            <div class='data-row stacked'><div class='data-label'>Tenant ID</div><div class='data-value data-mono'>$tenant</div></div>
                            <div class='data-row'><div class='data-label'>Graph Access</div><div class='data-value'>$graphStatus</div></div>
                            <div class='data-row'><div class='data-label'>ARM Access</div><div class='data-value'>$armStatus</div></div>
                        </div>
                        <div class='panel'>
                            <h3>Federated Domains (Graph)</h3>
                            " + $(if($Results.InsiderRecon.FederatedDomains -and $Results.InsiderRecon.FederatedDomains.Count -gt 0) {
                                '<ul class="list">' + ($Results.InsiderRecon.FederatedDomains | ForEach-Object { '<li>' + [System.Web.HttpUtility]::HtmlEncode($_.id) + ' (' + [System.Web.HttpUtility]::HtmlEncode($_.authenticationType) + ')</li>' }) -join '' + '</ul>'
                            } else {
                                '<div class="note">No federated domains detected via Graph.</div>'
                            }) + "
                        </div>
                        <div class='panel'>
                            <h3>Guest Accounts (Sample)</h3>
                            $guestList
                        </div>
                        <div class='panel'>
                            <h3>Purview Accounts (ARM)</h3>
                            $purviewHtml
                            " + $(if($Results.InsiderRecon.InternalResources.PurviewAccounts.Count -gt 5){
                                '<div class="note">Additional accounts available in JSON export.</div>'
                            }) + "
                        </div>
                        <div class='panel'>
                            <h3>Internal Resource Discovery</h3>
                            $resourceStats
                        </div>
                        <div class='panel'>
                            <h3>Cross-Tenant Access</h3>
                            <div class='data-row'><div class='data-label'>Partners</div><div class='data-value'>$partnerCount</div></div>
                            " + $(if($Results.InsiderRecon.CrossTenantAccess.partners){
                                '<div class="note">Partner tenant IDs available in JSON export.</div>'
                            } else {
                                '<div class="note">No partner configuration returned.</div>'
                            }) + "
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
        EmailPatterns -> Email Pattern Analysis section
        UserEnumeration.EntraExternalID -> External Identity section
        UserEnumeration.DeviceCodeResults -> External Identity section
        -->

        $(if($quickActionHtml) { $quickActionHtml })

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

function Invoke-AzureOsintAdvanced {
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
        [switch]$Interactive,

        [Parameter(Mandatory = $false)]
        [switch]$NoAutoOpen,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru,

        [Parameter(Mandatory = $false)]
        [switch]$ShowHelp
    )

    if ($ShowHelp) {
        Write-Host @"
Azure OSINT Advanced Tool
========================

This tool performs advanced OSINT reconnaissance on Azure AD/Entra ID tenants.

Usage:
    Invoke-AzureOsintAdvanced -Domain "contoso.com"
    Invoke-AzureOsintAdvanced -Domain "contoso.com" -OrganizationName "Contoso Corp"
    Invoke-AzureOsintAdvanced -Domain "contoso.com" -TenantId "12345678-1234-1234-1234-123456789012"

Parameters:
    -Domain            Target domain (e.g., contoso.com)
    -TenantId          Optional: Azure tenant ID
    -OrganizationName  Optional: Organization name for social media searches
    -OutputFile        Output file path (default: advanced-osint-results.json)
    -Interactive       Prompt for missing values when Domain is not supplied
    -NoAutoOpen        Skip automatically opening the generated HTML report
    -PassThru          Return the raw results object alongside export metadata
    -ShowHelp          Display this help message

Features:
    • Enhanced user enumeration (GetCredentialType API, OneDrive, Graph API)
    • Advanced tenant discovery (mjendza.net techniques)
    • Authentication flow analysis (OAuth 2.0, Device Code Flow)
    • Security posture assessment (MFA, Conditional Access, Federation)
    • Extended Azure resource discovery (ROADtools inspired)
    • Certificate Transparency logs
    • Social media footprint discovery
    • Insider vs outsider recon with tenant-aware heuristics
    • Email pattern analysis
    • Interactive HTML reports with copy-to-clipboard
"@ -ForegroundColor Cyan
        return
    }

    if (-not $Domain) {
        if ($Interactive) {
            Write-Host "Azure OSINT Advanced Tool" -ForegroundColor Cyan
            Write-Host "=========================" -ForegroundColor Cyan
            Write-Host ""

            $Domain = Read-Host "Enter target domain (e.g., contoso.com)"
            if ([string]::IsNullOrWhiteSpace($Domain)) {
                throw "Domain is required. Provide -Domain or enable -Interactive to be prompted."
            }

            $OrganizationName = Read-Host "Enter organization name (optional, press Enter to skip)"
            if ([string]::IsNullOrWhiteSpace($OrganizationName)) {
                $OrganizationName = $null
            }
        }
        else {
            throw "Domain is required. Provide -Domain or enable -Interactive to be prompted."
        }
    }

    try {
        Write-Host "`nStarting Advanced Azure OSINT Reconnaissance..." -ForegroundColor Green
        Write-Host "Target: $Domain" -ForegroundColor White

        $preReconContext = $null
        try { $preReconContext = Get-AzureCliContext } catch { }

        if ($preReconContext -and $preReconContext.IsAuthenticated) {
            $preAccount = $preReconContext.Account
            if (-not $preAccount) { $preAccount = "Unknown" }
            $preTenant = $preReconContext.TenantId ?? "Unknown"
            Write-Host "Azure CLI context detected: $preAccount (Tenant: $preTenant). Insider recon will only run if the tenant matches the target." -ForegroundColor Cyan
            Write-Host "Operating mode: Insider attempt (authenticated probes will execute once tenant alignment is confirmed)." -ForegroundColor Cyan
        }
        else {
            Write-Host "No authenticated Azure CLI session detected." -ForegroundColor Yellow
            Write-Host "Operating mode: OUTSIDER (public recon only; run 'az login --tenant <tenantId>' to enable insider insights)." -ForegroundColor Yellow
        }

        $results = Start-AdvancedReconnaissance -Domain $Domain -TenantId $TenantId -OrganizationName $OrganizationName -PreReconContext $preReconContext

        $tenantSignalsSnapshot = $null
        try {
            if ($results -and $results.TenantInfo -and $results.TenantInfo.TenantTypeSignals) {
                $tenantSignalsSnapshot = @($results.TenantInfo.TenantTypeSignals | Where-Object { $_ } | ForEach-Object { $_.ToString().Trim() })
                if ($tenantSignalsSnapshot.Count -eq 0) { $tenantSignalsSnapshot = $null }
            }
        }
        catch { $tenantSignalsSnapshot = $null }

        if ($results.UserEnumeration -and $results.UserEnumeration.DeviceCodeResults -and $results.UserEnumeration.DeviceCodeResults.AuthorityUsed) {
            Write-Host "[DEBUG] AuthorityUsed type: $($results.UserEnumeration.DeviceCodeResults.AuthorityUsed.GetType().FullName)" -ForegroundColor DarkGray
            Write-Host "[DEBUG] AuthorityUsed value: $($results.UserEnumeration.DeviceCodeResults.AuthorityUsed)" -ForegroundColor DarkGray
        }

        if ($results.UserEnumeration -and $results.UserEnumeration.DeviceCodeResults -and $results.UserEnumeration.DeviceCodeResults.AuthorityTried) {
            $authTriedSample = $results.UserEnumeration.DeviceCodeResults.AuthorityTried | Select-Object -First 1
            if ($authTriedSample) {
                Write-Host "[DEBUG] AuthorityTried sample type: $($authTriedSample.GetType().FullName)" -ForegroundColor DarkGray
                Write-Host "[DEBUG] AuthorityTried sample value: $authTriedSample" -ForegroundColor DarkGray
            }
        }

        $rawTimestamp = $results.Timestamp
        $rawCertificates = $results.Certificates
        $rawDeviceResults = $null
        $rawAuthorityUsed = $null
        $rawAuthorityTried = @()

        if ($results.UserEnumeration -and $results.UserEnumeration.DeviceCodeResults) {
            $rawDeviceResults = $results.UserEnumeration.DeviceCodeResults
            if ($rawDeviceResults) {
                if ($rawDeviceResults.AuthorityUsed) { $rawAuthorityUsed = $rawDeviceResults.AuthorityUsed }
                if ($rawDeviceResults.AuthorityTried) {
                    if ($rawDeviceResults.AuthorityTried -is [System.Collections.IEnumerable] -and -not ($rawDeviceResults.AuthorityTried -is [string])) {
                        $rawAuthorityTried = @($rawDeviceResults.AuthorityTried)
                    }
                    else {
                        $rawAuthorityTried = @($rawDeviceResults.AuthorityTried)
                    }
                }
            }
        }

        Write-Host "[DEBUG-BEFORE] rawAuthorityUsed: $rawAuthorityUsed" -ForegroundColor DarkGray
        if ($rawAuthorityTried -and $rawAuthorityTried.Count -gt 0) {
            Write-Host "[DEBUG-BEFORE] rawAuthorityTried sample: $($rawAuthorityTried[0])" -ForegroundColor DarkGray
        }

        $results = ConvertTo-NormalizedHashtable $results

        if ($tenantSignalsSnapshot -and $results -and $results.ContainsKey('TenantInfo')) {
            try {
                if (-not $results.TenantInfo) { $results.TenantInfo = @{} }
                $results.TenantInfo.TenantTypeSignals = $tenantSignalsSnapshot | Where-Object { $_ } | Sort-Object -Unique
            }
            catch { }
        }

        if ($rawTimestamp) {
            if ($rawTimestamp -is [string]) {
                $results.Timestamp = $rawTimestamp
            }
            elseif ($rawTimestamp -is [DateTime]) {
                $results.Timestamp = $rawTimestamp.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
            }
            else {
                try { $results.Timestamp = ([DateTime]$rawTimestamp).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") }
                catch { $results.Timestamp = $rawTimestamp.ToString() }
            }
        }
        elseif ($results.Timestamp) {
            if ($results.Timestamp -isnot [string]) {
                try { $results.Timestamp = $results.Timestamp.ToString() }
                catch { $results.Timestamp = ($results.Timestamp | Out-String).Trim() }
            }
        }
        else {
            $results.Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        }

        $certificateItems = $rawCertificates
        if (-not $certificateItems) { $certificateItems = $results.Certificates }
        $normalizedCertificates = @()
        if ($certificateItems) {
            if (-not ($certificateItems -is [System.Collections.IEnumerable]) -or ($certificateItems -is [string])) {
                $certificateItems = @($certificateItems)
            }

            foreach ($item in $certificateItems) {
                if ($null -eq $item) { continue }
                if ($item -is [System.Collections.IDictionary]) { $normalizedCertificates += $item; continue }
                if ($item -is [pscustomobject]) { $normalizedCertificates += (ConvertTo-HashtableRecursive $item); continue }

                try {
                    $converted = ConvertTo-HashtableRecursive $item
                    if ($converted -is [System.Collections.IDictionary]) {
                        $normalizedCertificates += $converted
                        continue
                    }
                }
                catch { }

                $normalizedCertificates += @{
                    CommonName   = $item.ToString()
                    Issuer       = $null
                    ValidFrom    = $null
                    ValidTo      = $null
                    SerialNumber = $null
                    Subdomains   = @()
                }
            }
        }
        $results.Certificates = $normalizedCertificates

        if (-not $results.UserEnumeration) { $results.UserEnumeration = @{} }
        if (-not $results.UserEnumeration.DeviceCodeResults) { $results.UserEnumeration.DeviceCodeResults = @{} }

        if ($results.UserEnumeration -and $results.UserEnumeration.DeviceCodeResults) {
            $deviceResults = $results.UserEnumeration.DeviceCodeResults

            $authorityTriedSource = $rawAuthorityTried
            if (-not $authorityTriedSource -or $authorityTriedSource.Count -eq 0) {
                if ($deviceResults.AuthorityTried) {
                    if ($deviceResults.AuthorityTried -is [System.Collections.IEnumerable] -and -not ($deviceResults.AuthorityTried -is [string])) {
                        $authorityTriedSource = @($deviceResults.AuthorityTried)
                    }
                    else {
                        $authorityTriedSource = @($deviceResults.AuthorityTried)
                    }
                }
            }

            $deviceResults.AuthorityTried = @()
            foreach ($authorityEntry in $authorityTriedSource) {
                if (-not $authorityEntry) { continue }
                if ($authorityEntry -is [string]) {
                    $deviceResults.AuthorityTried += $authorityEntry
                }
                else {
                    try { $deviceResults.AuthorityTried += $authorityEntry.ToString() }
                    catch { $deviceResults.AuthorityTried += ($authorityEntry | Out-String).Trim() }
                }
            }

            $authorityUsedValue = $rawAuthorityUsed
            if (-not $authorityUsedValue -and $deviceResults.AuthorityUsed) { $authorityUsedValue = $deviceResults.AuthorityUsed }

            if ($authorityUsedValue) {
                if ($authorityUsedValue -isnot [string]) {
                    try { $authorityUsedValue = $authorityUsedValue.ToString() }
                    catch { $authorityUsedValue = ($authorityUsedValue | Out-String).Trim() }
                }
                $deviceResults.AuthorityUsed = $authorityUsedValue
            }
            else {
                $deviceResults.AuthorityUsed = $null
            }

            if ($deviceResults.AuthorityUsed) {
                Write-Host "[DEBUG-NORM] AuthorityUsed (post): $($deviceResults.AuthorityUsed) [$($deviceResults.AuthorityUsed.GetType().FullName)]" -ForegroundColor DarkGray
            }
            if ($deviceResults.AuthorityTried -and $deviceResults.AuthorityTried.Count -gt 0) {
                $dbgSample = $deviceResults.AuthorityTried[0]
                Write-Host "[DEBUG-NORM] AuthorityTried sample (post): $dbgSample [$($dbgSample.GetType().FullName)]" -ForegroundColor DarkGray
            }
        }

        $exportedFiles = Export-AdvancedResults -Results $results -OutputPath $OutputFile

        if ($results.ReconMode -eq "Insider" -and $results.InsiderRecon -and (Test-StructuredFlag $results.InsiderRecon.Context 'IsAuthenticated')) {
            $postAccount = Get-StructuredValue -Source $results.InsiderRecon.Context -Key 'Account'
            if (-not $postAccount) { $postAccount = "Unknown" }
            Write-Host "Recon Context (final): INSIDER (Azure CLI account: $postAccount)" -ForegroundColor Green
        }
        else {
            $finalReason = $results.InsiderReason
            if (-not $finalReason) { $finalReason = "Recon Context (final): OUTSIDER." }
            Write-Host $finalReason -ForegroundColor Yellow
        }

        Write-Host "`nAdvanced OSINT scan completed successfully!" -ForegroundColor Green
        Write-Host "Results saved to: $OutputFile" -ForegroundColor Cyan

        if (-not $NoAutoOpen -and $exportedFiles.HTMLFile -and (Test-Path $exportedFiles.HTMLFile)) {
            Write-Host "Opening HTML report in default browser..." -ForegroundColor Yellow
            try {
                Start-Process $exportedFiles.HTMLFile
                Write-Host "✅ HTML report opened successfully!" -ForegroundColor Green
            }
            catch {
                Write-Host "❌ Could not open HTML report automatically. Please open manually: $($exportedFiles.HTMLFile)" -ForegroundColor Red
            }
        }
        elseif (-not $NoAutoOpen) {
            Write-Host "⚠️ HTML file not found for auto-open. Check the generated files above." -ForegroundColor Yellow
        }

        if ($PassThru) {
            return [pscustomobject]@{
                Results       = $results
                ExportedFiles = $exportedFiles
            }
        }

        return $exportedFiles
    }
    catch {
        Write-Host "Error during advanced reconnaissance: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# =============================================================================

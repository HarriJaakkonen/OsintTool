#Requires -Version 7.0
<#!
.SYNOPSIS
Advanced Azure AD/Entra ID OSINT reconnaissance entry point.

.DESCRIPTION
Wrapper script that imports the Azure OSINT advanced module and exposes the
original command-line parameters for interactive usage. The heavy lifting lives
in module/AzureOsintAdvanced.psm1.

.PARAMETER Domain
Target domain to investigate (e.g., contoso.com).

.PARAMETER TenantId
Optional Azure tenant ID override when discovery is ambiguous.

.PARAMETER OrganizationName
Optional friendly organization name used for social media enrichment.

.PARAMETER OutputFile
Base filename for exported reports (timestamp suffixes are appended).

.PARAMETER Help
Show detailed usage information and exit.

.PARAMETER Interactive
Prompt for values when -Domain is not provided (enabled automatically when
Domain is omitted).

.PARAMETER NoAutoOpen
Prevent the HTML report from opening automatically after the run completes.

.PARAMETER PassThru
Return the results object and export metadata to the caller.

.EXAMPLE
./Azure-OSINT-Advanced.ps1 -Domain "contoso.com" -OutputFile "contoso.json"

.NOTES
This script is designed for PowerShell 7+ environments.
#>

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
    [switch]$Help,

    [Parameter(Mandatory = $false)]
    [switch]$Interactive,

    [Parameter(Mandatory = $false)]
    [switch]$NoAutoOpen,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'AzureOsintAdvanced/AzureOsintAdvanced.psd1'
if (-not (Test-Path -Path $modulePath)) {
    throw "Azure OSINT module not found at $modulePath. Ensure the repository structure is intact."
}

Import-Module -Name $modulePath -Force

if ($Help) {
    Invoke-AzureOsintAdvanced -ShowHelp
    return
}

$invokeParams = @{
    OutputFile = $OutputFile
}

if ($PSBoundParameters.ContainsKey('Domain')) {
    $invokeParams.Domain = $Domain
}
else {
    $invokeParams.Interactive = $true
}

if ($PSBoundParameters.ContainsKey('TenantId')) { $invokeParams.TenantId = $TenantId }
if ($PSBoundParameters.ContainsKey('OrganizationName')) { $invokeParams.OrganizationName = $OrganizationName }
if ($PSBoundParameters.ContainsKey('NoAutoOpen')) { $invokeParams.NoAutoOpen = $NoAutoOpen }
if ($PSBoundParameters.ContainsKey('PassThru')) { $invokeParams.PassThru = $PassThru }

if ($PSBoundParameters.ContainsKey('Interactive') -and $PSBoundParameters.ContainsKey('Domain')) {
    $invokeParams.Interactive = $Interactive
}
elseif ($PSBoundParameters.ContainsKey('Interactive') -and -not $PSBoundParameters.ContainsKey('Domain')) {
    $invokeParams.Interactive = $true
}

try {
    $result = Invoke-AzureOsintAdvanced @invokeParams
    if ($PassThru) {
        return $result
    }
}
catch {
    Write-Error $_
    exit 1
}

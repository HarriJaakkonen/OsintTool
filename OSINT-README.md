# Azure AD/Entra ID OSINT Tool

A comprehensive PowerShell-based Open Source Intelligence (OSINT) tool for Azure AD/Entra ID reconnaissance, inspired by osint.aadinternals.com.

## Features

### Basic Reconnaissance (`Azure-OSINT-Tool.ps1`)
- **Tenant Information Discovery**: OpenID configuration, federation metadata, tenant branding
- **User Enumeration**: OneDrive, Teams, login timing attacks
- **Service Detection**: Office 365, SharePoint, Teams, Exchange, Intune detection
- **DNS Reconnaissance**: A, MX, TXT, CNAME records and subdomain discovery
- **Cloud Asset Discovery**: Azure Storage, Web Apps, and other public resources

### Advanced Reconnaissance (`Azure-OSINT-Advanced.ps1`)
- **Certificate Transparency Logs**: Historical SSL certificate discovery
- **Social Media Footprint**: LinkedIn, GitHub, Twitter reconnaissance
- **Breach Data Correlation**: Integration points for breach databases
- **Email Pattern Analysis**: Common email format identification
- **Azure Resource Enumeration**: Storage accounts, Key Vaults, databases
- **Document Metadata Analysis**: Office document discovery and analysis

## Installation

```powershell
# Clone or download the scripts
# Ensure PowerShell 7+ is installed
# No additional modules required - uses built-in cmdlets
```

## Usage

### Basic OSINT Reconnaissance

```powershell
# Basic reconnaissance with console output
.\Azure-OSINT-Tool.ps1 -Domain "contoso.com"

# Full reconnaissance with JSON output
.\Azure-OSINT-Tool.ps1 -Domain "contoso.onmicrosoft.com" -OutputFormat JSON -OutputFile "results.json"

# Specific modules only
.\Azure-OSINT-Tool.ps1 -Domain "example.com" -Modules "TenantInfo,UserEnum" -Verbose

# HTML report generation
.\Azure-OSINT-Tool.ps1 -Domain "target.com" -OutputFormat HTML -OutputFile "report.html"

# CSV export (creates multiple files)
.\Azure-OSINT-Tool.ps1 -Domain "company.com" -OutputFormat CSV -OutputFile "data.csv"
```

### Advanced OSINT Techniques

```powershell
# Load the advanced module
. .\Azure-OSINT-Advanced.ps1

# Run advanced reconnaissance
$results = Start-AdvancedReconnaissance -Domain "contoso.com" -OrganizationName "Contoso Corporation"

# Export advanced results
Export-AdvancedResults -Results $results -OutputPath "advanced-results.json"
```

## Output Formats

### Console Output
```
==== Azure AD/Entra ID OSINT Results ====
Domain: contoso.com
Timestamp: 2025-09-24 15:30:00 UTC
Tenant ID: 12345678-1234-1234-1234-123456789abc

---- Services Detected ----
Office365: ✓
SharePoint: ✓
Teams: ✓
Exchange: ✓
AzureAD: ✓

---- Users Found (3) ----
admin@contoso.com [Exists] - OneDrive
test@contoso.com [Possible] - LoginTiming
support@contoso.com [Exists] - Teams
```

### JSON Output
```json
{
  "Domain": "contoso.com",
  "TenantId": "12345678-1234-1234-1234-123456789abc",
  "Timestamp": "2025-09-24 15:30:00 UTC",
  "TenantInfo": {
    "Domain": "contoso.com",
    "TenantId": "12345678-1234-1234-1234-123456789abc",
    "AuthenticationUrl": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/oauth2/authorize",
    "BrandingInfo": {
      "BackgroundColor": "#0078d4",
      "LogoUrl": "https://contoso.com/logo.png"
    }
  },
  "UserEnum": [
    {
      "Username": "admin@contoso.com",
      "Status": "Exists",
      "Source": "OneDrive",
      "OneDriveUrl": "https://contoso-my.sharepoint.com/personal/admin_contoso_com"
    }
  ],
  "ServiceEnum": {
    "Office365": true,
    "Teams": true,
    "SharePoint": true,
    "Exchange": true,
    "AzureAD": true
  }
}
```

## Modules

### TenantInfo
Discovers tenant information through multiple methods:
- OpenID Connect configuration discovery
- Federation metadata lookup
- Tenant branding extraction
- Autodiscover endpoint probing

### UserEnum
Enumerates potential users using:
- OneDrive URL testing
- Microsoft Teams user validation
- Login timing analysis (rate-limited)
- Common username patterns

### ServiceEnum
Detects Microsoft cloud services:
- Office 365 presence
- SharePoint Online sites
- Microsoft Teams organization
- Exchange Online mailboxes
- Azure AD/Entra ID configuration

### DNSRecon
Performs DNS reconnaissance:
- Standard DNS record types (A, MX, TXT, CNAME, NS, SOA)
- Common subdomain enumeration
- Microsoft-specific subdomain patterns

### CloudAssets
Discovers Azure cloud assets:
- Azure Storage accounts
- Azure Web Apps
- Azure Functions
- CDN endpoints

## Advanced Features

### Certificate Transparency
```powershell
# Search certificate transparency logs
$certs = Get-CertificateTransparency -Domain "contoso.com"
```

### Social Media Reconnaissance
```powershell
# Discover social media presence
$social = Get-SocialMediaFootprint -Domain "contoso.com" -OrganizationName "Contoso"
```

### Azure Resource Enumeration
```powershell
# Enumerate Azure resources
$resources = Get-AzureResourceEnumeration -Domain "contoso.com"
```

## Security Considerations

### Ethical Usage
- Only perform reconnaissance on domains you own or have explicit permission to test
- Respect rate limits and avoid aggressive scanning
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Rate Limiting
The tool implements several rate limiting measures:
- Delays between requests to prevent service disruption
- Limited concurrent connections
- Timeout controls for web requests
- Error handling for blocked requests

### Detection Avoidance
- Randomized user agent strings
- Request timing variation
- Multiple discovery methods
- Graceful error handling

## Integration Examples

### Automated Reporting
```powershell
# Daily reconnaissance script
$domains = @("company1.com", "company2.com", "company3.com")
foreach ($domain in $domains) {
    $results = .\Azure-OSINT-Tool.ps1 -Domain $domain -OutputFormat JSON -OutputFile "$domain-$(Get-Date -Format 'yyyyMMdd').json"
    
    # Process results, send alerts, etc.
}
```

### Threat Intelligence
```powershell
# Combine with threat intel feeds
$results = .\Azure-OSINT-Tool.ps1 -Domain "target.com" -OutputFormat JSON
$intelligence = $results | ConvertFrom-Json

# Check against known bad indicators
if ($intelligence.UserEnum.Count -gt 10) {
    Write-Warning "Large user base detected - potential target"
}
```

## Limitations

### Current Limitations
- No built-in proxy support (use system proxy)
- Limited to publicly available information
- Rate limiting may affect comprehensive scans
- Some advanced features require API keys (not included)

### Future Enhancements
- Proxy and Tor support
- Advanced breach database integration
- Machine learning for user enumeration
- Automated report generation
- Integration with SIEM systems

## Troubleshooting

### Common Issues
1. **Rate Limiting**: Reduce concurrent requests, add delays
2. **Network Timeouts**: Increase timeout values, check connectivity
3. **Permission Errors**: Run with appropriate privileges
4. **Output File Issues**: Verify write permissions for output directory

### Debug Mode
```powershell
# Enable verbose output
.\Azure-OSINT-Tool.ps1 -Domain "target.com" -Verbose

# PowerShell debug mode
$DebugPreference = "Continue"
.\Azure-OSINT-Tool.ps1 -Domain "target.com"
```

## Legal Disclaimer

This tool is for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before conducting reconnaissance activities. The authors are not responsible for any misuse of this tool.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request with detailed description

## License

MIT License - see LICENSE file for details
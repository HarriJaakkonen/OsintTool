# Azure OSINT Advanced - Examples
## Overview

This folder contains practical examples demonstrating various use cases for the AzureOsintAdvanced PowerShell module.

## Files

### `BasicUsage.ps1`
Simple examples showing how to:
- Run basic domain reconnaissance
- Use organization names for social media enrichment
- Specify tenant IDs for targeted analysis
- Use interactive mode

### `AdvancedAutomation.ps1`
Advanced scenarios including:
- Batch processing multiple domains
- Scheduled reconnaissance with alerting
- Integration with threat intelligence workflows
- Rate limiting and error handling

### `CustomReporting.ps1`
Custom report generation examples:
- HTML report generation with security analysis
- JSON export for SIEM integration
- Custom data formatting and visualization

## Usage

1. **Import the module first:**
   ```powershell
   Import-Module "$PSScriptRoot\..\AzureOsintAdvanced\AzureOsintAdvanced.psd1" -Force
   ```

2. **Run basic reconnaissance:**
   ```powershell
   . .\BasicUsage.ps1
   ```

3. **Try advanced automation:**
   ```powershell
   . .\AdvancedAutomation.ps1
   Start-ScheduledRecon -Domain "contoso.com"
   ```

4. **Generate custom reports:**
   ```powershell
   . .\CustomReporting.ps1
   $results = Invoke-AzureOsintAdvanced -Domain "contoso.com" -PassThru -NoAutoOpen
   New-CustomOSINTReport -Results $results.Results
   ```

## Best Practices

- Always use `-NoAutoOpen` in automation scripts
- Implement rate limiting when processing multiple domains
- Store sensitive results securely
- Follow responsible disclosure practices
- Respect target organization policies

## Contributing

Feel free to contribute additional examples or improvements to existing ones!
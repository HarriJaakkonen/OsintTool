# 🔍 How gettenantpartitionweb.azurewebsites.net Finds Tenant IDs

## 🎯 **Core Technique Explained**

The website uses Microsoft's **OpenID Connect Discovery Endpoint** to extract tenant information. Here's exactly how it works:

### **1. The API Call**
```javascript
// The site makes a GET request to:
var lookupUrl = "https://login.microsoftonline.com/" + tenant + "/.well-known/openid-configuration";

// For different Azure clouds:
// Worldwide: https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration
// US Gov:    https://login.microsoftonline.us/{tenant}/.well-known/openid-configuration  
// China:     https://login.partner.microsoftonline.cn/{tenant}/.well-known/openid-configuration
// Germany:   https://login.microsoftonline.de/{tenant}/.well-known/openid-configuration
```

### **2. Tenant ID Extraction**
```javascript
// Extract tenant ID from the authorization_endpoint using regex:
var tenantIdRegEx = /^https:\/\/login\.microsoftonline\.(?:us|com)\/([\dA-Fa-f]{8}-[\dA-Fa-f]{4}-[\dA-Fa-f]{4}-[\dA-Fa-f]{4}-[\dA-Fa-f]{12})\/oauth2\/authorize$/;
var tenantAuthEndpoint = myObj.authorization_endpoint;
var tenantId = tenantAuthEndpoint.match(tenantIdRegEx);
```

### **3. Sample Response Structure**
```json
{
  "token_endpoint": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/oauth2/v2.0/token",
  "authorization_endpoint": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/oauth2/v2.0/authorize", 
  "issuer": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0",
  "tenant_region_scope": "WW",      // WW=Worldwide, USGov=US Government, etc.
  "tenant_region_sub_scope": null   // GCC, DOD, DODCON for government tenants
}
```

### **4. Region & Scope Detection**
```javascript
// Tenant regions:
switch (myObj.tenant_region_scope) {
    case 'USGov': tenantRegion = "Azure AD Government: Arlington"; break;
    case 'USG':   tenantRegion = "Azure AD Government: Fairfax"; break;
    case 'WW':    tenantRegion = "Azure AD Global"; break;
    case 'NA':    tenantRegion = "Azure AD Global: North America"; break;
    case 'EU':    tenantRegion = "Azure AD Global: Europe"; break;
    case 'AS':    tenantRegion = "Azure AD Global: Asia-Pacific"; break;
    case 'OC':    tenantRegion = "Azure AD Global: Oceania"; break;
}

// Government scopes:
switch (myObj.tenant_region_sub_scope) {
    case 'DOD':    tenantScope = "DOD"; break;
    case 'DODCON': tenantScope = "GCC High"; break;
    case 'GCC':    tenantScope = "GCC"; break;
}
```

## ⚡ **Why This Method Works**

1. **Always Available**: OpenID Connect discovery is a standard that's always exposed
2. **No Authentication Required**: Public endpoint, no API keys needed
3. **Reliable Data Source**: Direct from Microsoft's authentication infrastructure
4. **Rich Metadata**: Provides tenant ID, region, and government classification

## 🔧 **Implementation in Our OSINT Tool**

We should enhance our current implementation to use this exact method as a primary technique:

```powershell
function Get-TenantIdViaOpenIDDiscovery {
    param([string]$Domain)
    
    $clouds = @(
        @{Name="Worldwide"; Endpoint="https://login.microsoftonline.com"},
        @{Name="US Government"; Endpoint="https://login.microsoftonline.us"},
        @{Name="China"; Endpoint="https://login.partner.microsoftonline.cn"},
        @{Name="Germany"; Endpoint="https://login.microsoftonline.de"}
    )
    
    foreach ($cloud in $clouds) {
        try {
            $url = "$($cloud.Endpoint)/$Domain/.well-known/openid-configuration"
            $response = Invoke-RestMethod -Uri $url -ErrorAction Stop
            
            # Extract tenant ID from authorization_endpoint
            if ($response.authorization_endpoint -match '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
                return @{
                    TenantId = $matches[1]
                    Cloud = $cloud.Name
                    Region = $response.tenant_region_scope
                    SubScope = $response.tenant_region_sub_scope
                    Issuer = $response.issuer
                }
            }
        }
        catch { }
    }
    return $null
}
```

## 🎯 **Advantages Over Current Methods**

| Method | Reliability | Data Quality | Authentication Required |
|--------|-------------|--------------|------------------------|
| **OpenID Discovery** | ✅ **High** | ✅ **Complete** | ❌ **No** |
| GetCredentialType | ⚠️ Medium | ⚠️ Limited | ❌ No |
| Branding URL Analysis | ⚠️ Medium | ⚠️ Variable | ❌ No |
| GetUserRealm | ⚠️ Medium | ⚠️ Basic | ❌ No |

## 🚀 **Enhanced Information Available**

Using this method, we can extract:

- ✅ **Tenant GUID** (primary identifier)
- ✅ **Cloud Instance** (Worldwide, US Gov, China, Germany)
- ✅ **Geographic Region** (NA, EU, AS, OC, USGov)  
- ✅ **Government Classification** (GCC, GCC High, DOD)
- ✅ **All OAuth Endpoints** (token, authorize, jwks_uri, etc.)

## 💡 **Why Our Tool Should Adopt This**

1. **Primary Method**: Should be the first technique we try
2. **Most Reliable**: Direct from Microsoft's authoritative source
3. **Comprehensive Data**: Gets more than just tenant ID
4. **Standard Compliant**: Uses OpenID Connect standards
5. **Multi-Cloud Support**: Works across all Azure environments

This is essentially the "gold standard" method for tenant discovery - it's what Microsoft's own tools use internally.
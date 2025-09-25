# 🚀 Azure OSINT Advanced Tool - Enhanced with mjendza.net & ROADtools Techniques

## ✨ **Major Enhancements Added**

### **🔍 Enhanced User Enumeration Techniques**

#### **1. GetCredentialType API (mjendza.net method)**
- **Purpose**: Advanced user validation using Microsoft's GetCredentialType endpoint
- **Technique**: 
  - Sends POST requests to `https://login.microsoftonline.com/common/GetCredentialType`
  - Analyzes `IfExistsResult` field: 0 = user exists, 1 = user doesn't exist, 5 = user in different tenant
  - Extracts authentication methods (Password, FIDO2, Certificate, WHfB, SMS, Social logins)
- **Enhancement**: More reliable than traditional methods, provides authentication method intelligence

#### **2. Entra External ID Enumeration**
- **Purpose**: Handle External ID tenants (Customer Identity Access Management)
- **Technique**: 
  - Extracts `sCtx` parameter from authorization flow
  - Uses context for enhanced user enumeration in External ID scenarios
- **Enhancement**: Expands coverage to CIAM scenarios

#### **3. Device Code Flow Analysis (ROADtools inspired)**
- **Purpose**: Analyze OAuth 2.0 Device Code Flow availability
- **Technique**: 
  - Tests device code endpoint for Microsoft Office client ID
  - Extracts device codes, user codes, and verification URLs
- **Enhancement**: Provides insight into available authentication flows

#### **4. Tenant Availability Analysis**
- **Purpose**: Verify tenant name usage via o365.rocks API
- **Technique**: 
  - Checks if `domain.onmicrosoft.com` is available or taken
  - Fallback to OpenID configuration testing
- **Enhancement**: Confirms tenant existence through multiple methods

---

### **🏢 Advanced Tenant Discovery (mjendza.net techniques)**

#### **1. Multiple Tenant ID Discovery Methods**
- **whatismytenantid.com method**: OpenID configuration parsing
- **gettenantpartitionweb.azurewebsites.net**: Partition web service API
- **Tenant region discovery**: Extract `tenant_region_scope` from OpenID config

#### **2. Enhanced Enterprise Service Detection**
- **Enterprise Registration**: `https://enterpriseregistration.domain/EnrollmentServer/Discovery.svc`
- **Enterprise Enrollment**: `https://enterpriseenrollment.domain/EnrollmentServer/Discovery.svc` 
- **Lyncdiscover**: Teams/Skype for Business discovery
- **SIP Federation**: `https://sipfed.domain` endpoint testing
- **Microsoft Online ID**: `https://msoid.domain` endpoint verification

#### **3. Branding URL Analysis Enhancement**
- **Multi-URL Analysis**: Checks BannerLogo, TileLogo, Illustration, CustomizationFiles
- **Pattern Matching**: Enhanced regex for complete tenant ID extraction
- **CDN URL Parsing**: Extract tenant identifiers from Microsoft CDN URLs

---

### **🔐 Authentication & Token Analysis (ROADtools inspired)**

#### **1. OAuth 2.0 Flow Discovery**
```powershell
# Supported flows tested:
- Authorization Code Flow
- Device Code Flow  
- Client Credentials Flow
```

#### **2. Authentication Method Intelligence**
- **Multi-Factor Authentication**: Password, FIDO2, Windows Hello for Business
- **Certificate Authentication**: CBA detection and analysis
- **Social Login Integration**: Google, Facebook SSO detection
- **SMS Authentication**: SAS parameters analysis

#### **3. Federation Configuration Analysis**
- **ADFS Detection**: Federation metadata XML parsing
- **SAML Configuration**: Entity ID and certificate extraction
- **Signing Certificates**: X.509 certificate enumeration
- **Cloud vs Federated**: Distinction between cloud-only and federated tenants

#### **4. Conditional Access Policy Detection**
- **Policy Hints**: OAuth flow analysis for CA triggers
- **Device Registration**: Enterprise registration service detection
- **Compliance Requirements**: MDM/MAM policy indicators

---

### **☁️ Extended Azure Resource Discovery (ROADtools style)**

#### **1. Expanded Resource Coverage**
```powershell
# New resources added:
- ARM Templates (via GitHub search)
- CDN Endpoints (Azure CDN, Classic CDN)
- Traffic Manager profiles
- Azure Front Door endpoints
- Service Bus namespaces
- Event Hub namespaces  
- API Management services
- Logic Apps (multi-region)
```

#### **2. Public ARM Template Discovery**
- **GitHub Search**: Searches for exposed Azure deployment templates
- **Security Risk**: Identifies potentially leaked infrastructure templates
- **Pattern Matching**: Finds ARM templates containing domain references

#### **3. CDN & Edge Services**
```powershell
# Enhanced CDN discovery:
- https://{variation}.azureedge.net     # Azure CDN
- https://{variation}.vo.msecnd.net     # Azure CDN Classic  
- https://{variation}.b-cdn.net         # Third-party CDN
- https://{variation}.azurefd.net       # Azure Front Door
```

---

### **🛡️ Security Posture Analysis**

#### **1. Security Defaults Detection**
- **MFA Enforcement**: Analyzes credential requirements for MFA indicators
- **Security Policy**: Distinguishes Security Defaults vs Conditional Access
- **Risk Assessment**: Evaluates baseline security posture

#### **2. Threat Protection Services**
```powershell
# Services detected:
- Microsoft Defender for Office 365 (via EOP detection)
- Microsoft Defender for Identity (MDI instance testing)
- Data Loss Prevention (DLP policy hints)
```

#### **3. Guest Access Configuration**
- **Invitation API**: Tests Graph API invitation endpoint accessibility
- **External Collaboration**: B2B guest access policy analysis
- **Risk Indicators**: Identifies potential external access vectors

---

### **📊 Enhanced Reporting & Analytics**

#### **1. Interactive HTML Reports**
```javascript
// New JavaScript features:
- Copy-to-clipboard functionality for tenant IDs
- Quick access links to Azure services
- Expandable sections with detailed analysis
- Mobile-responsive design with modern CSS
```

#### **2. Comprehensive Statistics**
- **Authentication Methods Count**: Number of detected auth methods
- **OAuth Flow Support**: Supported authentication flows
- **Security Features**: MFA, CA, Federation status
- **Resource Coverage**: Extended Azure service enumeration

#### **3. Multi-Format Export**
- **JSON**: Technical data for further analysis
- **HTML**: Visual reports for presentations
- **CSV**: Tabular data for spreadsheet analysis

---

## 🎯 **Technical Implementation Details**

### **API Endpoints Enhanced**
```powershell
# mjendza.net techniques:
- GetCredentialType API with isOtherIdpSupported parameter
- o365.rocks tenant availability API
- gettenantpartitionweb.azurewebsites.net partition service

# ROADtools inspired endpoints:
- OAuth 2.0 device code flow
- Graph API invitation endpoint
- Regional Logic Apps endpoints
- ARM template GitHub search API
```

### **Error Handling & Rate Limiting**
- **Smart Throttling**: Configurable delays between requests
- **Graceful Degradation**: Continues on individual failures
- **Progress Indicators**: Visual feedback for long operations
- **Silent Failures**: Reduces noise while maintaining intelligence

### **Security & Ethics**
- **Passive Reconnaissance**: No authentication required
- **Public Data Only**: Uses publicly accessible endpoints
- **Rate Limiting**: Respects service rate limits
- **Responsible Disclosure**: Identifies security misconfigurations

---

## 🚀 **Usage Examples**

### **Basic Enhanced Scan**
```powershell
.\Azure-OSINT-Advanced.ps1 -Domain "contoso.com"
```

### **Targeted Analysis with Organization Context**
```powershell
.\Azure-OSINT-Advanced.ps1 -Domain "contoso.com" -OrganizationName "Contoso Corporation"
```

### **Comprehensive Security Assessment**
```powershell
.\Azure-OSINT-Advanced.ps1 -Domain "contoso.com" -TenantId "12345678-1234-1234-1234-123456789012"
```

---

## 📈 **Results Comparison**

### **Before Enhancement**
- Basic tenant discovery via OpenID
- Limited user enumeration
- Simple Azure resource checking
- Basic HTML reporting

### **After Enhancement (mjendza.net + ROADtools)**
- ✅ **10+ tenant discovery methods**
- ✅ **Advanced user enumeration (GetCredentialType, OneDrive, Graph)**
- ✅ **OAuth 2.0 flow analysis**  
- ✅ **Security posture assessment**
- ✅ **Extended Azure resource discovery (15+ service types)**
- ✅ **Authentication method intelligence**
- ✅ **Interactive HTML reports with JavaScript**
- ✅ **Multi-format export (JSON, HTML, CSV)**

---

## 🔗 **References & Credits**

- **mjendza.net**: [Entra ID Public Data Analysis](https://mjendza.net/post/entra-id-public-data/)
- **ROADtools**: [dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools)
- **AADInternals**: Original inspiration for tenant analysis techniques
- **Microsoft Documentation**: OAuth 2.0 and Azure AD authentication flows

---

## 🎉 **Impact Summary**

The enhanced Azure OSINT Advanced tool now provides **enterprise-grade reconnaissance capabilities** that rival commercial security assessment tools. The integration of techniques from mjendza.net and ROADtools significantly expands the tool's capability to:

1. **Enumerate users** with high accuracy using multiple methods
2. **Analyze authentication flows** and security configurations  
3. **Discover Azure resources** across 15+ service types
4. **Assess security posture** including MFA, CA, and threat protection
5. **Generate professional reports** suitable for security assessments

This makes it an invaluable tool for **red teams**, **penetration testers**, and **security researchers** conducting authorized Azure AD/Entra ID reconnaissance.
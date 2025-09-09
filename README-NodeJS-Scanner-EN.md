# Node.js Package Security Scanner

## 🛡️ Overview

The **Node.js Package Security Scanner** is a comprehensive PowerShell tool for detecting compromised npm packages in Node.js projects. It was specifically developed to protect against the supply chain attack on September 8, 2025, against developer "qix".

## 🚀 Quick Start

```powershell
# Basic system scan
.\NodeJS-Security-Scanner.ps1

# Detailed scan with export
.\NodeJS-Security-Scanner.ps1 -Detailed -ExportResults

# Scan specific paths
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\Projects,D:\Development" -MaxDepth 3
```

## 📋 System Requirements

- **PowerShell**: Version 5.1 or higher
- **Operating System**: Windows 7/8/10/11, Windows Server 2012+
- **Permissions**: Standard user rights (Admin rights for advanced network analysis)
- **Dependencies**: No external modules required

## 🎯 Main Features

### Comprehensive Project Detection
- ✅ Automatic search for `package.json` files
- ✅ Configurable search depth for performance optimization
- ✅ Intelligent filtering of `node_modules` directories
- ✅ Support for custom search paths

### Advanced Package Analysis
- ✅ Analysis of all dependency types:
  - `dependencies` (production dependencies)
  - `devDependencies` (development dependencies)
  - `peerDependencies` (peer dependencies)
  - `optionalDependencies` (optional dependencies)
- ✅ Semantic version comparison
- ✅ Exact version match detection

### System Security Monitoring
- ✅ Detection of running Node.js processes
- ✅ Identification of suspicious cryptocurrency processes
- ✅ Optional network connection analysis
- ✅ Process ID tracking and path analysis

## 📖 Parameter Reference

### Basic Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Detailed` | Switch | `$false` | Shows detailed information about dependencies |
| `-ExportResults` | Switch | `$false` | Exports results to CSV file |
| `-ScanPaths` | String[] | Auto-detection | Comma-separated list of scan paths |
| `-MaxDepth` | Int | `5` | Maximum search depth in directory structures |
| `-ShowNetworkDetails` | Switch | `$false` | Shows detailed network connections |

### Default Search Paths (when no custom paths specified)
```powershell
$env:USERPROFILE\Desktop
$env:USERPROFILE\Documents
$env:USERPROFILE\source
$env:USERPROFILE\Projects
$env:USERPROFILE\Development
C:\Projects
C:\Development
```

## 🔍 Usage Examples

### Development Environment
```powershell
# Complete developer workstation scan
.\NodeJS-Security-Scanner.ps1 -ScanPaths "$env:USERPROFILE\source,$env:USERPROFILE\Desktop,$env:USERPROFILE\Documents" -Detailed -ExportResults

# Quick project check
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\CurrentProject" -MaxDepth 2
```

### CI/CD Pipeline
```powershell
# Build agent security check
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\BuildAgent\work" -ExportResults

# Exit code-based pipeline integration
$exitCode = & .\NodeJS-Security-Scanner.ps1 -ScanPaths $BUILD_DIRECTORY
if ($exitCode -eq 2) { 
    Write-Error "Critical security issues found!"
    exit 1 
}
```

### Production Server
```powershell
# Server security audit
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\inetpub,C:\Applications" -MaxDepth 2 -ShowNetworkDetails -ExportResults

# Monitoring with reduced search depth for performance
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\WebApps" -MaxDepth 1
```

## 🎨 Output Categories

### Console Output
- **🚨 CRITICAL**: Projects with exact version matches of compromised packages
- **⚠️ MEDIUM**: Projects with large dependency trees (>50 dependencies)
- **✅ LOW**: Safe projects with no detected threats

### Color Coding
- **Red**: Critical threats, immediate action required
- **Yellow**: Warnings, monitoring recommended
- **Green**: Safe states
- **Cyan**: Informational details
- **Magenta**: Section headers

## 📊 CSV Export Format

```csv
ProjectName,Version,Path,RiskLevel,TotalDependencies,CompromisedPackagesCount,CompromisedPackagesDetails
MyApp,1.0.0,C:\Projects\MyApp,Critical,25,2,"chalk:5.6.1->5.6.1:EXACT_MATCH;debug:4.4.2->4.4.2:EXACT_MATCH"
```

### Export Field Explanation
- **CompromisedPackagesDetails**: Format `PackageName:InstalledVersion->CompromisedVersion:Status`
- **Status Values**: `EXACT_MATCH` (highest risk) or `VERSION_DIFFERS`

## 🔧 Risk Assessment Framework

### Critical Risk (🚨)
- Contains packages with **exact version matches** to compromised versions
- Direct dependencies on known malicious packages
- High probability of active compromise

### Medium Risk (⚠️)
- Projects with >50 total dependencies (increased attack surface)
- Complex project structures with extensive node_modules
- Active development environments with frequent dependency updates

### Low Risk (✅)
- No compromised packages detected
- Minimal, focused dependency trees
- Version differences from flagged packages (lower compromise probability)

## ⚡ Performance Optimization

### Recommended Settings by Scenario

| Scenario | MaxDepth | Detailed | ShowNetworkDetails | Rationale |
|----------|----------|----------|--------------------|-----------|
| **Developer Workstation** | 3-5 | ✅ | ✅ | Complete analysis desired |
| **Build Server** | 2-3 | ❌ | ❌ | Focus on critical findings |
| **Production Server** | 1-2 | ❌ | ✅ | Performance + Network monitoring |
| **Security Audit** | 5+ | ✅ | ✅ | Full coverage required |

### Performance Features
- **Streaming Analysis**: Memory-efficient processing of large project collections
- **Progress Tracking**: Real-time feedback for long-running operations
- **Configurable Depth Limiting**: Prevents excessive recursion
- **Smart Filtering**: Automatically skips irrelevant directories

## 🚨 Compromised Packages Database (September 2025)

The scanner detects the following compromised npm packages:

```powershell
'ansi-regex' = '6.2.1'          # Terminal output manipulation
'ansi-styles' = '6.2.2'         # Styling library
'backslash' = '0.2.1'           # String processing
'chalk' = '5.6.1'               # Terminal colors (widely used!)
'chalk-template' = '1.1.1'      # Chalk extension
'color-convert' = '3.1.1'       # Color conversion
'color-name' = '2.0.1'          # Color names library
'color-string' = '2.1.1'        # String-to-color conversion
'debug' = '4.4.2'               # Debug output (very common!)
'error-ex' = '1.3.3'            # Enhanced error handling
'has-ansi' = '6.0.1'            # ANSI detection
'is-arrayish' = '0.3.3'         # Array-like object detection
'simple-swizzle' = '0.2.3'      # Color swizzling
'slice-ansi' = '7.1.1'          # ANSI string slicing
'strip-ansi' = '7.1.1'          # ANSI code removal
'supports-color' = '10.2.1'     # Color support detection
'supports-hyperlinks' = '4.1.1' # Hyperlink support
'wrap-ansi' = '9.0.1'           # ANSI string wrapping
'proto-tinker-wc' = '1.8.7'     # Less known library
```

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### "No Node.js projects found!"
```powershell
# Solution 1: Increase search depth
.\NodeJS-Security-Scanner.ps1 -MaxDepth 10

# Solution 2: Specify exact paths
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\MyProjectPath"

# Solution 3: Check if package.json files exist
Get-ChildItem -Recurse -Name "package.json" -Path "C:\Projects"
```

#### "Network connections could not be checked"
```powershell
# Solution: Run PowerShell as Administrator
# Or use without network monitoring:
.\NodeJS-Security-Scanner.ps1 -Detailed -ExportResults
```

#### Slow performance with large directories
```powershell
# Solution: Reduce MaxDepth and use specific paths
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\SpecificProject" -MaxDepth 2
```

## 🔗 Integration with VSCode Scanner

### Complementary Usage
```powershell
# Step 1: Scan VSCode extensions
.\VSCode-Security-Scanner.ps1 -Detailed -ExportResults

# Step 2: Scan system-wide Node.js projects
.\NodeJS-Security-Scanner.ps1 -Detailed -ExportResults -ShowNetworkDetails

# Step 3: Compare and correlate results
```

### Shared Detection Logic
- Identical compromised package database
- Unified risk assessment framework
- Consistent version comparison algorithms
- Common exit code conventions

## 📞 Support and Contribution

### Exit Codes
- `0`: No critical threats found
- `1`: General errors (no projects found, invalid parameters)
- `2`: Critical security threats detected - **Immediate action required!**

### Immediate Actions for Exit Code 2
1. **Stop all Node.js processes** for affected projects
2. **Delete node_modules** and package-lock.json/yarn.lock
3. **Update package.json** to safe versions
4. **Run `npm audit`** or `yarn audit`
5. **Check cryptocurrency wallets** immediately
6. **Rotate passwords and API keys**
7. **Review transactions** from recent weeks

---

**⚠️ Important Security Note**: This tool is designed exclusively for **defensive security purposes**. It detects and helps remediate security threats but performs no malicious actions.
# VS Code Extension Security Scanner

?? **A PowerShell security scanner for detecting compromised npm packages in VS Code extensions**

## ?? Critical Security Alert

This scanner detects VS Code extensions affected by the major npm supply chain attack that occurred on **September 8, 2025**, where the developer account "qix" was compromised through spear-phishing. The attack affected packages with **over 2 billion weekly downloads**.

## ?? What It Does

- **Scans all installed VS Code extensions** for compromised npm packages
- **Identifies critical security risks** in your development environment  
- **Detects cryptocurrency wallet targeting malware** in extensions
- **Performs precise version matching** against specific compromised versions
- **Distinguishes between exact matches and version differences** for better risk assessment
- **Provides immediate remediation steps** for compromised systems
- **Exports detailed reports** with version information for security auditing
- **Performs system-wide security checks** for indicators of compromise

## ?? Compromised Packages Detected

The scanner checks for these compromised npm packages with their specific malicious versions:

| Package Name | Compromised Version |
|--------------|-------------------|
| `ansi-regex` | 6.2.1 |
| `ansi-styles` | 6.2.2 |
| `backslash` | 0.2.1 |
| `chalk` | 5.6.1 |
| `chalk-template` | 1.1.1 |
| `color-convert` | 3.1.1 |
| `color-name` | 2.0.1 |
| `color-string` | 2.1.1 |
| `debug` | 4.4.2 |
| `error-ex` | 1.3.3 |
| `has-ansi` | 6.0.1 |
| `is-arrayish` | 0.3.3 |
| `simple-swizzle` | 0.2.3 |
| `slice-ansi` | 7.1.1 |
| `strip-ansi` | 7.1.1 |
| `supports-color` | 10.2.1 |
| `supports-hyperlinks` | 4.1.1 |
| `wrap-ansi` | 9.0.1 |
| `proto-tinker-wc` | 1.8.7 |

**⚠️ Version Matching**: The scanner performs precise version comparison to distinguish between:
- **🔴 EXACT MATCH**: Installed version matches the compromised version exactly (CRITICAL RISK)
- **🟡 VERSION DIFFERS**: Package is present but version differs from the compromised one (MEDIUM RISK)

## ?? Quick Start

### Prerequisites
- Windows PowerShell 5.1 or later
- VS Code installed (any version/channel)

### Basic Usage

```powershell
# Download and run the scanner
.\VSCode-Security-Scanner.ps1
```

### Advanced Usage

```powershell
# Detailed scan with network analysis and CSV export
.\VSCode-Security-Scanner.ps1 -Detailed -ExportResults -ShowNetworkDetails

# Custom VS Code installation path
.\VSCode-Security-Scanner.ps1 -CustomVSCodePath "H:\VSCode" -Detailed
```

## ?? Parameters

| Parameter | Description |
|-----------|-------------|
| `-Detailed` | Shows comprehensive dependency information |
| `-ExportResults` | Exports scan results to CSV file |
| `-CustomVSCodePath` | Specify custom VS Code installation directory |
| `-ShowNetworkDetails` | Displays detailed network connection analysis |

## ??? What Happens If Compromised Extensions Are Found

### Immediate Actions Required:
1. **?? Disable/uninstall** the compromised extension immediately
2. **?? Restart VS Code** completely
3. **?? Check system** for suspicious activities
4. **?? Rotate passwords** and API keys
5. **?? Verify cryptocurrency wallets** for unauthorized transactions
6. **?? Review crypto transactions** from recent weeks

### The Malware's Capabilities:
- **Cryptocurrency theft** targeting Bitcoin, Ethereum, Solana, and others
- **Address replacement** using visually similar addresses (Levenshtein distance)
- **Browser manipulation** intercepting wallet transactions
- **API traffic interception** modifying network requests

## ?? Output Explanation

### Risk Levels:
- ?? **CRITICAL**: Contains confirmed compromised packages - **Immediate action required**
- ?? **MEDIUM**: High dependency count or node_modules present - **Monitor closely**  
- ?? **LOW**: No known risks detected - **Safe to use**

### Sample Output:
```
=== VS CODE EXTENSION SECURITY SCAN RESULTS ===
Scanned extensions: 47

=== RISK OVERVIEW ===
?? CRITICAL: 2 Extensions
?? MEDIUM: 5 Extensions  
?? LOW: 40 Extensions

=== ?? CRITICAL EXTENSIONS (COMPROMISED PACKAGES FOUND) ===
?? GitHub Copilot by GitHub
   Version: 1.364.0
   Path: C:\Users\user\.vscode\extensions\github.copilot-1.364.0
   ??  Compromised packages found:
      - chalk
        Installed: ^5.4.1 | Compromised: 5.6.1
        Status: Version differs
        Type: devDependency

?? WARNING: 1 critical extension(s) found!
Affected extensions:
  - GitHub Copilot (GitHub): chalk [VERSION DIFFERS]
```

### Version Status Indicators:
- **🔴 EXACT MATCH**: The installed version exactly matches the compromised version
- **🟡 VERSION DIFFERS**: The package is present but the version is different from the compromised one
- **📊 Export Data**: CSV exports include detailed version comparison data

## ?? Technical Details

### How It Works:
1. **Locates VS Code extensions** in standard and custom directories
2. **Parses package.json files** to extract dependencies with version information
3. **Cross-references dependencies** against known compromised packages and their specific versions
4. **Performs precise version matching** using semantic version comparison
5. **Scans node_modules** for actual installed packages with version verification
6. **Performs system checks** for malware indicators
7. **Generates comprehensive reports** with detailed version analysis and risk assessments

### Version Comparison Logic:
- **Exact Match Detection**: Compares semantic versions (major.minor.patch)
- **Range Handling**: Processes version ranges (^, ~, >=, etc.) 
- **Fallback Comparison**: Uses string matching when version parsing fails
- **Dual Verification**: Checks both package.json declarations and physically installed packages

### Supported VS Code Versions:
- VS Code (Stable)
- VS Code Insiders
- Portable installations
- Custom installation paths

## ?? Performance

- **Fast scanning**: Processes 50+ extensions in seconds
- **Low resource usage**: Minimal system impact during scanning
- **Comprehensive coverage**: Checks both dependencies and installed packages

## ?? Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution:
- Additional compromise indicators
- Performance optimizations
- Cross-platform support (Linux/macOS)
- Integration with CI/CD pipelines

## ?? License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ?? Security Policy

Found a security vulnerability? Please see our [Security Policy](SECURITY.md) for responsible disclosure.

## ?? Support

If you find compromised extensions:

1. **Follow the immediate actions** listed above
2. **Report to VS Code team**: [VS Code Security](https://code.visualstudio.com/security)
3. **Contact npm security**: security@npmjs.com
4. **Open an issue** in this repository with (sanitized) details

## ?? Additional Resources

- [npm Security Advisory](https://npmjs.com/advisories)
- [VS Code Extension Security](https://code.visualstudio.com/api/extension-guides/extension-security)
- [Supply Chain Attack Prevention](https://owasp.org/www-community/attacks/Supply_Chain_Attack)

---

**? Don't wait - scan your VS Code extensions now!** This attack is actively targeting developers and their cryptocurrency assets.

## ?? Statistics

- **2+ billion downloads** affected by the original attack
- **20+ npm packages** compromised in initial wave  
- **Millions of developers** potentially at risk
- **Immediate scanning recommended** for all VS Code users

---

*This tool is provided as-is for security research and protection purposes. Always verify results and follow your organization's security policies.*
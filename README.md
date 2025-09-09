# VS Code Extension Security Scanner

?? **A PowerShell security scanner for detecting compromised npm packages in VS Code extensions**

## ?? Critical Security Alert

This scanner detects VS Code extensions affected by the major npm supply chain attack that occurred on **September 8, 2025**, where the developer account "qix" was compromised through spear-phishing. The attack affected packages with **over 2 billion weekly downloads**.

## ?? What It Does

- **Scans all installed VS Code extensions** for compromised npm packages
- **Identifies critical security risks** in your development environment  
- **Detects cryptocurrency wallet targeting malware** in extensions
- **Provides immediate remediation steps** for compromised systems
- **Exports detailed reports** for security auditing
- **Performs system-wide security checks** for indicators of compromise

## ?? Compromised Packages Detected

The scanner checks for these compromised npm packages:

- `ansi-regex`, `ansi-styles`, `backslash`, `chalk`, `chalk-template`
- `color-convert`, `color-name`, `color-string`, `debug`, `error-ex`
- `has-ansi`, `is-arrayish`, `simple-swizzle`, `slice-ansi`, `strip-ansi`
- `supports-color`, `supports-hyperlinks`, `wrap-ansi`, `proto-tinker-wc`

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
?? Extension Name by Publisher
   ??  Compromised packages: chalk, ansi-styles
```

## ?? Technical Details

### How It Works:
1. **Locates VS Code extensions** in standard and custom directories
2. **Parses package.json files** to extract dependencies
3. **Cross-references dependencies** against known compromised packages
4. **Scans node_modules** for actual installed packages
5. **Performs system checks** for malware indicators
6. **Generates comprehensive reports** with risk assessments

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
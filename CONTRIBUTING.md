# Contributing to VS Code Extension Security Scanner

Thank you for your interest in contributing to this security tool! This scanner helps protect developers from supply chain attacks.

## ?? Quick Start

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Test your changes thoroughly
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## ??? Security-First Development

Since this is a security tool, all contributions must follow strict security guidelines:

### Code Review Requirements
- **All PRs require review** from at least one maintainer
- **Security-related changes** require review from security team
- **No direct commits** to main branch

### Testing Requirements
- **Test with compromised packages** (use test data, not real malware)
- **Verify false positive rates** are minimal
- **Test on multiple PowerShell versions** (5.1, 7.x)
- **Test on different VS Code installations** (stable, insiders, portable)

## ?? Types of Contributions Needed

### High Priority
- **New compromise indicators** from recent attacks
- **Performance optimizations** for large extension collections
- **Enhanced detection algorithms** for obfuscated malware
- **Cross-platform support** (Linux/macOS versions)

### Medium Priority
- **Better reporting formats** (JSON, HTML output)
- **Integration capabilities** (CI/CD pipeline support)
- **Configuration options** (custom package lists)
- **Logging improvements** for audit trails

### Low Priority
- **UI improvements** (better console output)
- **Documentation enhancements**
- **Code refactoring** for maintainability

## ?? Code Standards

### PowerShell Style Guide
```powershell
# Use Pascal Case for functions
function Get-ExtensionInfo { }

# Use approved verbs
function Test-SystemSecurity { }  # Good
function Check-SystemSecurity { } # Avoid

# Include proper help documentation
<#
.SYNOPSIS
Brief description
.DESCRIPTION
Detailed description
.PARAMETER ParameterName
Parameter description
#>
```

### Security Guidelines
- **Never include real malware** in test cases
- **Sanitize all output** that might contain sensitive paths
- **Validate all inputs** to prevent injection attacks
- **Use secure defaults** in all configurations

## ?? Testing Guidelines

### Unit Testing
- Test individual functions with mock data
- Cover edge cases (missing files, corrupted JSON)
- Test error handling paths

### Integration Testing
- Test with real VS Code installations
- Verify detection accuracy with known safe/unsafe packages
- Test performance with large extension collections

### Security Testing
- Verify no false negatives with known compromised packages
- Test resistance to evasion techniques
- Validate output sanitization

## ?? Reporting Issues

### Security Vulnerabilities
- **DO NOT** open public issues for security vulnerabilities
- Use private disclosure via our [Security Policy](SECURITY.md)
- Include proof of concept (if safe)

### Bug Reports
Include the following information:
- **PowerShell version** (`$PSVersionTable`)
- **Operating system** version
- **VS Code version(s)** installed
- **Complete error messages** (sanitized)
- **Steps to reproduce**

### Feature Requests
- Describe the **security benefit** of the feature
- Provide **use cases** and examples
- Consider **performance implications**

## ??? Development Setup

### Prerequisites
```powershell
# Check PowerShell version
$PSVersionTable

# Install Pester for testing (if developing tests)
Install-Module -Name Pester -Force
```

### Development Workflow
1. **Create test environment** with known packages
2. **Develop incrementally** with frequent testing
3. **Document security implications** of changes
4. **Test backwards compatibility** with PowerShell 5.1

## ?? Resources

### PowerShell Development
- [PowerShell Style Guide](https://github.com/PoshCode/PowerShellPracticeAndStyle)
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/dev-cross-plat/security/powershell-security-best-practices)

### Security Research
- [npm Security](https://docs.npmjs.com/about-security-audits)
- [Supply Chain Security](https://slsa.dev/)
- [OWASP Supply Chain](https://owasp.org/www-community/attacks/Supply_Chain_Attack)

## ?? Contribution Priorities

### Critical (Security Impact)
1. **Detection of new attack vectors**
2. **Reduction of false negatives**
3. **Performance for real-time scanning**

### Important (Usability)
1. **Better error messages**
2. **Clearer output formatting**
3. **Additional export formats**

### Nice to Have (Enhancement)
1. **Code organization improvements**
2. **Additional configuration options**
3. **Extended documentation**

## ? Pull Request Checklist

Before submitting a PR, ensure:

- [ ] **Code follows PowerShell best practices**
- [ ] **Security implications documented**
- [ ] **Tests pass on PowerShell 5.1 and 7.x**
- [ ] **No hardcoded paths or credentials**
- [ ] **Error handling implemented**
- [ ] **Documentation updated**
- [ ] **CHANGELOG.md updated** (if applicable)
- [ ] **No false positive/negative regressions**

## ?? Recognition

Contributors will be acknowledged in:
- **README.md contributors section**
- **Release notes** for significant contributions
- **Security hall of fame** for vulnerability discoveries

## ?? Communication

- **GitHub Issues**: Feature requests and bugs
- **Security Email**: Vulnerability reports
- **Discussions**: General questions and ideas

## ?? Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you agree to uphold this code.

---

**Remember**: This tool protects developers from real security threats. Every contribution makes the developer community safer! ???
#Requires -Version 5.1

<#
.SYNOPSIS
    VS Code Extension Security Scanner for npm Supply Chain Attack (September 2025)
    
.DESCRIPTION
    Checks all installed VS Code extensions for compromised npm packages
    from the supply chain attack against developer "qix" on September 8, 2025.
    
.PARAMETER Detailed
    Shows detailed information about found dependencies
    
.PARAMETER ExportResults
    Exports results to a CSV file
    
.PARAMETER CustomVSCodePath
    Specify custom VS Code installation path (e.g., H:\VSCode)

.PARAMETER ShowNetworkDetails
    Shows detailed network connection information
    
.EXAMPLE
    .\VSCode-Security-Scanner.ps1
    
.EXAMPLE
    .\VSCode-Security-Scanner.ps1 -Detailed -ExportResults
    
.EXAMPLE
    .\VSCode-Security-Scanner.ps1 -CustomVSCodePath "H:\VSCode" -Detailed -ShowNetworkDetails
#>

param(
    [switch]$Detailed,
    [switch]$ExportResults,
    [string]$CustomVSCodePath,
    [switch]$ShowNetworkDetails
)

# Compromised npm packages from September 8, 2025 attack
$CompromisedPackages = @(
    'ansi-regex',
    'ansi-styles', 
    'backslash',
    'chalk',
    'chalk-template',
    'color-convert',
    'color-name',
    'color-string',
    'debug',
    'error-ex',
    'has-ansi',
    'is-arrayish',
    'simple-swizzle',
    'slice-ansi',
    'strip-ansi',
    'supports-color',
    'supports-hyperlinks',
    'wrap-ansi',
    'proto-tinker-wc'
)

# Colors for output
$Colors = @{
    Good = 'Green'
    Warning = 'Yellow' 
    Critical = 'Red'
    Info = 'Cyan'
    Header = 'Magenta'
}

function Write-ColorOutput {
    param(
        [string]$Text,
        [string]$Color = 'White'
    )
    Write-Host $Text -ForegroundColor $Colors[$Color]
}

function Get-VSCodeExtensionsPath {
    param([string]$CustomPath)
    
    $Paths = @()
    
    # Custom path if specified
    if ($CustomPath) {
        $CustomExtensionPaths = @(
            "$CustomPath\data\extensions",
            "$CustomPath\extensions", 
            "$CustomPath\resources\app\extensions",
            "$CustomPath\user-data\extensions",
            "$CustomPath\User\extensions"
        )
        
        foreach ($Path in $CustomExtensionPaths) {
            if (Test-Path $Path) {
                $Paths += $Path
                Write-ColorOutput "? Found: $Path" Good
            }
        }
    }
    
    # Standard VS Code extension paths
    $StandardPaths = @(
        "$env:USERPROFILE\.vscode\extensions",
        "$env:USERPROFILE\.vscode-insiders\extensions",
        "$env:APPDATA\Code\User\extensions",
        "$env:APPDATA\Code - Insiders\User\extensions",
        "$env:LOCALAPPDATA\Programs\Microsoft VS Code\resources\app\extensions"
    )
    
    foreach ($Path in $StandardPaths) {
        if (Test-Path $Path) {
            $Paths += $Path
        }
    }
    
    return $Paths
}

function Get-SafeValue {
    param(
        [object]$Value,
        [string]$Default = "Unknown"
    )
    
    if ($Value -and $Value -ne $null -and $Value -ne "") {
        return $Value
    } else {
        return $Default
    }
}

function Get-ExtensionInfo {
    param([string]$ExtensionPath)
    
    $PackageJsonPath = Join-Path $ExtensionPath "package.json"
    $NodeModulesPath = Join-Path $ExtensionPath "node_modules"
    
    if (-not (Test-Path $PackageJsonPath)) {
        return $null
    }
    
    try {
        $PackageJson = Get-Content $PackageJsonPath -Raw | ConvertFrom-Json
        
        # Safe value extraction for older PowerShell versions
        $ExtensionName = Get-SafeValue $PackageJson.displayName
        if ($ExtensionName -eq "Unknown") {
            $ExtensionName = Get-SafeValue $PackageJson.name
        }
        if ($ExtensionName -eq "Unknown") {
            $ExtensionName = Split-Path $ExtensionPath -Leaf
        }
        
        $PublisherName = Get-SafeValue $PackageJson.publisher
        $VersionNumber = Get-SafeValue $PackageJson.version
        
        $ExtensionInfo = [PSCustomObject]@{
            Name = $ExtensionName
            Publisher = $PublisherName
            Version = $VersionNumber
            Path = $ExtensionPath
            Dependencies = @()
            DevDependencies = @()
            HasNodeModules = Test-Path $NodeModulesPath
            CompromisedPackages = @()
            RiskLevel = "Low"
        }
        
        # Read dependencies
        if ($PackageJson.dependencies) {
            $ExtensionInfo.Dependencies = $PackageJson.dependencies.PSObject.Properties.Name
        }
        
        if ($PackageJson.devDependencies) {
            $ExtensionInfo.DevDependencies = $PackageJson.devDependencies.PSObject.Properties.Name
        }
        
        # Check for compromised packages - IMPORTANT CORRECTION
        $AllDeps = $ExtensionInfo.Dependencies + $ExtensionInfo.DevDependencies
        $FoundCompromised = @()
        foreach ($dep in $AllDeps) {
            if ($dep -in $CompromisedPackages) {
                $FoundCompromised += $dep
            }
        }
        $ExtensionInfo.CompromisedPackages = $FoundCompromised
        
        # Risk assessment
        if ($ExtensionInfo.CompromisedPackages.Count -gt 0) {
            $ExtensionInfo.RiskLevel = "Critical"
        } elseif ($ExtensionInfo.HasNodeModules -and ($AllDeps.Count -gt 10)) {
            $ExtensionInfo.RiskLevel = "Medium"
        }
        
        return $ExtensionInfo
    }
    catch {
        Write-Warning "Error reading $PackageJsonPath : $($_.Exception.Message)"
        return $null
    }
}

function Scan-NodeModulesForCompromised {
    param(
        [string]$NodeModulesPath,
        [array]$CompromisedPackages
    )
    
    $FoundPackages = @()
    
    if (-not (Test-Path $NodeModulesPath)) {
        return $FoundPackages
    }
    
    foreach ($Package in $CompromisedPackages) {
        $PackagePath = Join-Path $NodeModulesPath $Package
        if (Test-Path $PackagePath) {
            $PackageJsonPath = Join-Path $PackagePath "package.json"
            if (Test-Path $PackageJsonPath) {
                try {
                    $PackageJson = Get-Content $PackageJsonPath -Raw | ConvertFrom-Json
                    $PackageVersion = Get-SafeValue $PackageJson.version
                    
                    $FoundPackages += [PSCustomObject]@{
                        Name = $Package
                        Version = $PackageVersion
                        Path = $PackagePath
                    }
                }
                catch {
                    $FoundPackages += [PSCustomObject]@{
                        Name = $Package
                        Version = "Error reading"
                        Path = $PackagePath
                    }
                }
            }
        }
    }
    
    return $FoundPackages
}

function Show-ScanResults {
    param([array]$Results)
    
    Write-ColorOutput "`n=== VS CODE EXTENSION SECURITY SCAN RESULTS ===" Header
    Write-ColorOutput "Scan performed on: $(Get-Date)" Info
    Write-ColorOutput "Scanned extensions: $($Results.Count)" Info
    
    # Correct filtering of extensions
    $CriticalExtensions = @($Results | Where-Object { $_.RiskLevel -eq "Critical" })
    $MediumExtensions = @($Results | Where-Object { $_.RiskLevel -eq "Medium" })
    $SafeExtensions = @($Results | Where-Object { $_.RiskLevel -eq "Low" })
    
    if ($Detailed) {
        Write-ColorOutput "`n?? Debug: Found RiskLevels:" Info
        $Results | Group-Object RiskLevel | ForEach-Object {
            Write-ColorOutput "   - $($_.Name): $($_.Count) Extensions" Info
        }
        
        if ($CriticalExtensions.Count -gt 0) {
            Write-ColorOutput "`n?? Debug: Critical extensions found:" Info
            $CriticalExtensions | ForEach-Object {
                Write-ColorOutput "   - $($_.Name): $($_.CompromisedPackages -join ', ')" Info
            }
        }
    }
    
    Write-ColorOutput "`n=== RISK OVERVIEW ===" Header
    Write-ColorOutput "?? CRITICAL: $($CriticalExtensions.Count) Extensions" Critical
    Write-ColorOutput "?? MEDIUM: $($MediumExtensions.Count) Extensions" Warning  
    Write-ColorOutput "?? LOW: $($SafeExtensions.Count) Extensions" Good
    
    if ($CriticalExtensions.Count -gt 0) {
        Write-ColorOutput "`n=== ?? CRITICAL EXTENSIONS (COMPROMISED PACKAGES FOUND) ===" Critical
        foreach ($Ext in $CriticalExtensions) {
            Write-ColorOutput "`n?? $($Ext.Name) by $($Ext.Publisher)" Critical
            Write-ColorOutput "   Version: $($Ext.Version)" Info
            Write-ColorOutput "   Path: $($Ext.Path)" Info
            Write-ColorOutput "   ??  Compromised packages: $($Ext.CompromisedPackages -join ', ')" Critical
            
            if ($Detailed) {
                Write-ColorOutput "   ?? All Dependencies: $($Ext.Dependencies -join ', ')" Info
                Write-ColorOutput "   ?? Dev Dependencies: $($Ext.DevDependencies -join ', ')" Info
                
                # Detailed analysis of node_modules
                $NodeModulesPath = Join-Path $Ext.Path "node_modules"
                $FoundInNodeModules = Scan-NodeModulesForCompromised $NodeModulesPath $CompromisedPackages
                
                if ($FoundInNodeModules.Count -gt 0) {
                    Write-ColorOutput "   ?? Found in node_modules:" Warning
                    foreach ($Found in $FoundInNodeModules) {
                        Write-ColorOutput "      - $($Found.Name) v$($Found.Version)" Critical
                    }
                }
            }
        }
        
        Write-ColorOutput "`n=== ?? IMMEDIATE ACTIONS FOR CRITICAL EXTENSIONS ===" Critical
        Write-ColorOutput "1. Immediately disable/uninstall extension" Critical
        Write-ColorOutput "2. Restart VS Code" Critical
        Write-ColorOutput "3. Check system for suspicious activities" Critical
        Write-ColorOutput "4. Rotate passwords and API keys" Critical
        Write-ColorOutput "5. Check cryptocurrency wallets" Critical
        Write-ColorOutput "6. Review crypto wallet transactions from recent weeks" Critical
    }
    
    if ($MediumExtensions.Count -gt 0 -and $Detailed) {
        Write-ColorOutput "`n=== ??  MEDIUM RISK EXTENSIONS ===" Warning
        foreach ($Ext in $MediumExtensions) {
            Write-ColorOutput "`n?? $($Ext.Name) by $($Ext.Publisher)" Warning
            Write-ColorOutput "   Reason: Many dependencies or node_modules present" Info
            Write-ColorOutput "   Dependencies: $($Ext.Dependencies.Count + $Ext.DevDependencies.Count)" Info
        }
    }
}

function Test-SystemForIndicators {
    param([switch]$ShowDetails)
    
    Write-ColorOutput "`n=== ??? SYSTEM SECURITY CHECK ===" Header
    
    # Check for suspicious processes
    $SuspiciousProcesses = Get-Process | Where-Object { 
        $_.ProcessName -match "(crypto|wallet|miner|coin)" -and
        $_.ProcessName -notmatch "(chrome|firefox|edge|brave)"
    }
    
    if ($SuspiciousProcesses) {
        Write-ColorOutput "??  Suspicious processes found:" Warning
        $SuspiciousProcesses | ForEach-Object {
            Write-ColorOutput "   - $($_.ProcessName) (PID: $($_.Id))" Warning
        }
    } else {
        Write-ColorOutput "? No suspicious processes found" Good
    }
    
    # Detailed network analysis ONLY if ShowDetails is enabled
    if ($ShowDetails) {
        try {
            Write-ColorOutput "`n?? DETAILED NETWORK CONNECTIONS:" Info
            
            $NetworkConnections = Get-NetTCPConnection -State Established | 
                Where-Object { $_.RemotePort -notin @(80, 443, 53) } |
                Group-Object RemoteAddress | 
                Where-Object { $_.Count -gt 3 }
            
            if ($NetworkConnections) {
                Write-ColorOutput "??  Unusual network connections:" Warning
                
                foreach ($Connection in $NetworkConnections) {
                    $RemoteIP = $Connection.Name
                    $ConnectionCount = $Connection.Count
                    
                    Write-ColorOutput "`n?? $RemoteIP ($ConnectionCount connections):" Warning
                    
                    # Detailed connections for this IP
                    $DetailedConnections = Get-NetTCPConnection -State Established | 
                        Where-Object { $_.RemoteAddress -eq $RemoteIP }
                    
                    $DetailedConnections | ForEach-Object {
                        try {
                            $Process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                            $ProcessName = if ($Process) { $Process.ProcessName } else { "Unknown" }
                            $ProcessPath = if ($Process) { 
                                try { $Process.MainModule.FileName } catch { "Unknown" }
                            } else { "Unknown" }
                            
                            Write-ColorOutput "   ?? Port $($_.RemotePort) ? $ProcessName (PID: $($_.OwningProcess))" Info
                            if ($ProcessPath -ne "Unknown") {
                                Write-ColorOutput "      ?? $ProcessPath" Info
                            }
                        }
                        catch {
                            Write-ColorOutput "   ?? Port $($_.RemotePort) ? PID: $($_.OwningProcess)" Info
                        }
                    }
                    
                    # Try to determine hostname
                    try {
                        $HostName = [System.Net.Dns]::GetHostEntry($RemoteIP).HostName
                        if ($HostName -ne $RemoteIP) {
                            Write-ColorOutput "   ???  Hostname: $HostName" Info
                        }
                    }
                    catch {
                        Write-ColorOutput "   ???  Hostname: Not available" Info
                    }
                }
            } else {
                Write-ColorOutput "? No unusual network connections found" Good
            }
            
            # VS Code network activity
            Write-ColorOutput "`n?? VS CODE NETWORK ACTIVITY:" Info
            $VSCodeProcesses = Get-Process | Where-Object { $_.ProcessName -match "code|electron" }
            
            if ($VSCodeProcesses) {
                foreach ($VSProc in $VSCodeProcesses) {
                    $VSConnections = Get-NetTCPConnection -State Established | 
                        Where-Object { $_.OwningProcess -eq $VSProc.Id }
                    
                    if ($VSConnections) {
                        Write-ColorOutput "   ?? $($VSProc.ProcessName) (PID: $($VSProc.Id)):" Info
                        $VSConnections | ForEach-Object {
                            Write-ColorOutput "      ? $($_.RemoteAddress):$($_.RemotePort)" Info
                        }
                    }
                }
            } else {
                Write-ColorOutput "   No active VS Code processes found" Info
            }
            
        }
        catch {
            Write-ColorOutput "Network connections could not be checked (admin rights required)" Info
            Write-ColorOutput "Error: $($_.Exception.Message)" Warning
        }
    } else {
        Write-ColorOutput "`nNote: Use -ShowNetworkDetails for detailed network analysis" Info
    }
}

function Export-ResultsToCSV {
    param(
        [array]$Results,
        [string]$OutputPath = "VSCode_Extension_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    )
    
    $ExportData = foreach ($Result in $Results) {
        [PSCustomObject]@{
            Name = $Result.Name
            Publisher = $Result.Publisher
            Version = $Result.Version
            RiskLevel = $Result.RiskLevel
            CompromisedPackages = ($Result.CompromisedPackages -join ';')
            DependencyCount = $Result.Dependencies.Count + $Result.DevDependencies.Count
            HasNodeModules = $Result.HasNodeModules
            Path = $Result.Path
        }
    }
    
    $ExportData | Export-Csv -Path $OutputPath -Encoding UTF8 -NoTypeInformation
    Write-ColorOutput "`nResults exported to: $OutputPath" Good
}

# === MAIN PROGRAM ===
Write-ColorOutput "?? VS Code Extension Security Scanner" Header
Write-ColorOutput "Checking for npm Supply Chain Attack (Sept 8, 2025)" Info

if ($CustomVSCodePath) {
    Write-ColorOutput "?? Using custom VS Code path: $CustomVSCodePath" Info
}

$ExtensionPaths = Get-VSCodeExtensionsPath -CustomPath $CustomVSCodePath

if ($ExtensionPaths.Count -eq 0) {
    Write-ColorOutput "? No VS Code extensions found!" Critical
    if ($CustomVSCodePath) {
        Write-ColorOutput "Check the specified path: $CustomVSCodePath" Info
        Write-ColorOutput "Possible extension directories:" Info
        Write-ColorOutput "  - $CustomVSCodePath\data\extensions" Info
        Write-ColorOutput "  - $CustomVSCodePath\extensions" Info
        Write-ColorOutput "  - $CustomVSCodePath\User\extensions" Info
    } else {
        Write-ColorOutput "Check if VS Code is installed." Info
        Write-ColorOutput "Or use -CustomVSCodePath for custom paths." Info
    }
    exit 1
}

Write-ColorOutput "`nFound extension directories:" Info
$ExtensionPaths | ForEach-Object { Write-ColorOutput "  - $_" Info }

$AllResults = @()

foreach ($BasePath in $ExtensionPaths) {
    Write-ColorOutput "`n?? Scanning: $BasePath" Info
    
    $Extensions = Get-ChildItem -Path $BasePath -Directory | 
        Where-Object { $_.Name -notmatch "^ms-vscode" -or $Detailed }
    
    foreach ($Extension in $Extensions) {
        $Progress = @{
            Activity = "Scanning Extensions"
            Status = "Processing: $($Extension.Name)"
            PercentComplete = ([Array]::IndexOf($Extensions, $Extension) / $Extensions.Count) * 100
        }
        Write-Progress @Progress
        
        $ExtensionInfo = Get-ExtensionInfo -ExtensionPath $Extension.FullName
        if ($ExtensionInfo) {
            $AllResults += $ExtensionInfo
        }
    }
}

Write-Progress -Activity "Scanning Extensions" -Completed

# Show results
Show-ScanResults -Results $AllResults

# System security check (with ShowDetails parameter)
Test-SystemForIndicators -ShowDetails:$ShowNetworkDetails

# Export if requested
if ($ExportResults) {
    Export-ResultsToCSV -Results $AllResults
}

# Summary
$CriticalCount = @($AllResults | Where-Object { $_.RiskLevel -eq "Critical" }).Count

if ($CriticalCount -gt 0) {
    Write-ColorOutput "`n?? WARNING: $CriticalCount critical extension(s) found!" Critical
    Write-ColorOutput "Immediate action required!" Critical
    
    # Show affected extensions again
    Write-ColorOutput "`nAffected extensions:" Critical
    $AllResults | Where-Object { $_.RiskLevel -eq "Critical" } | ForEach-Object {
        Write-ColorOutput "  - $($_.Name) ($($_.Publisher)): $($_.CompromisedPackages -join ', ')" Critical
    }
    
    exit 2
} else {
    Write-ColorOutput "`n? No critical extensions found." Good
    Write-ColorOutput "Your system appears to be safe." Good
    exit 0
}
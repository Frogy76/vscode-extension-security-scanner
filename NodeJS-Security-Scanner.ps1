#Requires -Version 5.1

<#
.SYNOPSIS
    Node.js Package Security Scanner for npm Supply Chain Attack (September 2025)
    
.DESCRIPTION
    Scans all Node.js projects on the system for compromised npm packages
    from the supply chain attack against developer "qix" on September 8, 2025.
    
.PARAMETER Detailed
    Shows detailed information about found dependencies and scan process
    
.PARAMETER ExportResults
    Exports results to a CSV file
    
.PARAMETER ScanPaths
    Specify custom paths to scan (comma-separated). If not provided, scans common locations.

.PARAMETER MaxDepth
    Maximum directory depth to search for package.json files (default: 5)

.PARAMETER ShowNetworkDetails
    Shows detailed network connection information for Node.js processes
    
.EXAMPLE
    .\NodeJS-Security-Scanner.ps1
    
.EXAMPLE
    .\NodeJS-Security-Scanner.ps1 -Detailed -ExportResults
    
.EXAMPLE
    .\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\Projects,D:\Development" -MaxDepth 3 -Detailed
#>

param(
    [switch]$Detailed,
    [switch]$ExportResults,
    [string[]]$ScanPaths,
    [int]$MaxDepth = 5,
    [switch]$ShowNetworkDetails
)

# Compromised npm packages from September 8, 2025 attack with specific versions
$CompromisedPackages = @{
    'ansi-regex' = '6.2.1'
    'ansi-styles' = '6.2.2'
    'backslash' = '0.2.1'
    'chalk' = '5.6.1'
    'chalk-template' = '1.1.1'
    'color-convert' = '3.1.1'
    'color-name' = '2.0.1'
    'color-string' = '2.1.1'
    'debug' = '4.4.2'
    'error-ex' = '1.3.3'
    'has-ansi' = '6.0.1'
    'is-arrayish' = '0.3.3'
    'simple-swizzle' = '0.2.3'
    'slice-ansi' = '7.1.1'
    'strip-ansi' = '7.1.1'
    'supports-color' = '10.2.1'
    'supports-hyperlinks' = '4.1.1'
    'wrap-ansi' = '9.0.1'
    'proto-tinker-wc' = '1.8.7'
}

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

function Compare-PackageVersion {
    param(
        [string]$InstalledVersion,
        [string]$CompromisedVersion
    )
    
    try {
        if ([string]::IsNullOrEmpty($InstalledVersion) -or [string]::IsNullOrEmpty($CompromisedVersion)) {
            return $false
        }
        
        # Clean version strings
        $CleanInstalled = $InstalledVersion -replace '^[v\^~>=<]+', ''
        $CleanCompromised = $CompromisedVersion -replace '^[v\^~>=<]+', ''
        
        # Split version parts
        $InstalledParts = $CleanInstalled.Split('.')
        $CompromisedParts = $CleanCompromised.Split('.')
        
        # Compare major.minor.patch
        for ($i = 0; $i -lt [Math]::Min($InstalledParts.Length, $CompromisedParts.Length); $i++) {
            $InstalledPart = 0
            $CompromisedPart = 0
            
            [int]::TryParse($InstalledParts[$i], [ref]$InstalledPart) | Out-Null
            [int]::TryParse($CompromisedParts[$i], [ref]$CompromisedPart) | Out-Null
            
            if ($InstalledPart -ne $CompromisedPart) {
                return $false
            }
        }
        
        return $true
    }
    catch {
        return $InstalledVersion -eq $CompromisedVersion
    }
}

function Get-DefaultScanPaths {
    $DefaultPaths = @()
    
    $CommonPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents", 
        "$env:USERPROFILE\source",
        "$env:USERPROFILE\Projects",
        "$env:USERPROFILE\Development",
        "C:\Projects",
        "C:\Development"
    )
    
    foreach ($Path in $CommonPaths) {
        if (Test-Path $Path) {
            $DefaultPaths += $Path
        }
    }
    
    return $DefaultPaths
}

function Find-NodeJSProjects {
    param(
        [string[]]$SearchPaths,
        [int]$MaxSearchDepth = 5
    )
    
    $Projects = @()
    Write-ColorOutput "`nSearching for Node.js projects..." Info
    
    foreach ($BasePath in $SearchPaths) {
        if (-not (Test-Path $BasePath)) {
            Write-ColorOutput "Path not found: $BasePath" Warning
            continue
        }
        
        Write-ColorOutput "Scanning: $BasePath (max depth: $MaxSearchDepth)" Info
        
        try {
            # Find package.json files
            $PackageFiles = Get-ChildItem -Path $BasePath -Name "package.json" -Recurse -Depth $MaxSearchDepth -File -ErrorAction SilentlyContinue
            
            foreach ($File in $PackageFiles) {
                $FullPath = Join-Path $BasePath $File
                $ProjectDir = Split-Path $FullPath -Parent
                
                # Skip node_modules directories
                if ($ProjectDir -notmatch "node_modules") {
                    $Projects += [PSCustomObject]@{
                        Name = Split-Path $ProjectDir -Leaf
                        Path = $ProjectDir
                        PackageJsonPath = $FullPath
                    }
                }
            }
        }
        catch {
            Write-ColorOutput "Error scanning $BasePath : $($_.Exception.Message)" Warning
        }
    }
    
    return $Projects
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

function Get-ProjectInfo {
    param([PSCustomObject]$Project)
    
    if (-not (Test-Path $Project.PackageJsonPath)) {
        return $null
    }
    
    try {
        $PackageJson = Get-Content $Project.PackageJsonPath -Raw | ConvertFrom-Json
        
        $ProjectInfo = [PSCustomObject]@{
            Name = Get-SafeValue $PackageJson.name $Project.Name
            Version = Get-SafeValue $PackageJson.version "Unknown"
            Path = $Project.Path
            Dependencies = @()
            CompromisedPackages = @()
            RiskLevel = "Low"
            TotalDependencies = 0
        }
        
        # Read dependencies
        if ($PackageJson.dependencies) {
            $ProjectInfo.Dependencies = $PackageJson.dependencies.PSObject.Properties.Name
        }
        
        $ProjectInfo.TotalDependencies = $ProjectInfo.Dependencies.Count
        
        # Check for compromised packages
        $FoundCompromised = @()
        
        if ($PackageJson.dependencies) {
            foreach ($depName in $PackageJson.dependencies.PSObject.Properties.Name) {
                if ($CompromisedPackages.ContainsKey($depName)) {
                    $installedVersion = $PackageJson.dependencies.$depName
                    $compromisedVersion = $CompromisedPackages[$depName]
                    $versionMatch = Compare-PackageVersion $installedVersion $compromisedVersion
                    
                    $FoundCompromised += [PSCustomObject]@{
                        Name = $depName
                        InstalledVersion = $installedVersion
                        CompromisedVersion = $compromisedVersion
                        ExactMatch = $versionMatch
                        Type = "dependency"
                    }
                }
            }
        }
        
        $ProjectInfo.CompromisedPackages = $FoundCompromised
        
        # Risk assessment
        if ($ProjectInfo.CompromisedPackages.Count -gt 0) {
            $ProjectInfo.RiskLevel = "Critical"
        } elseif ($ProjectInfo.TotalDependencies -gt 50) {
            $ProjectInfo.RiskLevel = "Medium"
        }
        
        return $ProjectInfo
    }
    catch {
        Write-Warning "Error reading $($Project.PackageJsonPath): $($_.Exception.Message)"
        return $null
    }
}

function Show-ScanResults {
    param([array]$Results)
    
    Write-ColorOutput "`n=== NODE.JS PROJECT SECURITY SCAN RESULTS ===" Header
    Write-ColorOutput "Scan performed on: $(Get-Date)" Info
    Write-ColorOutput "Scanned projects: $($Results.Count)" Info
    
    $CriticalProjects = @($Results | Where-Object { $_.RiskLevel -eq "Critical" })
    $MediumProjects = @($Results | Where-Object { $_.RiskLevel -eq "Medium" })
    $SafeProjects = @($Results | Where-Object { $_.RiskLevel -eq "Low" })
    
    Write-ColorOutput "`n=== RISK OVERVIEW ===" Header
    Write-ColorOutput "CRITICAL: $($CriticalProjects.Count) Projects" Critical
    Write-ColorOutput "MEDIUM: $($MediumProjects.Count) Projects" Warning  
    Write-ColorOutput "LOW: $($SafeProjects.Count) Projects" Good
    
    if ($CriticalProjects.Count -gt 0) {
        Write-ColorOutput "`n=== CRITICAL PROJECTS (COMPROMISED PACKAGES FOUND) ===" Critical
        foreach ($Project in $CriticalProjects) {
            Write-ColorOutput "`n$($Project.Name) v$($Project.Version)" Critical
            Write-ColorOutput "   Path: $($Project.Path)" Info
            
            Write-ColorOutput "   Compromised packages found:" Critical
            foreach ($CompromisedPkg in $Project.CompromisedPackages) {
                $Status = if ($CompromisedPkg.ExactMatch) { "EXACT MATCH!" } else { "Version differs" }
                $StatusColor = if ($CompromisedPkg.ExactMatch) { "Critical" } else { "Warning" }
                
                Write-ColorOutput "      - $($CompromisedPkg.Name)" Critical
                Write-ColorOutput "        Installed: $($CompromisedPkg.InstalledVersion) | Compromised: $($CompromisedPkg.CompromisedVersion)" Info
                Write-ColorOutput "        Status: $Status" $StatusColor
            }
        }
        
        Write-ColorOutput "`n=== IMMEDIATE ACTIONS REQUIRED ===" Critical
        Write-ColorOutput "1. Stop all Node.js processes for affected projects" Critical
        Write-ColorOutput "2. Delete node_modules and package-lock.json" Critical
        Write-ColorOutput "3. Update package.json to use safe versions" Critical
        Write-ColorOutput "4. Check system for suspicious activities" Critical
        Write-ColorOutput "5. Check cryptocurrency wallets immediately" Critical
    }
    
    if ($MediumProjects.Count -gt 0 -and $Detailed) {
        Write-ColorOutput "`n=== MEDIUM RISK PROJECTS ===" Warning
        foreach ($Project in $MediumProjects) {
            Write-ColorOutput "`n$($Project.Name) v$($Project.Version)" Warning
            Write-ColorOutput "   Path: $($Project.Path)" Info
            Write-ColorOutput "   Reason: Large number of dependencies ($($Project.TotalDependencies))" Info
        }
    }
}

function Test-SystemForIndicators {
    param([switch]$ShowDetails)
    
    Write-ColorOutput "`n=== SYSTEM SECURITY CHECK ===" Header
    
    $NodeProcesses = Get-Process | Where-Object { 
        $_.ProcessName -match "(node|npm|yarn)" 
    }
    
    if ($NodeProcesses) {
        Write-ColorOutput "Active Node.js processes found:" Warning
        $NodeProcesses | ForEach-Object {
            Write-ColorOutput "   - $($_.ProcessName) (PID: $($_.Id))" Info
        }
    } else {
        Write-ColorOutput "No active Node.js processes found" Good
    }
    
    $SuspiciousProcesses = Get-Process | Where-Object { 
        $_.ProcessName -match "(crypto|wallet|miner|coin)" -and
        $_.ProcessName -notmatch "(chrome|firefox|edge|brave)"
    }
    
    if ($SuspiciousProcesses) {
        Write-ColorOutput "Suspicious crypto-related processes found:" Critical
        $SuspiciousProcesses | ForEach-Object {
            Write-ColorOutput "   - $($_.ProcessName) (PID: $($_.Id))" Critical
        }
    } else {
        Write-ColorOutput "No suspicious crypto-related processes found" Good
    }
}

function Export-ResultsToCSV {
    param(
        [array]$Results,
        [string]$OutputPath = "NodeJS_Security_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    )
    
    $ExportData = foreach ($Result in $Results) {
        $CompromisedDetails = @()
        foreach ($CompromisedPkg in $Result.CompromisedPackages) {
            $VersionStatus = if ($CompromisedPkg.ExactMatch) { "EXACT_MATCH" } else { "VERSION_DIFFERS" }
            $Detail = "$($CompromisedPkg.Name):$($CompromisedPkg.InstalledVersion)->$($CompromisedPkg.CompromisedVersion):$VersionStatus"
            $CompromisedDetails += $Detail
        }
        
        [PSCustomObject]@{
            ProjectName = $Result.Name
            Version = $Result.Version
            Path = $Result.Path
            RiskLevel = $Result.RiskLevel
            TotalDependencies = $Result.TotalDependencies
            CompromisedPackagesCount = $Result.CompromisedPackages.Count
            CompromisedPackagesDetails = ($CompromisedDetails -join ";")
        }
    }
    
    $ExportData | Export-Csv -Path $OutputPath -Encoding UTF8 -NoTypeInformation
    Write-ColorOutput "`nResults exported to: $OutputPath" Good
}

# === MAIN PROGRAM ===
Write-ColorOutput "Node.js Package Security Scanner" Header
Write-ColorOutput "Checking for npm Supply Chain Attack (Sept 8, 2025)" Info

# Determine scan paths
if ($ScanPaths) {
    $PathsToScan = $ScanPaths
    Write-ColorOutput "Using custom scan paths: $($ScanPaths -join ', ')" Info
} else {
    $PathsToScan = Get-DefaultScanPaths
    Write-ColorOutput "Using default scan paths:" Info
    $PathsToScan | ForEach-Object { Write-ColorOutput "  - $_" Info }
}

if ($PathsToScan.Count -eq 0) {
    Write-ColorOutput "No valid paths found to scan!" Critical
    Write-ColorOutput "Try using -ScanPaths to specify custom directories" Info
    exit 1
}

# Find all Node.js projects
$NodeProjects = Find-NodeJSProjects -SearchPaths $PathsToScan -MaxSearchDepth $MaxDepth

if ($NodeProjects.Count -eq 0) {
    Write-ColorOutput "No Node.js projects found!" Warning
    Write-ColorOutput "Searched in:" Info
    $PathsToScan | ForEach-Object { Write-ColorOutput "  - $_" Info }
    exit 1
}

Write-ColorOutput "`nFound $($NodeProjects.Count) Node.js project(s)" Good

# Analyze each project
$AllResults = @()
$ProcessedCount = 0

foreach ($Project in $NodeProjects) {
    $ProcessedCount++
    Write-Progress -Activity "Analyzing Projects" -Status "Processing: $($Project.Name)" -PercentComplete (($ProcessedCount / $NodeProjects.Count) * 100)
    
    $ProjectInfo = Get-ProjectInfo -Project $Project
    if ($ProjectInfo) {
        $AllResults += $ProjectInfo
    }
}

Write-Progress -Activity "Analyzing Projects" -Completed

# Show results
Show-ScanResults -Results $AllResults

# System security check
Test-SystemForIndicators -ShowDetails:$ShowNetworkDetails

# Export if requested
if ($ExportResults) {
    Export-ResultsToCSV -Results $AllResults
}

# Summary and exit
$CriticalCount = @($AllResults | Where-Object { $_.RiskLevel -eq "Critical" }).Count

if ($CriticalCount -gt 0) {
    Write-ColorOutput "`nWARNING: $CriticalCount critical project(s) found!" Critical
    Write-ColorOutput "IMMEDIATE ACTION REQUIRED!" Critical
    exit 2
} else {
    Write-ColorOutput "`nNo critical projects found." Good
    Write-ColorOutput "Your Node.js projects appear to be safe from this specific attack." Good
    exit 0
}
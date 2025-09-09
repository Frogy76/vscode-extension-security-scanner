# Node.js Package Security Scanner

## 🛡️ Overview

Der **Node.js Package Security Scanner** ist ein umfassendes PowerShell-Tool zur Erkennung kompromittierter npm-Pakete in Node.js-Projekten. Es wurde speziell entwickelt, um gegen die Supply-Chain-Attacke vom 8. September 2025 gegen den Entwickler "qix" zu schützen.

## 🚀 Quick Start

```powershell
# Basis-Scan des Systems
.\NodeJS-Security-Scanner.ps1

# Detaillierter Scan mit Export
.\NodeJS-Security-Scanner.ps1 -Detailed -ExportResults

# Spezifische Pfade scannen
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\Projects,D:\Development" -MaxDepth 3
```

## 📋 Systemanforderungen

- **PowerShell**: Version 5.1 oder höher
- **Betriebssystem**: Windows 7/8/10/11, Windows Server 2012+
- **Berechtigung**: Standard-Benutzerrechte (Admin-Rechte für erweiterte Netzwerkanalyse)
- **Abhängigkeiten**: Keine externen Module erforderlich

## 🎯 Hauptfunktionen

### Umfassende Projekterkennung
- ✅ Automatische Suche nach `package.json`-Dateien
- ✅ Konfigurierbare Suchtiefe zur Performance-Optimierung
- ✅ Intelligente Filterung von `node_modules`-Verzeichnissen
- ✅ Unterstützung für benutzerdefinierte Suchpfade

### Erweiterte Paketanalyse
- ✅ Prüfung aller Abhängigkeitstypen:
  - `dependencies` (Produktions-Abhängigkeiten)
  - `devDependencies` (Entwicklungs-Abhängigkeiten)
  - `peerDependencies` (Peer-Abhängigkeiten)
  - `optionalDependencies` (Optionale Abhängigkeiten)
- ✅ Semantische Versionsvergreichung
- ✅ Erkennung exakter Versionsübereinstimmungen

### System-Sicherheitsüberwachung
- ✅ Erkennung laufender Node.js-Prozesse
- ✅ Identifikation verdächtiger Kryptowährungs-Prozesse
- ✅ Optionale Netzwerkverbindungsanalyse
- ✅ Prozess-ID-Tracking und Pfadanalyse

## 📖 Parameter-Referenz

### Basis-Parameter

| Parameter | Typ | Standard | Beschreibung |
|-----------|-----|----------|-------------|
| `-Detailed` | Switch | `$false` | Zeigt detaillierte Informationen über Abhängigkeiten |
| `-ExportResults` | Switch | `$false` | Exportiert Ergebnisse in CSV-Datei |
| `-ScanPaths` | String[] | Auto-Erkennung | Comma-getrennte Liste von Scan-Pfaden |
| `-MaxDepth` | Int | `5` | Maximale Suchtiefe in Verzeichnisstrukturen |
| `-ShowNetworkDetails` | Switch | `$false` | Zeigt detaillierte Netzwerkverbindungen |

### Standard-Suchpfade (wenn keine benutzerdefinierten angegeben)
```powershell
$env:USERPROFILE\Desktop
$env:USERPROFILE\Documents
$env:USERPROFILE\source
$env:USERPROFILE\Projects
$env:USERPROFILE\Development
C:\Projects
C:\Development
```

## 🔍 Verwendungsbeispiele

### Entwicklungsumgebung
```powershell
# Vollständiger Entwickler-Workstation-Scan
.\NodeJS-Security-Scanner.ps1 -ScanPaths "$env:USERPROFILE\source,$env:USERPROFILE\Desktop,$env:USERPROFILE\Documents" -Detailed -ExportResults

# Schneller Projekt-Check
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\CurrentProject" -MaxDepth 2
```

### CI/CD-Pipeline
```powershell
# Build-Agent Sicherheitsprüfung
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\BuildAgent\work" -ExportResults

# Exit-Code-basierte Pipeline-Integration
$exitCode = & .\NodeJS-Security-Scanner.ps1 -ScanPaths $BUILD_DIRECTORY
if ($exitCode -eq 2) { 
    Write-Error "Kritische Sicherheitsprobleme gefunden!"
    exit 1 
}
```

### Produktionsserver
```powershell
# Server-Sicherheitsaudit
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\inetpub,C:\Applications" -MaxDepth 2 -ShowNetworkDetails -ExportResults

# Überwachung mit reduzierter Suchtiefe für Performance
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\WebApps" -MaxDepth 1
```

## 🎨 Output-Kategorien

### Konsolen-Ausgabe
- **🚨 CRITICAL**: Projekte mit exakten Versionsübereinstimmungen kompromittierter Pakete
- **⚠️ MEDIUM**: Projekte mit großen Abhängigkeitsbäumen (>50 Abhängigkeiten)
- **✅ LOW**: Sichere Projekte ohne erkannte Bedrohungen

### Farbkodierung
- **Rot**: Kritische Bedrohungen, sofortiges Handeln erforderlich
- **Gelb**: Warnungen, Überwachung empfohlen
- **Grün**: Sichere Zustände
- **Cyan**: Informative Details
- **Magenta**: Abschnitts-Header

## 📊 CSV-Export-Format

```csv
ProjectName,Version,Path,RiskLevel,TotalDependencies,CompromisedPackagesCount,CompromisedPackagesDetails
MyApp,1.0.0,C:\Projects\MyApp,Critical,25,2,"chalk:5.6.1->5.6.1:EXACT_MATCH;debug:4.4.2->4.4.2:EXACT_MATCH"
```

### Export-Felder Erklärung
- **CompromisedPackagesDetails**: Format `PackageName:InstalledVersion->CompromisedVersion:Status`
- **Status-Werte**: `EXACT_MATCH` (höchstes Risiko) oder `VERSION_DIFFERS`

## 🔧 Risikobewertungs-Framework

### Critical Risk (🚨)
- Enthält Pakete mit **exakter Versionsübereinstimmung** zu kompromittierten Versionen
- Direkte Abhängigkeiten von bekannten schädlichen Paketen
- Hohe Wahrscheinlichkeit einer aktiven Kompromittierung

### Medium Risk (⚠️)
- Projekte mit >50 Gesamtabhängigkeiten (erhöhte Angriffsfläche)
- Komplexe Projektstrukturen mit umfangreichen node_modules
- Aktive Entwicklungsumgebungen mit häufigen Abhängigkeits-Updates

### Low Risk (✅)
- Keine kompromittierten Pakete erkannt
- Minimale, fokussierte Abhängigkeitsbäume
- Versionsunterschiede zu markierten Paketen (geringere Kompromittierungswahrscheinlichkeit)

## ⚡ Performance-Optimierung

### Empfohlene Einstellungen nach Szenario

| Szenario | MaxDepth | Detailed | ShowNetworkDetails | Begründung |
|----------|----------|----------|--------------------|-------------|
| **Entwickler-Workstation** | 3-5 | ✅ | ✅ | Vollständige Analyse gewünscht |
| **Build-Server** | 2-3 | ❌ | ❌ | Fokus auf kritische Findings |
| **Produktionsserver** | 1-2 | ❌ | ✅ | Performance + Netzwerk-Monitoring |
| **Sicherheitsaudit** | 5+ | ✅ | ✅ | Vollständige Abdeckung erforderlich |

### Performance-Features
- **Streaming-Analyse**: Speicher-effiziente Verarbeitung großer Projektsammlungen
- **Progress-Tracking**: Echtzeit-Feedback bei lang laufenden Operationen
- **Konfigurierbare Tiefenbegrenzung**: Verhindert übermäßige Rekursion
- **Smart Filtering**: Überspringt irrelevante Verzeichnisse automatisch

## 🚨 Kompromittierte Pakete-Datenbank (September 2025)

Der Scanner erkennt folgende kompromittierte npm-Pakete:

```powershell
'ansi-regex' = '6.2.1'          # Terminal-Ausgabe Manipulation
'ansi-styles' = '6.2.2'         # Styling-Bibliothek
'backslash' = '0.2.1'           # String-Verarbeitung
'chalk' = '5.6.1'               # Terminal-Farben (weit verbreitet!)
'chalk-template' = '1.1.1'      # Chalk-Erweiterung
'color-convert' = '3.1.1'       # Farbkonvertierung
'color-name' = '2.0.1'          # Farbnamen-Bibliothek
'color-string' = '2.1.1'        # String-zu-Farbe-Konvertierung
'debug' = '4.4.2'               # Debug-Ausgaben (sehr häufig!)
'error-ex' = '1.3.3'            # Erweiterte Error-Behandlung
'has-ansi' = '6.0.1'            # ANSI-Erkennung
'is-arrayish' = '0.3.3'         # Array-ähnliche Objekterkennung
'simple-swizzle' = '0.2.3'      # Farb-Swizzling
'slice-ansi' = '7.1.1'          # ANSI-String-Slicing
'strip-ansi' = '7.1.1'          # ANSI-Code-Entfernung
'supports-color' = '10.2.1'     # Farbunterstützung-Detection
'supports-hyperlinks' = '4.1.1' # Hyperlink-Unterstützung
'wrap-ansi' = '9.0.1'           # ANSI-String-Wrapping
'proto-tinker-wc' = '1.8.7'     # Weniger bekannte Bibliothek
```

## 🛠️ Troubleshooting

### Häufige Probleme und Lösungen

#### "No Node.js projects found!"
```powershell
# Lösung 1: Erhöhe die Suchtiefe
.\NodeJS-Security-Scanner.ps1 -MaxDepth 10

# Lösung 2: Spezifiziere exakte Pfade
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\MeinProjektPfad"

# Lösung 3: Prüfe, ob package.json-Dateien existieren
Get-ChildItem -Recurse -Name "package.json" -Path "C:\Projects"
```

#### "Network connections could not be checked"
```powershell
# Lösung: Führe PowerShell als Administrator aus
# Oder verwende ohne Netzwerk-Monitoring:
.\NodeJS-Security-Scanner.ps1 -Detailed -ExportResults
```

#### Langsame Performance bei großen Verzeichnissen
```powershell
# Lösung: Reduziere MaxDepth und verwende spezifische Pfade
.\NodeJS-Security-Scanner.ps1 -ScanPaths "C:\SpecificProject" -MaxDepth 2
```

## 🔗 Integration mit VSCode Scanner

### Komplementäre Verwendung
```powershell
# Schritt 1: VSCode-Erweiterungen scannen
.\VSCode-Security-Scanner.ps1 -Detailed -ExportResults

# Schritt 2: System-weite Node.js-Projekte scannen
.\NodeJS-Security-Scanner.ps1 -Detailed -ExportResults -ShowNetworkDetails

# Schritt 3: Ergebnisse vergleichen und korrelieren
```

### Geteilte Erkennungslogik
- Identische kompromittierte Paket-Datenbank
- Einheitliches Risikobewertungs-Framework
- Konsistente Versions-Vergleichsalgorithmen
- Gemeinsame Exit-Code-Konventionen

## 📞 Support und Beitrag

### Exit-Codes
- `0`: Keine kritischen Bedrohungen gefunden
- `1`: Allgemeine Fehler (keine Projekte gefunden, ungültige Parameter)
- `2`: Kritische Sicherheitsbedrohungen erkannt - **Sofortiges Handeln erforderlich!**

### Sofortige Maßnahmen bei Exit-Code 2
1. **Stoppe alle Node.js-Prozesse** der betroffenen Projekte
2. **Lösche node_modules** und package-lock.json/yarn.lock
3. **Aktualisiere package.json** auf sichere Versionen
4. **Führe `npm audit`** oder `yarn audit` aus
5. **Überprüfe Kryptowährungs-Wallets** sofort
6. **Rotiere Passwörter und API-Keys**
7. **Überprüfe Transaktionen** der letzten Wochen

---

**⚠️ Wichtiger Sicherheitshinweis**: Dieses Tool dient ausschließlich **defensiven Sicherheitszwecken**. Es erkennt und hilft bei der Behebung von Sicherheitsbedrohungen, führt aber keine schädlichen Aktionen aus.
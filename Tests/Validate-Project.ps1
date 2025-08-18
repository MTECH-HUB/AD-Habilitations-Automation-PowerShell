<#
.SYNOPSIS
    Script de validation complète du projet AD-Habilitations-Automation

.DESCRIPTION
    Ce script effectue une validation complète de tous les composants du projet
    pour s'assurer qu'il n'y a pas d'erreurs et que tout fonctionne correctement.

.NOTES
    Auteur: IT Security Team
    Version: 1.0
#>

function Write-ValidationLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $colors = @{
        "INFO" = "White"
        "SUCCESS" = "Green"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
    }
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Test-PowerShellSyntax {
    param([string]$FilePath)
    
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $FilePath -Raw), [ref]$null)
        return $true
    } catch {
        Write-ValidationLog "Erreur de syntaxe dans $FilePath : $_" -Level "ERROR"
        return $false
    }
}

function Test-JsonSyntax {
    param([string]$FilePath)
    
    try {
        Get-Content $FilePath | ConvertFrom-Json | Out-Null
        return $true
    } catch {
        Write-ValidationLog "Erreur JSON dans $FilePath : $_" -Level "ERROR"
        return $false
    }
}

function Test-FunctionReferences {
    param([string]$ProjectPath)
    
    Write-ValidationLog "Vérification des références de fonctions..." -Level "INFO"
    $issues = @()
    
    # Fonctions définies dans AD-Functions.psm1
    $moduleFile = Join-Path $ProjectPath "Config\AD-Functions.psm1"
    if (Test-Path $moduleFile) {
        $moduleContent = Get-Content $moduleFile -Raw
        $definedFunctions = [regex]::Matches($moduleContent, "function\s+([a-zA-Z-]+)") | ForEach-Object { $_.Groups[1].Value }
        Write-ValidationLog "Fonctions définies dans le module : $($definedFunctions -join ', ')" -Level "INFO"
    }
    
    # Vérification des appels de fonctions
    $scriptFiles = Get-ChildItem $ProjectPath -Recurse -Filter "*.ps1"
    foreach ($script in $scriptFiles) {
        $content = Get-Content $script.FullName -Raw
        
        # Recherche d'appels de fonctions inexistantes (patterns courants)
        $functionCalls = [regex]::Matches($content, "([A-Z][a-zA-Z-]+)\s*-") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        
        foreach ($call in $functionCalls) {
            if ($call -notin $definedFunctions -and $call -notmatch "^(Get|Set|New|Remove|Add|Test|Invoke|Start|Stop|Enable|Disable|Import|Export|Write|Read)-.+") {
                # Ignorer les cmdlets PowerShell standards
                if ($call -notin @("Write-Host", "Write-Log", "Get-Content", "Test-Path")) {
                    $issues += "Fonction potentiellement inexistante '$call' dans $($script.Name)"
                }
            }
        }
    }
    
    return $issues
}

function Test-ProjectStructure {
    param([string]$ProjectPath)
    
    Write-ValidationLog "Vérification de la structure du projet..." -Level "INFO"
    $requiredPaths = @(
        "Scripts",
        "Config", 
        "Logs",
        "Reports",
        "Templates",
        "Tests",
        "Scripts\AD-MainMenu.ps1",
        "Scripts\AD-UserManagement.ps1",
        "Scripts\AD-RightsAudit.ps1",
        "Scripts\AD-ComplianceReport.ps1",
        "Config\settings.json",
        "Config\user-templates.json",
        "Config\compliance-rules.json",
        "Config\AD-Functions.psm1"
    )
    
    $missing = @()
    foreach ($path in $requiredPaths) {
        $fullPath = Join-Path $ProjectPath $path
        if (-not (Test-Path $fullPath)) {
            $missing += $path
        }
    }
    
    return $missing
}

function Test-ConfigurationValidity {
    param([string]$ProjectPath)
    
    Write-ValidationLog "Validation des fichiers de configuration..." -Level "INFO"
    $issues = @()
    
    # Test settings.json
    $settingsPath = Join-Path $ProjectPath "Config\settings.json"
    if (Test-Path $settingsPath) {
        try {
            $settings = Get-Content $settingsPath | ConvertFrom-Json
            
            # Vérifications de base
            if (-not $settings.General) { $issues += "Section General manquante dans settings.json" }
            if (-not $settings.UserManagement) { $issues += "Section UserManagement manquante dans settings.json" }
            if (-not $settings.Compliance) { $issues += "Section Compliance manquante dans settings.json" }
            
        } catch {
            $issues += "Erreur dans settings.json : $_"
        }
    }
    
    # Test user-templates.json
    $templatesPath = Join-Path $ProjectPath "Config\user-templates.json"
    if (Test-Path $templatesPath) {
        try {
            $templates = Get-Content $templatesPath | ConvertFrom-Json
            if (-not $templates.Default) { $issues += "Modèle Default manquant dans user-templates.json" }
        } catch {
            $issues += "Erreur dans user-templates.json : $_"
        }
    }
    
    return $issues
}

function Test-ScriptParameters {
    param([string]$ProjectPath)
    
    Write-ValidationLog "Vérification des paramètres des scripts..." -Level "INFO"
    $issues = @()
    
    $scriptFiles = Get-ChildItem (Join-Path $ProjectPath "Scripts") -Filter "*.ps1"
    foreach ($script in $scriptFiles) {
        $content = Get-Content $script.FullName -Raw
        
        # Vérifier la présence de param() au début
        if ($content -match "param\s*\(" -and $content -notmatch "^\s*<#.*?#>\s*param\s*\(") {
            # Script avec paramètres - vérifier la structure
            if ($content -notmatch "\[Parameter\(") {
                $issues += "Paramètres sans attributs [Parameter] dans $($script.Name)"
            }
        }
    }
    
    return $issues
}

# Fonction principale de validation
function Invoke-ProjectValidation {
    param([string]$ProjectPath)
    
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    🔍 VALIDATION DU PROJET AD-AUTOMATION 🔍                     ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    $allIssues = @()
    $totalTests = 0
    $passedTests = 0
    
    # 1. Structure du projet
    Write-ValidationLog "═══ TEST 1: Structure du projet ═══" -Level "INFO"
    $totalTests++
    $missingPaths = Test-ProjectStructure -ProjectPath $ProjectPath
    if ($missingPaths.Count -eq 0) {
        Write-ValidationLog "Structure du projet: OK" -Level "SUCCESS"
        $passedTests++
    } else {
        Write-ValidationLog "Éléments manquants: $($missingPaths -join ', ')" -Level "ERROR"
        $allIssues += $missingPaths
    }
    
    # 2. Syntaxe PowerShell
    Write-ValidationLog "`n═══ TEST 2: Syntaxe PowerShell ═══" -Level "INFO"
    $psFiles = Get-ChildItem $ProjectPath -Recurse -Filter "*.ps*"
    foreach ($file in $psFiles) {
        $totalTests++
        if (Test-PowerShellSyntax -FilePath $file.FullName) {
            Write-ValidationLog "$($file.Name): OK" -Level "SUCCESS"
            $passedTests++
        } else {
            $allIssues += "Erreur de syntaxe dans $($file.Name)"
        }
    }
    
    # 3. Syntaxe JSON
    Write-ValidationLog "`n═══ TEST 3: Syntaxe JSON ═══" -Level "INFO"
    $jsonFiles = Get-ChildItem $ProjectPath -Recurse -Filter "*.json"
    foreach ($file in $jsonFiles) {
        $totalTests++
        if (Test-JsonSyntax -FilePath $file.FullName) {
            Write-ValidationLog "$($file.Name): OK" -Level "SUCCESS"
            $passedTests++
        } else {
            $allIssues += "Erreur JSON dans $($file.Name)"
        }
    }
    
    # 4. Configuration
    Write-ValidationLog "`n═══ TEST 4: Configuration ═══" -Level "INFO"
    $totalTests++
    $configIssues = Test-ConfigurationValidity -ProjectPath $ProjectPath
    if ($configIssues.Count -eq 0) {
        Write-ValidationLog "Configuration: OK" -Level "SUCCESS"
        $passedTests++
    } else {
        Write-ValidationLog "Problèmes de configuration détectés" -Level "ERROR"
        $allIssues += $configIssues
    }
    
    # 5. Références de fonctions
    Write-ValidationLog "`n═══ TEST 5: Références de fonctions ═══" -Level "INFO"
    $totalTests++
    $functionIssues = Test-FunctionReferences -ProjectPath $ProjectPath
    if ($functionIssues.Count -eq 0) {
        Write-ValidationLog "Références de fonctions: OK" -Level "SUCCESS"
        $passedTests++
    } else {
        Write-ValidationLog "Problèmes de références détectés" -Level "WARNING"
        $allIssues += $functionIssues
    }
    
    # 6. Paramètres des scripts
    Write-ValidationLog "`n═══ TEST 6: Paramètres des scripts ═══" -Level "INFO"
    $totalTests++
    $paramIssues = Test-ScriptParameters -ProjectPath $ProjectPath
    if ($paramIssues.Count -eq 0) {
        Write-ValidationLog "Paramètres des scripts: OK" -Level "SUCCESS"
        $passedTests++
    } else {
        Write-ValidationLog "Problèmes de paramètres détectés" -Level "WARNING"
        $allIssues += $paramIssues
    }
    
    # Résumé final
    Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                              📊 RÉSULTATS DE VALIDATION                          ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    $successRate = [math]::Round(($passedTests / $totalTests) * 100, 1)
    
    Write-Host "📈 Tests réussis: $passedTests/$totalTests ($successRate%)" -ForegroundColor $(if($successRate -ge 90){"Green"}elseif($successRate -ge 70){"Yellow"}else{"Red"})
    
    if ($allIssues.Count -eq 0) {
        Write-Host "🎉 Aucun problème détecté ! Le projet est prêt à être utilisé." -ForegroundColor Green
    } else {
        Write-Host "`n⚠️  Problèmes détectés:" -ForegroundColor Yellow
        foreach ($issue in $allIssues) {
            Write-Host "   • $issue" -ForegroundColor Red
        }
        
        Write-Host "`n💡 Actions recommandées:" -ForegroundColor Cyan
        Write-Host "   Write-Host "   1. Corriger les erreurs critiques (syntaxe, configuration)" -ForegroundColor Yellow" -ForegroundColor Yellow
        Write-Host "   2. Réviser les avertissements si nécessaire" -ForegroundColor Yellow
        Write-Host "   3. Tester le fonctionnement avec .\Tests\Test-Installation.ps1" -ForegroundColor Yellow
    }
    
    # Score final
    $finalScore = if ($allIssues.Count -eq 0) { "A+" } 
                  elseif ($successRate -ge 90) { "A" }
                  elseif ($successRate -ge 80) { "B" }
                  elseif ($successRate -ge 70) { "C" }
                  else { "D" }
    
    Write-Host "`n🏆 Score de qualité: $finalScore" -ForegroundColor $(if($finalScore -match "A"){"Green"}elseif($finalScore -eq "B"){"Yellow"}else{"Red"})
    
    return @{
        TotalTests = $totalTests
        PassedTests = $passedTests
        SuccessRate = $successRate
        Issues = $allIssues
        Grade = $finalScore
    }
}

# Exécution
$projectPath = Split-Path $PSScriptRoot -Parent
$result = Invoke-ProjectValidation -ProjectPath $projectPath

# Génération d'un rapport
$reportPath = Join-Path $projectPath "Reports\ValidationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
if (-not (Test-Path (Split-Path $reportPath))) {
    New-Item -Path (Split-Path $reportPath) -ItemType Directory -Force | Out-Null
}

$reportData = @{
    Timestamp = Get-Date
    ProjectPath = $projectPath
    ValidationResults = $result
}

$reportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "`n📄 Rapport détaillé sauvegardé: $reportPath" -ForegroundColor Cyan

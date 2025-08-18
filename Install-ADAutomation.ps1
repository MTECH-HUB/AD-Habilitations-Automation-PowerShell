<#
.SYNOPSIS
    Script d'installation et de configuration du système d'automatisation des habilitations AD

.DESCRIPTION
    Ce script configure automatiquement l'environnement, installe les modules requis
    et vérifie que tout fonctionne correctement.

.PARAMETER SkipModuleInstallation
    Ignore l'installation des modules PowerShell

.PARAMETER ConfigureScheduledTasks
    Configure les tâches planifiées pour les audits automatiques

.EXAMPLE
    .\Install-ADAutomation.ps1

.EXAMPLE
    .\Install-ADAutomation.ps1 -ConfigureScheduledTasks
#>

param(
    [switch]$SkipModuleInstallation,
    [switch]$ConfigureScheduledTasks,
    [switch]$Force
)

function Write-InstallLog {
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

function Test-AdminRights {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Install-RequiredModules {
    Write-InstallLog "Installation des modules PowerShell requis..." -Level "INFO"
    
    $modules = @(
        @{ Name = "ActiveDirectory"; Description = "Module Active Directory" },
        @{ Name = "ImportExcel"; Description = "Module pour l'export Excel (optionnel)" }
    )
    
    foreach ($module in $modules) {
        try {
            if (Get-Module -ListAvailable -Name $module.Name) {
                Write-InstallLog "Module $($module.Name) déjà installé" -Level "SUCCESS"
            } else {
                Write-InstallLog "Installation du module $($module.Name)..." -Level "INFO"
                
                if ($module.Name -eq "ActiveDirectory") {
                    # Le module AD fait partie des RSAT
                    Write-InstallLog "Le module ActiveDirectory nécessite les RSAT Windows" -Level "WARNING"
                    Write-InstallLog "Veuillez installer les RSAT manuellement si nécessaire" -Level "WARNING"
                } else {
                    Install-Module -Name $module.Name -Force -Scope CurrentUser
                    Write-InstallLog "Module $($module.Name) installé avec succès" -Level "SUCCESS"
                }
            }
        } catch {
            Write-InstallLog "Erreur lors de l'installation du module $($module.Name) : $_" -Level "ERROR"
        }
    }
}

function Initialize-DirectoryStructure {
    Write-InstallLog "Création de la structure des dossiers..." -Level "INFO"
    
    $baseDir = Split-Path $PSScriptRoot -Parent
    $directories = @(
        "Config",
        "Scripts", 
        "Logs",
        "Reports",
        "Templates",
        "Tests",
        "Backups",
        "Archives"
    )
    
    foreach ($dir in $directories) {
        $fullPath = Join-Path $baseDir $dir
        if (-not (Test-Path $fullPath)) {
            try {
                New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
                Write-InstallLog "Dossier créé : $dir" -Level "SUCCESS"
            } catch {
                Write-InstallLog "Erreur lors de la création du dossier $dir : $_" -Level "ERROR"
            }
        } else {
            Write-InstallLog "Dossier existant : $dir" -Level "INFO"
        }
    }
}

function Set-FilePermissions {
    Write-InstallLog "Configuration des permissions de fichiers..." -Level "INFO"
    
    try {
        $baseDir = Split-Path $PSScriptRoot -Parent
        $scriptsDir = Join-Path $baseDir "Scripts"
        
        # Configuration des permissions pour les scripts
        $scripts = Get-ChildItem -Path $scriptsDir -Filter "*.ps1"
        foreach ($script in $scripts) {
            # Débloquer les scripts téléchargés
            Unblock-File -Path $script.FullName -ErrorAction SilentlyContinue
        }
        
        Write-InstallLog "Permissions configurées" -Level "SUCCESS"
    } catch {
        Write-InstallLog "Erreur lors de la configuration des permissions : $_" -Level "ERROR"
    }
}

function Test-ADConnectivity {
    Write-InstallLog "Test de connectivité Active Directory..." -Level "INFO"
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        Write-InstallLog "Connecté au domaine : $($domain.Name)" -Level "SUCCESS"
        return $true
    } catch {
        Write-InstallLog "Erreur de connectivité AD : $_" -Level "ERROR"
        return $false
    }
}

function New-ScheduledTasks {
    if (-not $ConfigureScheduledTasks) {
        return
    }
    
    Write-InstallLog "Configuration des tâches planifiées..." -Level "INFO"
    
    try {
        $baseDir = Split-Path $PSScriptRoot -Parent
        $scriptPath = Join-Path $baseDir "Scripts\AD-RightsAudit.ps1"
        
        # Tâche quotidienne d'audit
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$scriptPath`" -AuditType InactiveUsers -Format HTML"
        $trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        
        Register-ScheduledTask -TaskName "AD-DailyAudit" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Audit quotidien des comptes inactifs AD" -Force
        
        Write-InstallLog "Tâche planifiée 'AD-DailyAudit' créée" -Level "SUCCESS"
        
        # Tâche hebdomadaire de rapport de conformité
        $weeklyAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$scriptPath`" -AuditType Compliance -Format HTML -SendEmail"
        $weeklyTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "06:00"
        
        Register-ScheduledTask -TaskName "AD-WeeklyCompliance" -Action $weeklyAction -Trigger $weeklyTrigger -Principal $principal -Settings $settings -Description "Rapport hebdomadaire de conformité AD" -Force
        
        Write-InstallLog "Tâche planifiée 'AD-WeeklyCompliance' créée" -Level "SUCCESS"
        
    } catch {
        Write-InstallLog "Erreur lors de la création des tâches planifiées : $_" -Level "ERROR"
    }
}

function Show-PostInstallInstructions {
    Write-InstallLog "Installation terminée !" -Level "SUCCESS"
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                        🎉 INSTALLATION TERMINÉE 🎉                              ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Prochaines étapes :" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   1️⃣  Adapter la configuration dans Config\settings.json" -ForegroundColor Yellow
    Write-Host "       • Modifier le nom de domaine" -ForegroundColor White
    Write-Host "       • Configurer les OUs par défaut" -ForegroundColor White
    Write-Host "       • Adapter les paramètres email" -ForegroundColor White
    Write-Host ""
    Write-Host "   2️⃣  Personnaliser les modèles dans Config\user-templates.json" -ForegroundColor Yellow
    Write-Host "       • Adapter les OUs aux besoins" -ForegroundColor White
    Write-Host "       • Configurer les groupes par défaut" -ForegroundColor White
    Write-Host ""
    Write-Host "   3️⃣  Lancer le système avec :" -ForegroundColor Yellow
    Write-Host "       .\Scripts\AD-MainMenu.ps1" -ForegroundColor Green
    Write-Host ""
    Write-Host "   4️⃣  Tester avec :" -ForegroundColor Yellow
    Write-Host "       .\Tests\Test-Installation.ps1" -ForegroundColor Green
    Write-Host ""
    
    if ($ConfigureScheduledTasks) {
        Write-Host "   ✅ Tâches planifiées configurées :" -ForegroundColor Green
        Write-Host "       • AD-DailyAudit : Audit quotidien à 02:00" -ForegroundColor White
        Write-Host "       • AD-WeeklyCompliance : Rapport hebdomadaire le lundi à 06:00" -ForegroundColor White
        Write-Host ""
    }
    
    Write-Host "📚 Documentation disponible dans le dossier docs\" -ForegroundColor Cyan
    Write-Host "🐛 Logs disponibles dans le dossier Logs\" -ForegroundColor Cyan
    Write-Host ""
}

# Fonction principale
function Main {
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    🛠️  INSTALLATION DU SYSTÈME AD  🛠️                           ║" -ForegroundColor Cyan
    Write-Host "║                                                                                  ║" -ForegroundColor Cyan
    Write-Host "║                    Automatisation des Habilitations Active Directory           ║" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Vérification des droits administrateur
    if (-not (Test-AdminRights)) {
        Write-InstallLog "Droits administrateur recommandés pour l'installation complète" -Level "WARNING"
    }
    
    Write-InstallLog "Début de l'installation..." -Level "INFO"
    
    # Étapes d'installation
    Initialize-DirectoryStructure
    
    if (-not $SkipModuleInstallation) {
        Install-RequiredModules
    }
    
    Set-FilePermissions
    
    # Test de connectivité
    $adConnected = Test-ADConnectivity
    if (-not $adConnected) {
        Write-InstallLog "Attention : Connectivité AD non disponible. Certaines fonctionnalités pourraient être limitées." -Level "WARNING"
    }
    
    # Configuration des tâches planifiées
    New-ScheduledTasks
    
    # Test final
    Write-InstallLog "Exécution des tests post-installation..." -Level "INFO"
    try {
        $testScript = Join-Path $PSScriptRoot "Tests\Test-Installation.ps1"
        if (Test-Path $testScript) {
            & $testScript
        }
    } catch {
        Write-InstallLog "Erreur lors des tests : $_" -Level "ERROR"
    }
    
    # Instructions finales
    Show-PostInstallInstructions
}

# Exécution
if ($MyInvocation.InvocationName -ne '.') {
    Main
}

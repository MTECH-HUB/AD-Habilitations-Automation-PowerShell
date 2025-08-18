<#
.SYNOPSIS
    Interface utilisateur principale pour l'automatisation des habilitations Active Directory

.DESCRIPTION
    Ce script fournit une interface en ligne de commande interactive pour accéder à toutes
    les fonctionnalités de gestion et d'audit des comptes Active Directory.

.NOTES
    Auteur: IT Security Team
    Version: 1.0
    Date: $(Get-Date -Format "dd/MM/yyyy")
#>

# Importation des modules requis
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot "..\Config\AD-Functions.psm1") -ErrorAction Stop

# Configuration globale
$script:ConfigPath = Join-Path $PSScriptRoot "..\Config\settings.json"
$script:Config = Get-Content $ConfigPath | ConvertFrom-Json

function Show-Header {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    🛡️  AUTOMATISATION DES HABILITATIONS AD  🛡️                     ║" -ForegroundColor Cyan
    Write-Host "║                                                                                  ║" -ForegroundColor Cyan
    Write-Host "║                        Système de Gestion des Comptes Utilisateurs              ║" -ForegroundColor White
    Write-Host "║                                   Version 1.0                                   ║" -ForegroundColor Gray
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Vérification de la connectivité AD
    $adStatus = Test-ADConnectivity
    if ($adStatus.Success) {
        Write-Host "✅ Connecté au domaine: $($adStatus.Domain) | Contrôleur: $($adStatus.DomainController)" -ForegroundColor Green
    } else {
        Write-Host "❌ Erreur de connexion AD: $($adStatus.Error)" -ForegroundColor Red
        Write-Host "Veuillez vérifier votre connectivité avant de continuer." -ForegroundColor Yellow
    }
    
    Write-Host "👤 Utilisateur: $env:USERNAME | 📅 $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
}

function Show-MainMenu {
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                                    🏠 MENU PRINCIPAL                                 " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  👥 GESTION DES UTILISATEURS" -ForegroundColor Green
    Write-Host "     1️⃣  Créer un nouvel utilisateur"
    Write-Host "     2️⃣  Modifier un utilisateur existant"
    Write-Host "     3️⃣  Supprimer un utilisateur"
    Write-Host "     4️⃣  Activer/Désactiver un compte"
    Write-Host "     5️⃣  Création en masse (CSV)"
    Write-Host ""
    Write-Host "  📊 AUDIT ET RAPPORTS" -ForegroundColor Blue
    Write-Host "     6️⃣  Audit complet des utilisateurs"
    Write-Host "     7️⃣  Audit des groupes et permissions"
    Write-Host "     8️⃣  Détection des comptes inactifs"
    Write-Host "     9️⃣  Rapport de conformité"
    Write-Host "     🔟 Audit des comptes privilégiés"
    Write-Host ""
    Write-Host "  ⚙️  CONFIGURATION ET OUTILS" -ForegroundColor Magenta
    Write-Host "     1️⃣1️⃣ Configuration du système"
    Write-Host "     1️⃣2️⃣ Gestion des modèles utilisateur"
    Write-Host "     1️⃣3️⃣ Consultation des logs"
    Write-Host "     1️⃣4️⃣ Test de connectivité AD"
    Write-Host ""
    Write-Host "     0️⃣  🚪 Quitter"
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Get-MenuChoice {
    param([string]$Prompt = "Votre choix")
    
    Write-Host ""
    $choice = Read-Host "👉 $Prompt (0-14)"
    return $choice.Trim()
}

function Show-UserCreationMenu {
    Clear-Host
    Show-Header
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "                               👤 CRÉATION D'UTILISATEUR                             " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    
    try {
        # Collecte des informations utilisateur
        $userData = @{}
        
        Write-Host "📝 Veuillez saisir les informations utilisateur :" -ForegroundColor Cyan
        Write-Host ""
        
        $userData.GivenName = Read-Host "   Prénom"
        $userData.Surname = Read-Host "   Nom de famille"
        $userData.SamAccountName = Read-Host "   Nom d'utilisateur (laisser vide pour génération automatique)"
        
        # Génération automatique du nom d'utilisateur si vide
        if ([string]::IsNullOrWhiteSpace($userData.SamAccountName)) {
            $userData.SamAccountName = New-UniqueUsername -FirstName $userData.GivenName -LastName $userData.Surname
            Write-Host "   → Nom d'utilisateur généré : $($userData.SamAccountName)" -ForegroundColor Yellow
        }
        
        $userData.UserPrincipalName = Read-Host "   UPN (ex: utilisateur@domaine.com)"
        $userData.EmailAddress = Read-Host "   Adresse email"
        $userData.Department = Read-Host "   Département"
        $userData.Title = Read-Host "   Poste/Titre"
        $userData.Company = Read-Host "   Entreprise"
        $userData.Manager = Read-Host "   Manager (nom d'utilisateur, optionnel)"
        $userData.Description = Read-Host "   Description (optionnel)"
        
        Write-Host ""
        Write-Host "📋 Modèles disponibles :" -ForegroundColor Cyan
        $templates = Get-Content (Join-Path $PSScriptRoot "..\Config\user-templates.json") | ConvertFrom-Json
        $templateNames = $templates.PSObject.Properties.Name | Where-Object { $_ -ne "Default" }
        
        for ($i = 0; $i -lt $templateNames.Count; $i++) {
            Write-Host "   $($i + 1). $($templateNames[$i]) - $($templates.($templateNames[$i]).Description)"
        }
        Write-Host "   0. Aucun modèle (configuration manuelle)"
        
        $templateChoice = Read-Host "`n   Choisir un modèle (0-$($templateNames.Count))"
        $selectedTemplate = $null
        
        if ($templateChoice -gt 0 -and $templateChoice -le $templateNames.Count) {
            $selectedTemplate = $templateNames[$templateChoice - 1]
            Write-Host "   → Modèle sélectionné : $selectedTemplate" -ForegroundColor Green
        }
        
        # Validation des données
        $validationErrors = Test-UserData -UserData $userData
        if ($validationErrors.Count -gt 0) {
            Write-Host "`n❌ Erreurs de validation :" -ForegroundColor Red
            foreach ($validationItem in $validationErrors) {
                Write-Host "   • $validationItem" -ForegroundColor Red
            }
            Read-Host "`nAppuyez sur Entrée pour continuer"
            return
        }
        
        # Confirmation
        Write-Host "`n📋 Résumé de la création :" -ForegroundColor Cyan
        Write-Host "   Nom complet : $($userData.GivenName) $($userData.Surname)"
        Write-Host "   Nom d'utilisateur : $($userData.SamAccountName)"
        Write-Host "   UPN : $($userData.UserPrincipalName)"
        Write-Host "   Email : $($userData.EmailAddress)"
        Write-Host "   Département : $($userData.Department)"
        Write-Host "   Modèle : $(if($selectedTemplate) { $selectedTemplate } else { 'Aucun' })"
        
        Write-Host ""
        $confirm = Read-Host "Confirmer la création ? (O/N)"
        
        if ($confirm -eq 'O' -or $confirm -eq 'o') {
            Write-Host "`n⏳ Création en cours..." -ForegroundColor Yellow
            
            # Appel du script de gestion des utilisateurs
            $scriptPath = Join-Path $PSScriptRoot "AD-UserManagement.ps1"
            $params = @{
                Action = "Create"
                UserData = $userData
            }
            
            if ($selectedTemplate) {
                $params.Template = $selectedTemplate
            }
            
            $result = & $scriptPath @params
            
            if ($result.Success) {
                Write-Host "`n✅ Utilisateur créé avec succès !" -ForegroundColor Green
                Write-Host "   Nom d'utilisateur : $($result.Username)" -ForegroundColor Green
                if ($result.Password) {
                    Write-Host "   Mot de passe temporaire : $($result.Password)" -ForegroundColor Yellow
                    Write-Host "   ⚠️  L'utilisateur devra changer le mot de passe à la première connexion" -ForegroundColor Yellow
                }
            } else {
                Write-Host "`n❌ Erreur lors de la création : $($result.Error)" -ForegroundColor Red
            }
        } else {
            Write-Host "`n❌ Création annulée" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "`n❌ Erreur : $_" -ForegroundColor Red
    }
    
    Read-Host "`nAppuyez sur Entrée pour continuer"
}

function Show-UserModificationMenu {
    Clear-Host
    Show-Header
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "                              ✏️  MODIFICATION D'UTILISATEUR                          " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host ""
    
    try {
        $username = Read-Host "👤 Nom d'utilisateur à modifier"
        
        # Vérification de l'existence
        try {
            $user = Get-ADUser -Identity $username -Properties * -ErrorAction Stop
            Write-Host "✅ Utilisateur trouvé : $($user.Name)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Utilisateur introuvable : $username" -ForegroundColor Red
            Read-Host "Appuyez sur Entrée pour continuer"
            return
        }
        
        # Affichage des informations actuelles
        Write-Host "`n📋 Informations actuelles :" -ForegroundColor Cyan
        Write-Host "   Nom complet : $($user.Name)"
        Write-Host "   Email : $($user.EmailAddress)"
        Write-Host "   Département : $($user.Department)"
        Write-Host "   Titre : $($user.Title)"
        Write-Host "   Manager : $($user.Manager)"
        Write-Host "   Statut : $(if($user.Enabled) { 'Activé' } else { 'Désactivé' })"
        
        Write-Host "`n📝 Nouvelles valeurs (laisser vide pour conserver) :" -ForegroundColor Cyan
        
        $updateData = @{}
        
        $newEmail = Read-Host "   Nouvelle adresse email"
        if (-not [string]::IsNullOrWhiteSpace($newEmail)) { $updateData.EmailAddress = $newEmail }
        
        $newDepartment = Read-Host "   Nouveau département"
        if (-not [string]::IsNullOrWhiteSpace($newDepartment)) { $updateData.Department = $newDepartment }
        
        $newTitle = Read-Host "   Nouveau titre"
        if (-not [string]::IsNullOrWhiteSpace($newTitle)) { $updateData.Title = $newTitle }
        
        $newManager = Read-Host "   Nouveau manager"
        if (-not [string]::IsNullOrWhiteSpace($newManager)) { $updateData.Manager = $newManager }
        
        $newDescription = Read-Host "   Nouvelle description"
        if (-not [string]::IsNullOrWhiteSpace($newDescription)) { $updateData.Description = $newDescription }
        
        if ($updateData.Count -eq 0) {
            Write-Host "`n⚠️  Aucune modification spécifiée" -ForegroundColor Yellow
            Read-Host "Appuyez sur Entrée pour continuer"
            return
        }
        
        # Confirmation
        Write-Host "`n📋 Modifications à appliquer :" -ForegroundColor Cyan
        foreach ($key in $updateData.Keys) {
            Write-Host "   $key : $($updateData[$key])"
        }
        
        $confirm = Read-Host "`nConfirmer les modifications ? (O/N)"
        
        if ($confirm -eq 'O' -or $confirm -eq 'o') {
            Write-Host "`n⏳ Modification en cours..." -ForegroundColor Yellow
            
            $scriptPath = Join-Path $PSScriptRoot "AD-UserManagement.ps1"
            $result = & $scriptPath -Action Update -Username $username -UserData $updateData
            
            if ($result.Success) {
                Write-Host "`n✅ Utilisateur modifié avec succès !" -ForegroundColor Green
            } else {
                Write-Host "`n❌ Erreur lors de la modification : $($result.Error)" -ForegroundColor Red
            }
        } else {
            Write-Host "`n❌ Modification annulée" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "`n❌ Erreur : $_" -ForegroundColor Red
    }
    
    Read-Host "`nAppuyez sur Entrée pour continuer"
}

function Show-AuditMenu {
    Clear-Host
    Show-Header
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "                                📊 MENU D'AUDIT                                      " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host ""
    Write-Host "  🔍 Types d'audit disponibles :" -ForegroundColor Cyan
    Write-Host "     1. Audit complet des utilisateurs"
    Write-Host "     2. Audit des groupes et permissions"
    Write-Host "     3. Détection des comptes inactifs"
    Write-Host "     4. Rapport de conformité complet"
    Write-Host "     5. Audit des comptes privilégiés"
    Write-Host "     0. Retour au menu principal"
    
    $choice = Get-MenuChoice -Prompt "Type d'audit"
    
    switch ($choice) {
        "1" { Invoke-AuditReport -AuditType "Users" }
        "2" { Invoke-AuditReport -AuditType "Groups" }
        "3" { Invoke-AuditReport -AuditType "InactiveUsers" }
        "4" { Invoke-AuditReport -AuditType "Compliance" }
        "5" { Invoke-AuditReport -AuditType "Permissions" }
        "0" { return }
        default { 
            Write-Host "❌ Choix invalide" -ForegroundColor Red
            Start-Sleep 2
        }
    }
}

function Invoke-AuditReport {
    param([string]$AuditType)
    
    Write-Host "`n⏳ Lancement de l'audit $AuditType..." -ForegroundColor Yellow
    Write-Host "📍 Format de sortie (HTML/CSV/JSON/Excel) :" -ForegroundColor Cyan
    $format = Read-Host "   Format (défaut: HTML)"
    if ([string]::IsNullOrWhiteSpace($format)) { $format = "HTML" }
    
    try {
        $scriptPath = Join-Path $PSScriptRoot "AD-RightsAudit.ps1"
        $result = & $scriptPath -AuditType $AuditType -Format $format
        
        if ($result.Success) {
            Write-Host "`n✅ Audit terminé avec succès !" -ForegroundColor Green
            Write-Host "📄 Rapport disponible : $($result.ReportPath)" -ForegroundColor Green
            
            $openReport = Read-Host "`nOuvrir le rapport ? (O/N)"
            if ($openReport -eq 'O' -or $openReport -eq 'o') {
                Start-Process $result.ReportPath
            }
        } else {
            Write-Host "`n❌ Erreur lors de l'audit : $($result.Error)" -ForegroundColor Red
        }
    } catch {
        Write-Host "`n❌ Erreur : $_" -ForegroundColor Red
    }
    
    Read-Host "`nAppuyez sur Entrée pour continuer"
}

function Show-ConfigurationMenu {
    Clear-Host
    Show-Header
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "                                ⚙️  CONFIGURATION                                     " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    
    Write-Host "📋 Configuration actuelle :" -ForegroundColor Cyan
    Write-Host "   Domaine : $($Config.General.DomainName)"
    Write-Host "   OU par défaut : $($Config.General.DefaultOU)"
    Write-Host "   Rétention des logs : $($Config.General.LogRetentionDays) jours"
    Write-Host "   Audit activé : $($Config.General.EnableAuditLogging)"
    Write-Host "   Notifications email : $($Config.General.EnableEmailNotifications)"
    Write-Host ""
    Write-Host "   Seuil d'inactivité : $($Config.Compliance.InactiveUserThreshold) jours"
    Write-Host "   Longueur mot de passe : $($Config.UserManagement.DefaultPasswordLength) caractères"
    Write-Host ""
    
    Write-Host "⚙️  Options de configuration :" -ForegroundColor Cyan
    Write-Host "     1. Modifier la configuration générale"
    Write-Host "     2. Gérer les modèles utilisateur"
    Write-Host "     3. Configurer les règles de conformité"
    Write-Host "     4. Paramètres d'email"
    Write-Host "     5. Recharger la configuration"
    Write-Host "     0. Retour"
    
    $choice = Get-MenuChoice -Prompt "Option de configuration"
    
    switch ($choice) {
        "1" { 
            Write-Host "`n⚠️  Edition de la configuration générale à implémenter" -ForegroundColor Yellow
            Write-Host "📝 Modifiez manuellement le fichier Config\settings.json" -ForegroundColor Cyan
            Read-Host "Appuyez sur Entrée pour continuer"
        }
        "2" { Show-TemplateManagement }
        "3" { 
            Write-Host "`n⚠️  Edition des règles de conformité à implémenter" -ForegroundColor Yellow
            Write-Host "📝 Modifiez manuellement le fichier Config\compliance-rules.json" -ForegroundColor Cyan
            Read-Host "Appuyez sur Entrée pour continuer"
        }
        "4" { 
            Write-Host "`n⚠️  Edition des paramètres email à implémenter" -ForegroundColor Yellow
            Write-Host "📝 Modifiez manuellement la section EmailSettings dans Config\settings.json" -ForegroundColor Cyan
            Read-Host "Appuyez sur Entrée pour continuer"
        }
        "5" { 
            $script:Config = Get-Content $ConfigPath | ConvertFrom-Json
            Write-Host "✅ Configuration rechargée" -ForegroundColor Green
            Start-Sleep 2
        }
        "0" { return }
        default { 
            Write-Host "❌ Choix invalide" -ForegroundColor Red
            Start-Sleep 2
        }
    }
}

function Show-TemplateManagement {
    Write-Host "`n📋 Gestion des modèles utilisateur :" -ForegroundColor Cyan
    
    $templatesPath = Join-Path $PSScriptRoot "..\Config\user-templates.json"
    $templates = Get-Content $templatesPath | ConvertFrom-Json
    
    Write-Host "`n📝 Modèles disponibles :" -ForegroundColor Green
    $templateNames = $templates.PSObject.Properties.Name
    for ($i = 0; $i -lt $templateNames.Count; $i++) {
        Write-Host "   $($i + 1). $($templateNames[$i]) - $($templates.($templateNames[$i]).Description)"
    }
    
    Read-Host "`nAppuyez sur Entrée pour continuer"
}

function Show-LogsMenu {
    Clear-Host
    Show-Header
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host "                               📜 CONSULTATION DES LOGS                              " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host ""
    
    $logsPath = Join-Path $PSScriptRoot "..\Logs"
    
    if (Test-Path $logsPath) {
        $logFiles = Get-ChildItem -Path $logsPath -Filter "*.log" | Sort-Object LastWriteTime -Descending
        
        if ($logFiles.Count -gt 0) {
            Write-Host "📂 Fichiers de logs disponibles :" -ForegroundColor Cyan
            for ($i = 0; $i -lt [Math]::Min($logFiles.Count, 10); $i++) {
                $file = $logFiles[$i]
                Write-Host "   $($i + 1). $($file.Name) - $(Get-Date $file.LastWriteTime -Format 'dd/MM/yyyy HH:mm')"
            }
            
            $choice = Read-Host "`nNuméro du fichier à consulter (1-$([Math]::Min($logFiles.Count, 10)), 0 pour annuler)"
            
            if ($choice -gt 0 -and $choice -le $logFiles.Count) {
                $selectedFile = $logFiles[$choice - 1]
                Write-Host "`n📄 Contenu de $($selectedFile.Name) :" -ForegroundColor Cyan
                Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
                
                $content = Get-Content $selectedFile.FullName -Tail 50
                foreach ($line in $content) {
                    if ($line -match "\[ERROR\]") {
                        Write-Host $line -ForegroundColor Red
                    } elseif ($line -match "\[WARNING\]") {
                        Write-Host $line -ForegroundColor Yellow
                    } elseif ($line -match "\[SUCCESS\]") {
                        Write-Host $line -ForegroundColor Green
                    } else {
                        Write-Host $line -ForegroundColor White
                    }
                }
            }
        } else {
            Write-Host "📂 Aucun fichier de log trouvé" -ForegroundColor Yellow
        }
    } else {
        Write-Host "📂 Dossier de logs inexistant" -ForegroundColor Yellow
    }
    
    Read-Host "`nAppuyez sur Entrée pour continuer"
}

function Test-ConnectivityMenu {
    Clear-Host
    Show-Header
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "                              🔍 TEST DE CONNECTIVITÉ                               " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "⏳ Test de connectivité en cours..." -ForegroundColor Yellow
    
    # Test AD
    $adTest = Test-ADConnectivity
    Write-Host "`n🏢 Active Directory :" -ForegroundColor Cyan
    if ($adTest.Success) {
        Write-Host "   ✅ Connecté au domaine : $($adTest.Domain)" -ForegroundColor Green
        Write-Host "   ✅ Contrôleur de domaine : $($adTest.DomainController)" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Erreur de connexion : $($adTest.Error)" -ForegroundColor Red
    }
    
    # Test modules PowerShell
    Write-Host "`n🔧 Modules PowerShell :" -ForegroundColor Cyan
    $modules = @("ActiveDirectory")
    foreach ($module in $modules) {
        if (Get-Module -ListAvailable -Name $module) {
            Write-Host "   ✅ Module $module disponible" -ForegroundColor Green
        } else {
            Write-Host "   ❌ Module $module manquant" -ForegroundColor Red
        }
    }
    
    # Test permissions
    Write-Host "`n🔐 Permissions utilisateur :" -ForegroundColor Cyan
    try {
        Get-ADUser -Filter "SamAccountName -eq '$env:USERNAME'" -ErrorAction Stop | Out-Null
        Write-Host "   ✅ Lecture des comptes utilisateur : OK" -ForegroundColor Green
        
        # Test création (simulation)
        Write-Host "   ℹ️  Test de création : Non testé (simulation requise)" -ForegroundColor Yellow
    } catch {
        Write-Host "   ❌ Erreur d'accès aux comptes : $_" -ForegroundColor Red
    }
    
    # Test chemins de fichiers
    Write-Host "`n📁 Structure des dossiers :" -ForegroundColor Cyan
    $paths = @(
        (Join-Path $PSScriptRoot "..\Config"),
        (Join-Path $PSScriptRoot "..\Logs"),
        (Join-Path $PSScriptRoot "..\Reports"),
        (Join-Path $PSScriptRoot "..\Templates")
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Write-Host "   ✅ $path" -ForegroundColor Green
        } else {
            Write-Host "   ❌ $path (manquant)" -ForegroundColor Red
        }
    }
    
    Read-Host "`nAppuyez sur Entrée pour continuer"
}

# Fonction principale
function Main {
    do {
        Show-Header
        Show-MainMenu
        $choice = Get-MenuChoice
        
        switch ($choice) {
            "1" { Show-UserCreationMenu }
            "2" { Show-UserModificationMenu }
            "3" { 
                # TODO: Implémenter la suppression d'utilisateur
                Write-Host "⚠️  Fonction de suppression à implémenter" -ForegroundColor Yellow
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            "4" { 
                # TODO: Implémenter l'activation/désactivation
                Write-Host "⚠️  Fonction d'activation/désactivation à implémenter" -ForegroundColor Yellow
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            "5" { 
                # TODO: Implémenter la création en masse
                Write-Host "⚠️  Fonction de création en masse à implémenter" -ForegroundColor Yellow
                Read-Host "Appuyez sur Entrée pour continuer"
            }
            "6" { Invoke-AuditReport -AuditType "Users" }
            "7" { Invoke-AuditReport -AuditType "Groups" }
            "8" { Invoke-AuditReport -AuditType "InactiveUsers" }
            "9" { Invoke-AuditReport -AuditType "Compliance" }
            "10" { Invoke-AuditReport -AuditType "Permissions" }
            "11" { Show-ConfigurationMenu }
            "12" { Show-TemplateManagement }
            "13" { Show-LogsMenu }
            "14" { Test-ConnectivityMenu }
            "0" { 
                Write-Host "`n👋 Au revoir !" -ForegroundColor Green
                break
            }
            default {
                Write-Host "`n❌ Choix invalide. Veuillez choisir un nombre entre 0 et 14." -ForegroundColor Red
                Start-Sleep 2
            }
        }
    } while ($true)
}

# Exécution du script principal
if ($MyInvocation.InvocationName -ne '.') {
    Main
}

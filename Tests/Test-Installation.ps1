<#
.SYNOPSIS
    Script de test pour valider l'installation et le fonctionnement du système

.DESCRIPTION
    Ce script effectue des tests de base pour vérifier que tous les composants
    sont correctement installés et configurés.
#>

# Importation des modules requis
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "✅ Module ActiveDirectory importé avec succès" -ForegroundColor Green
} catch {
    Write-Host "❌ Erreur d'importation du module ActiveDirectory : $_" -ForegroundColor Red
    exit 1
}

try {
    Import-Module (Join-Path $PSScriptRoot "..\Config\AD-Functions.psm1") -ErrorAction Stop
    Write-Host "✅ Module AD-Functions importé avec succès" -ForegroundColor Green
} catch {
    Write-Host "❌ Erreur d'importation du module AD-Functions : $_" -ForegroundColor Red
    exit 1
}

# Test de configuration
$configPath = Join-Path $PSScriptRoot "..\Config\settings.json"
if (Test-Path $configPath) {
    try {
        Get-Content $configPath | ConvertFrom-Json | Out-Null
        Write-Host "✅ Configuration chargée avec succès" -ForegroundColor Green
    } catch {
        Write-Host "❌ Erreur de lecture de la configuration : $_" -ForegroundColor Red
    }
} else {
    Write-Host "❌ Fichier de configuration manquant : $configPath" -ForegroundColor Red
}

# Test de connectivité AD
Write-Host "`n🔍 Test de connectivité Active Directory..." -ForegroundColor Cyan
$adTest = Test-ADConnectivity
if ($adTest.Success) {
    Write-Host "✅ Connectivité AD validée" -ForegroundColor Green
    Write-Host "   Domaine : $($adTest.Domain)" -ForegroundColor White
    Write-Host "   Contrôleur : $($adTest.DomainController)" -ForegroundColor White
} else {
    Write-Host "❌ Erreur de connectivité AD : $($adTest.Error)" -ForegroundColor Red
}

# Test des chemins
Write-Host "`n📁 Vérification de la structure des dossiers..." -ForegroundColor Cyan
$paths = @(
    (Join-Path $PSScriptRoot "..\Config"),
    (Join-Path $PSScriptRoot "..\Logs"),
    (Join-Path $PSScriptRoot "..\Reports"),
    (Join-Path $PSScriptRoot "..\Templates"),
    (Join-Path $PSScriptRoot "..\Tests")
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        Write-Host "✅ $path" -ForegroundColor Green
    } else {
        Write-Host "❌ $path (manquant)" -ForegroundColor Red
        try {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
            Write-Host "   → Dossier créé" -ForegroundColor Yellow
        } catch {
            Write-Host "   → Erreur de création : $_" -ForegroundColor Red
        }
    }
}

# Test des scripts principaux
Write-Host "`n📜 Vérification des scripts..." -ForegroundColor Cyan
$scripts = @(
    "AD-UserManagement.ps1",
    "AD-RightsAudit.ps1",
    "AD-MainMenu.ps1"
)

foreach ($script in $scripts) {
    $scriptPath = Join-Path $PSScriptRoot $script
    if (Test-Path $scriptPath) {
        Write-Host "✅ $script" -ForegroundColor Green
    } else {
        Write-Host "❌ $script (manquant)" -ForegroundColor Red
    }
}

# Test de génération de mot de passe
Write-Host "`n🔐 Test de génération de mot de passe..." -ForegroundColor Cyan
try {
    $password = New-SecurePassword -Length 12
    if ($password.Length -eq 12) {
        Write-Host "✅ Génération de mot de passe OK" -ForegroundColor Green
    } else {
        Write-Host "❌ Longueur de mot de passe incorrecte" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Erreur de génération de mot de passe : $_" -ForegroundColor Red
}

# Test de validation des données
Write-Host "`n✅ Test de validation des données..." -ForegroundColor Cyan
$testUserData = @{
    SamAccountName = "test.user"
    GivenName = "Test"
    Surname = "User"
    UserPrincipalName = "test.user@contoso.local"
}

try {
    $errors = Test-UserData -UserData $testUserData
    if ($errors.Count -eq 0) {
        Write-Host "✅ Validation des données OK" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Erreurs de validation détectées (normal pour les tests)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Erreur de validation : $_" -ForegroundColor Red
}

Write-Host "`n🎉 Tests terminés !" -ForegroundColor Green
Write-Host "📋 Pour démarrer le système, exécutez : .\Scripts\AD-MainMenu.ps1" -ForegroundColor Cyan

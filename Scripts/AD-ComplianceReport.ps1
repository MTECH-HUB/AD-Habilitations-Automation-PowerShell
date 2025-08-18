<#
.SYNOPSIS
    Générateur de rapports de conformité pour Active Directory

.DESCRIPTION
    Ce script génère des rapports de conformité détaillés selon différents standards
    (GDPR, SOX, ISO27001) avec des recommandations d'actions correctives.

.PARAMETER ComplianceStandard
    Standard de conformité : GDPR, SOX, ISO27001, All

.PARAMETER OutputFormat
    Format de sortie : HTML, PDF, Excel, JSON

.PARAMETER EmailReport
    Envoyer le rapport par email

.EXAMPLE
    .\AD-ComplianceReport.ps1 -ComplianceStandard GDPR -OutputFormat HTML

.NOTES
    Auteur: IT Security Team
    Version: 1.0
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("GDPR", "SOX", "ISO27001", "All")]
    [string]$ComplianceStandard = "All",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML", "PDF", "Excel", "JSON")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory=$false)]
    [switch]$EmailReport,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)

# Importation des modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot "..\Config\AD-Functions.psm1") -ErrorAction Stop

# Configuration
$script:ConfigPath = Join-Path $PSScriptRoot "..\Config\settings.json"
$script:ComplianceRulesPath = Join-Path $PSScriptRoot "..\Config\compliance-rules.json"
$script:Config = Get-Content $ConfigPath | ConvertFrom-Json
$script:ComplianceRules = Get-Content $ComplianceRulesPath | ConvertFrom-Json

function Get-ComplianceMetrics {
    param([string]$Standard)
    
    $metrics = @{}
    
    switch ($Standard) {
        "GDPR" {
            $metrics = @{
                Name = "RGPD (Règlement Général sur la Protection des Données)"
                Description = "Conformité RGPD pour la protection des données personnelles"
                Checks = @(
                    @{
                        Name = "Minimisation des données"
                        Query = "Utilisateurs avec données personnelles excessives"
                        Severity = "High"
                    },
                    @{
                        Name = "Retention des données"
                        Query = "Données conservées au-delà de la période légale"
                        Severity = "Critical"
                    },
                    @{
                        Name = "Chiffrement des données sensibles"
                        Query = "Données sensibles non chiffrées"
                        Severity = "High"
                    }
                )
                RequiredActions = @(
                    "Chiffrer tous les logs contenant des données personnelles",
                    "Implémenter une politique de rétention automatique",
                    "Documenter les bases légales de traitement"
                )
            }
        }
        
        "SOX" {
            $metrics = @{
                Name = "Sarbanes-Oxley Act"
                Description = "Conformité SOX pour les contrôles financiers"
                Checks = @(
                    @{
                        Name = "Séparation des tâches"
                        Query = "Utilisateurs avec conflits de privilèges"
                        Severity = "Critical"
                    },
                    @{
                        Name = "Traçabilité des accès"
                        Query = "Accès sans audit trail"
                        Severity = "High"
                    },
                    @{
                        Name = "Révision périodique des accès"
                        Query = "Accès non révisés"
                        Severity = "Medium"
                    }
                )
                RequiredActions = @(
                    "Mettre en place une matrice de séparation des tâches",
                    "Auditer tous les accès aux systèmes financiers",
                    "Documenter tous les changements d'accès"
                )
            }
        }
        
        "ISO27001" {
            $metrics = @{
                Name = "ISO 27001 - Gestion de la Sécurité de l'Information"
                Description = "Conformité ISO27001 pour la sécurité informatique"
                Checks = @(
                    @{
                        Name = "Gestion des accès"
                        Query = "Contrôles d'accès insuffisants"
                        Severity = "High"
                    },
                    @{
                        Name = "Classification de l'information"
                        Query = "Informations non classifiées"
                        Severity = "Medium"
                    },
                    @{
                        Name = "Gestion des incidents"
                        Query = "Incidents de sécurité non documentés"
                        Severity = "High"
                    }
                )
                RequiredActions = @(
                    "Classifier toutes les informations sensibles",
                    "Implémenter un processus de gestion des incidents",
                    "Effectuer des révisions de sécurité régulières"
                )
            }
        }
    }
    
    return $metrics
}

function Invoke-GDPRCompliance {
    $results = @()
    
    # Vérification de la minimisation des données
    $users = Get-ADUser -Filter * -Properties *
    foreach ($user in $users) {
        $violations = @()
        
        # Données personnelles non nécessaires
        $personalFields = @("HomePhone", "MobilePhone", "StreetAddress", "PersonalTitle")
        foreach ($field in $personalFields) {
            if ($user.$field -and [string]::IsNullOrWhiteSpace($user.Department)) {
                $violations += "Données personnelles sans justification métier : $field"
            }
        }
        
        # Vérification de la rétention
        if ($user.Created -lt (Get-Date).AddDays(-$ComplianceRules.RegulatoryCompliance.GDPR.DataRetention.UserLogs)) {
            if (-not $user.LastLogonDate -or $user.LastLogonDate -lt (Get-Date).AddDays(-90)) {
                $violations += "Données conservées au-delà de la période nécessaire"
            }
        }
        
        if ($violations.Count -gt 0) {
            $results += @{
                Type = "GDPR"
                Username = $user.SamAccountName
                Name = $user.Name
                Violations = $violations
                RiskLevel = "High"
                Recommendation = "Réviser et nettoyer les données personnelles"
            }
        }
    }
    
    return $results
}

function Invoke-SOXCompliance {
    $results = @()
    
    # Vérification de la séparation des tâches
    $sensitiveGroups = $ComplianceRules.ComplianceRules.Groups.SensitiveGroups
    $users = Get-ADUser -Filter * -Properties MemberOf
    
    foreach ($user in $users) {
        if ($user.MemberOf) {
            $userGroups = @()
            foreach ($groupDN in $user.MemberOf) {
                $group = Get-ADGroup $groupDN
                if ($group.Name -in $sensitiveGroups) {
                    $userGroups += $group.Name
                }
            }
            
            # Détection de conflits (exemple : admin ET utilisateur financier)
            $conflicts = @()
            if ($userGroups -contains "Domain Admins" -and $userGroups -contains "Finance Users") {
                $conflicts += "Conflit Admin/Finance"
            }
            
            if ($conflicts.Count -gt 0) {
                $results += @{
                    Type = "SOX"
                    Username = $user.SamAccountName
                    Name = $user.Name
                    Violations = $conflicts
                    RiskLevel = "Critical"
                    Recommendation = "Résoudre les conflits de séparation des tâches"
                }
            }
        }
    }
    
    return $results
}

function Invoke-ISO27001Compliance {
    $results = @()
    
    # Vérification de la gestion des accès
    $users = Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, MemberOf
    
    foreach ($user in $users) {
        $violations = @()
        
        # Accès sans connexion récente
        if (-not $user.LastLogonDate -or $user.LastLogonDate -lt (Get-Date).AddDays(-90)) {
            $violations += "Aucune connexion récente"
        }
        
        # Mot de passe ancien
        if ($user.PasswordLastSet -and $user.PasswordLastSet -lt (Get-Date).AddDays(-90)) {
            $violations += "Mot de passe trop ancien"
        }
        
        # Utilisateur sans manager (problème de gouvernance)
        if (-not $user.Manager) {
            $violations += "Pas de responsable assigné"
        }
        
        if ($violations.Count -gt 0) {
            $results += @{
                Type = "ISO27001"
                Username = $user.SamAccountName
                Name = $user.Name
                Violations = $violations
                RiskLevel = "Medium"
                Recommendation = "Réviser la gestion des accès"
            }
        }
    }
    
    return $results
}

function New-ComplianceScore {
    param([object[]]$Results)
    
    $totalUsers = (Get-ADUser -Filter *).Count
    $nonCompliantUsers = ($Results | Group-Object Username).Count
    
    $complianceRate = if ($totalUsers -gt 0) { 
        [math]::Round((($totalUsers - $nonCompliantUsers) / $totalUsers) * 100, 2) 
    } else { 100 }
    
    # Calcul du score par criticité
    $criticalIssues = ($Results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highIssues = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumIssues = ($Results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    
    # Score pondéré
    $weightedScore = 100 - ($criticalIssues * 10) - ($highIssues * 5) - ($mediumIssues * 2)
    $weightedScore = [math]::Max(0, $weightedScore)
    
    return @{
        ComplianceRate = $complianceRate
        WeightedScore = $weightedScore
        TotalUsers = $totalUsers
        NonCompliantUsers = $nonCompliantUsers
        CriticalIssues = $criticalIssues
        HighIssues = $highIssues
        MediumIssues = $mediumIssues
        TotalIssues = $Results.Count
    }
}

function Export-ComplianceReport {
    param(
        [object]$Data,
        [string]$Standard,
        [string]$Format,
        [string]$OutputPath
    )
    
    if (-not $OutputPath) {
        $OutputPath = Join-Path $PSScriptRoot "..\Reports"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "ComplianceReport_$Standard`_$timestamp"
    
    switch ($Format) {
        "HTML" {
            $filePath = Join-Path $OutputPath "$filename.html"
            Export-ComplianceHTML -Data $Data -Standard $Standard -FilePath $filePath
        }
        
        "JSON" {
            $filePath = Join-Path $OutputPath "$filename.json"
            $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        }
        
        "Excel" {
            if (Get-Module -ListAvailable -Name ImportExcel) {
                $filePath = Join-Path $OutputPath "$filename.xlsx"
                $Data.Results | Export-Excel -Path $filePath -WorksheetName "Violations" -AutoSize -BoldTopRow
                $Data.Score | Export-Excel -Path $filePath -WorksheetName "Score" -AutoSize -BoldTopRow
            } else {
                # Fallback vers CSV
                $filePath = Join-Path $OutputPath "$filename.csv"
                $Data.Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
            }
        }
        
        default {
            $filePath = Join-Path $OutputPath "$filename.json"
            $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        }
    }
    
    return $filePath
}

function Export-ComplianceHTML {
    param(
        [object]$Data,
        [string]$Standard,
        [string]$FilePath
    )
    
    $scoreColor = if ($Data.Score.WeightedScore -ge 90) { "success" } 
                  elseif ($Data.Score.WeightedScore -ge 70) { "warning" } 
                  else { "danger" }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Rapport de Conformité $Standard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 15px; margin-bottom: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header .subtitle { opacity: 0.9; margin-top: 10px; }
        .score-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .score-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
        .score-card h3 { margin: 0 0 15px 0; color: #2c3e50; }
        .score-number { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
        .score-success { color: #28a745; }
        .score-warning { color: #ffc107; }
        .score-danger { color: #dc3545; }
        .violations-section { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .violations-section h2 { color: #2c3e50; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background: #343a40; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #dee2e6; }
        tr:nth-child(even) { background: #f8f9fa; }
        .risk-critical { background-color: #f8d7da; }
        .risk-high { background-color: #fff3cd; }
        .risk-medium { background-color: #d1ecf1; }
        .recommendations { background: #e7f3ff; padding: 20px; border-radius: 10px; border-left: 5px solid #007bff; margin: 20px 0; }
        .footer { text-align: center; color: #6c757d; margin-top: 30px; padding: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Rapport de Conformité $Standard</h1>
            <div class="subtitle">Généré le $(Get-Date -Format 'dd/MM/yyyy à HH:mm:ss')</div>
            <div class="subtitle">Domaine : $($Config.General.DomainName)</div>
        </div>
        
        <div class="score-container">
            <div class="score-card">
                <h3>Score Global</h3>
                <div class="score-number score-$scoreColor">$($Data.Score.WeightedScore)%</div>
            </div>
            <div class="score-card">
                <h3>Taux de Conformité</h3>
                <div class="score-number score-$(if($Data.Score.ComplianceRate -ge 90){"success"}elseif($Data.Score.ComplianceRate -ge 70){"warning"}else{"danger"})">$($Data.Score.ComplianceRate)%</div>
            </div>
            <div class="score-card">
                <h3>Utilisateurs Auditées</h3>
                <div class="score-number">$($Data.Score.TotalUsers)</div>
            </div>
            <div class="score-card">
                <h3>Non Conformes</h3>
                <div class="score-number score-$(if($Data.Score.NonCompliantUsers -eq 0){"success"}else{"danger"})">$($Data.Score.NonCompliantUsers)</div>
            </div>
        </div>
        
        <div class="score-container">
            <div class="score-card">
                <h3>⚠️ Critique</h3>
                <div class="score-number score-danger">$($Data.Score.CriticalIssues)</div>
            </div>
            <div class="score-card">
                <h3>🔶 Élevé</h3>
                <div class="score-number score-warning">$($Data.Score.HighIssues)</div>
            </div>
            <div class="score-card">
                <h3>🔸 Moyen</h3>
                <div class="score-number score-warning">$($Data.Score.MediumIssues)</div>
            </div>
            <div class="score-card">
                <h3>📊 Total</h3>
                <div class="score-number">$($Data.Score.TotalIssues)</div>
            </div>
        </div>
        
        <div class="recommendations">
            <h3>📋 Recommandations Prioritaires</h3>
            $(if ($Data.Score.CriticalIssues -gt 0) { "<p><strong>🚨 URGENT :</strong> $($Data.Score.CriticalIssues) problèmes critiques nécessitent une action immédiate</p>" })
            <ul>
                <li>Résoudre tous les problèmes critiques dans les 24h</li>
                <li>Planifier la correction des problèmes de niveau élevé sous 7 jours</li>
                <li>Mettre en place un processus de surveillance continue</li>
                <li>Former les équipes sur les exigences de conformité $Standard</li>
            </ul>
        </div>
        
        <div class="violations-section">
            <h2>📋 Détail des Violations</h2>
            $($Data.Results | ConvertTo-Html -Fragment -Property Username,Name,Type,Violations,RiskLevel,Recommendation)
        </div>
        
        <div class="footer">
            <p>Rapport généré par le système d'automatisation des habilitations Active Directory</p>
            <p>Conformité $Standard - Version 1.0</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $FilePath -Encoding UTF8
}

# Fonction principale
function Main {
    Write-Host "🛡️ Génération du rapport de conformité $ComplianceStandard..." -ForegroundColor Cyan
    
    try {
        $allResults = @()
        
        if ($ComplianceStandard -eq "All" -or $ComplianceStandard -eq "GDPR") {
            Write-Host "📋 Vérification GDPR..." -ForegroundColor Yellow
            $gdprResults = Invoke-GDPRCompliance
            $allResults += $gdprResults
        }
        
        if ($ComplianceStandard -eq "All" -or $ComplianceStandard -eq "SOX") {
            Write-Host "📋 Vérification SOX..." -ForegroundColor Yellow
            $soxResults = Invoke-SOXCompliance
            $allResults += $soxResults
        }
        
        if ($ComplianceStandard -eq "All" -or $ComplianceStandard -eq "ISO27001") {
            Write-Host "📋 Vérification ISO27001..." -ForegroundColor Yellow
            $isoResults = Invoke-ISO27001Compliance
            $allResults += $isoResults
        }
        
        # Calcul du score
        $score = New-ComplianceScore -Results $allResults
        
        # Préparation des données de rapport
        $reportData = @{
            Standard = $ComplianceStandard
            GeneratedDate = Get-Date
            Results = $allResults
            Score = $score
            Metrics = Get-ComplianceMetrics -Standard $ComplianceStandard
        }
        
        # Export du rapport
        $reportPath = Export-ComplianceReport -Data $reportData -Standard $ComplianceStandard -Format $OutputFormat -OutputPath $OutputPath
        
        Write-Host "✅ Rapport généré avec succès !" -ForegroundColor Green
        Write-Host "📄 Fichier : $reportPath" -ForegroundColor Green
        Write-Host "📊 Score de conformité : $($score.WeightedScore)%" -ForegroundColor $(if($score.WeightedScore -ge 90){"Green"}elseif($score.WeightedScore -ge 70){"Yellow"}else{"Red"})
        
        if ($EmailReport) {
            # TODO: Implémenter l'envoi par email
            Write-Host "📧 Envoi par email à implémenter" -ForegroundColor Yellow
        }
        
        return @{
            Success = $true
            ReportPath = $reportPath
            Score = $score
            ResultsCount = $allResults.Count
        }
        
    } catch {
        Write-Host "❌ Erreur lors de la génération du rapport : $_" -ForegroundColor Red
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# Exécution
if ($MyInvocation.InvocationName -ne '.') {
    Main
}

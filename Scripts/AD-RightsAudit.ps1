<#
.SYNOPSIS
    Script PowerShell pour l'audit des droits et permissions Active Directory

.DESCRIPTION
    Ce script effectue un audit complet des droits et permissions dans Active Directory,
    identifie les anomalies et génère des rapports de conformité.

.PARAMETER AuditType
    Type d'audit à effectuer : Full, Users, Groups, Permissions, Compliance

.PARAMETER OutputPath
    Chemin de sortie pour les rapports

.PARAMETER Format
    Format de sortie : HTML, CSV, JSON, Excel

.PARAMETER SearchBase
    Base de recherche pour limiter l'audit à une OU spécifique

.PARAMETER IncludeInactive
    Inclure les comptes désactivés dans l'audit

.EXAMPLE
    .\AD-RightsAudit.ps1 -AuditType Full -Format HTML

.EXAMPLE
    .\AD-RightsAudit.ps1 -AuditType Compliance -OutputPath "C:\Reports" -Format Excel

.NOTES
    Auteur: IT Security Team
    Version: 1.0
    Date: $(Get-Date -Format "dd/MM/yyyy")
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Full", "Users", "Groups", "Permissions", "Compliance", "InactiveUsers", "SensitiveAccounts")]
    [string]$AuditType,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML", "CSV", "JSON", "Excel")]
    [string]$Format = "HTML",
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeInactive,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [int]$InactiveDays = 90
)

# Importation des modules requis
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot "..\Config\AD-Functions.psm1") -ErrorAction Stop

# Configuration globale
$script:ConfigPath = Join-Path $PSScriptRoot "..\Config\settings.json"
$script:ComplianceRulesPath = Join-Path $PSScriptRoot "..\Config\compliance-rules.json"
$script:LogPath = Join-Path $PSScriptRoot "..\Logs"
$script:Config = Get-Content $ConfigPath | ConvertFrom-Json
$script:ComplianceRules = Get-Content $ComplianceRulesPath | ConvertFrom-Json

# Initialisation
function Initialize-AuditLogging {
    $logFile = Join-Path $LogPath "AD-RightsAudit_$(Get-Date -Format 'yyyyMMdd').log"
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    return $logFile
}

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        [string]$LogFile
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor White }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
    }
    
    Add-Content -Path $LogFile -Value $logEntry
}

# Fonctions d'audit spécialisées
function Invoke-UserAudit {
    param(
        [string]$SearchBase,
        [bool]$IncludeInactive,
        [string]$LogFile
    )
    
    Write-AuditLog "Début de l'audit des utilisateurs" -Level "INFO" -LogFile $LogFile
    
    try {
        $filterParams = @{
            Filter = if ($IncludeInactive) { "*" } else { "Enabled -eq 'True'" }
            Properties = @(
                "SamAccountName", "Name", "UserPrincipalName", "EmailAddress", 
                "Department", "Title", "Manager", "Created", "LastLogonDate", 
                "PasswordLastSet", "PasswordNeverExpires", "PasswordExpired",
                "AccountExpirationDate", "LockedOut", "MemberOf", "Description"
            )
        }
        
        if ($SearchBase) {
            $filterParams.SearchBase = $SearchBase
        }
        
        $users = Get-ADUser @filterParams
        Write-AuditLog "Trouvé $($users.Count) utilisateurs à auditer" -Level "INFO" -LogFile $LogFile
        
        $auditResults = @()
        $violationCount = 0
        
        foreach ($user in $users) {
            $violations = @()
            $riskLevel = "Low"
            
            # Vérification des attributs obligatoires
            foreach ($required in $ComplianceRules.ComplianceRules.UserAccounts.RequiredAttributes) {
                if ([string]::IsNullOrWhiteSpace($user.$required)) {
                    $violations += "Attribut manquant: $required"
                }
            }
            
            # Vérification de l'âge du mot de passe
            if ($user.PasswordLastSet) {
                $passwordAge = (Get-Date) - $user.PasswordLastSet
                if ($passwordAge.Days -gt $ComplianceRules.ComplianceRules.UserAccounts.MaxPasswordAge) {
                    $violations += "Mot de passe trop ancien ($($passwordAge.Days) jours)"
                    $riskLevel = "Medium"
                }
            }
            
            # Vérification de l'inactivité
            if ($user.LastLogonDate) {
                $inactiveDays = (Get-Date) - $user.LastLogonDate
                if ($inactiveDays.Days -gt $ComplianceRules.ComplianceRules.UserAccounts.MaxInactiveDays) {
                    $violations += "Compte inactif ($($inactiveDays.Days) jours)"
                    $riskLevel = "High"
                }
            } else {
                $violations += "Aucune connexion enregistrée"
                $riskLevel = "Medium"
            }
            
            # Vérification de l'expiration du compte
            if ($user.AccountExpirationDate -and $user.AccountExpirationDate -lt (Get-Date)) {
                $violations += "Compte expiré"
                $riskLevel = "High"
            }
            
            # Analyse des groupes sensibles
            $sensitiveGroups = @()
            if ($user.MemberOf) {
                foreach ($groupDN in $user.MemberOf) {
                    $group = Get-ADGroup $groupDN
                    if ($group.Name -in $ComplianceRules.ComplianceRules.Groups.SensitiveGroups) {
                        $sensitiveGroups += $group.Name
                        $riskLevel = "High"
                    }
                }
            }
            
            if ($violations.Count -gt 0) {
                $violationCount++
            }
            
            $auditResults += @{
                Username = $user.SamAccountName
                Name = $user.Name
                Email = $user.EmailAddress
                Department = $user.Department
                Title = $user.Title
                Manager = $user.Manager
                Created = $user.Created
                LastLogon = $user.LastLogonDate
                PasswordAge = if ($user.PasswordLastSet) { ((Get-Date) - $user.PasswordLastSet).Days } else { "N/A" }
                AccountExpiry = $user.AccountExpirationDate
                Enabled = $user.Enabled
                Locked = $user.LockedOut
                SensitiveGroups = $sensitiveGroups -join "; "
                GroupCount = if ($user.MemberOf) { $user.MemberOf.Count } else { 0 }
                Violations = $violations -join "; "
                ViolationCount = $violations.Count
                RiskLevel = $riskLevel
                CompliantStatus = if ($violations.Count -eq 0) { "Conforme" } else { "Non conforme" }
            }
        }
        
        Write-AuditLog "Audit des utilisateurs terminé. $violationCount violations détectées" -Level "SUCCESS" -LogFile $LogFile
        return $auditResults
        
    } catch {
        Write-AuditLog "Erreur lors de l'audit des utilisateurs : $_" -Level "ERROR" -LogFile $LogFile
        throw
    }
}

function Invoke-GroupAudit {
    param(
        [string]$SearchBase,
        [string]$LogFile
    )
    
    Write-AuditLog "Début de l'audit des groupes" -Level "INFO" -LogFile $LogFile
    
    try {
        $filterParams = @{
            Filter = "*"
            Properties = @("Name", "Description", "GroupScope", "GroupCategory", "Members", "MemberOf", "Created", "Modified")
        }
        
        if ($SearchBase) {
            $filterParams.SearchBase = $SearchBase
        }
        
        $groups = Get-ADGroup @filterParams
        Write-AuditLog "Trouvé $($groups.Count) groupes à auditer" -Level "INFO" -LogFile $LogFile
        
        $auditResults = @()
        $violationCount = 0
        
        foreach ($group in $groups) {
            $violations = @()
            $riskLevel = "Low"
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction SilentlyContinue
            
            # Vérification des groupes sensibles
            $isSensitive = $group.Name -in $ComplianceRules.ComplianceRules.Groups.SensitiveGroups
            if ($isSensitive) {
                $riskLevel = "High"
                
                # Vérification du nombre max de membres
                if ($members.Count -gt $ComplianceRules.ComplianceRules.Groups.MaxMembersInSensitiveGroups) {
                    $violations += "Trop de membres dans le groupe sensible ($($members.Count))"
                }
            }
            
            # Groupes orphelins (sans membres)
            if ($members.Count -eq 0 -and -not $isSensitive) {
                $violations += "Groupe sans membres"
                $riskLevel = "Medium"
            }
            
            # Groupes sans description
            if ([string]::IsNullOrWhiteSpace($group.Description)) {
                $violations += "Description manquante"
            }
            
            # Analyse des membres
            $activeMembers = 0
            $inactiveMembers = 0
            $disabledMembers = 0
            
            foreach ($member in $members) {
                if ($member.ObjectClass -eq "user") {
                    $user = Get-ADUser $member.DistinguishedName -Properties Enabled, LastLogonDate -ErrorAction SilentlyContinue
                    if ($user) {
                        if (-not $user.Enabled) {
                            $disabledMembers++
                        } elseif ($user.LastLogonDate -and ((Get-Date) - $user.LastLogonDate).Days -gt 90) {
                            $inactiveMembers++
                        } else {
                            $activeMembers++
                        }
                    }
                }
            }
            
            if ($disabledMembers -gt 0) {
                $violations += "$disabledMembers membres désactivés"
                $riskLevel = "Medium"
            }
            
            if ($violations.Count -gt 0) {
                $violationCount++
            }
            
            $auditResults += @{
                GroupName = $group.Name
                Description = $group.Description
                GroupScope = $group.GroupScope
                GroupCategory = $group.GroupCategory
                TotalMembers = $members.Count
                ActiveMembers = $activeMembers
                InactiveMembers = $inactiveMembers
                DisabledMembers = $disabledMembers
                Created = $group.Created
                Modified = $group.Modified
                IsSensitive = $isSensitive
                Violations = $violations -join "; "
                ViolationCount = $violations.Count
                RiskLevel = $riskLevel
                CompliantStatus = if ($violations.Count -eq 0) { "Conforme" } else { "Non conforme" }
            }
        }
        
        Write-AuditLog "Audit des groupes terminé. $violationCount violations détectées" -Level "SUCCESS" -LogFile $LogFile
        return $auditResults
        
    } catch {
        Write-AuditLog "Erreur lors de l'audit des groupes : $_" -Level "ERROR" -LogFile $LogFile
        throw
    }
}

function Invoke-PermissionsAudit {
    param(
        [string]$LogFile
    )
    
    Write-AuditLog "Début de l'audit des permissions" -Level "INFO" -LogFile $LogFile
    
    try {
        $auditResults = @()
        $sensitiveGroups = $ComplianceRules.ComplianceRules.Groups.SensitiveGroups
        
        foreach ($groupName in $sensitiveGroups) {
            try {
                $members = Get-ADGroupMember -Identity $groupName -Recursive
                
                foreach ($member in $members) {
                    if ($member.ObjectClass -eq "user") {
                        $user = Get-ADUser $member.DistinguishedName -Properties Department, Title, Manager, LastLogonDate, Enabled
                        
                        $violations = @()
                        $riskLevel = "High"  # Par défaut élevé pour les groupes sensibles
                        
                        # Vérifications spécifiques aux comptes privilégiés
                        if (-not $user.Enabled) {
                            $violations += "Compte désactivé avec privilèges"
                        }
                        
                        if (-not $user.Manager) {
                            $violations += "Pas de manager assigné"
                        }
                        
                        if ($user.LastLogonDate -and ((Get-Date) - $user.LastLogonDate).Days -gt 30) {
                            $violations += "Aucune connexion récente avec privilèges"
                        }
                        
                        $auditResults += @{
                            Username = $user.SamAccountName
                            Name = $user.Name
                            PrivilegedGroup = $groupName
                            Department = $user.Department
                            Title = $user.Title
                            Manager = $user.Manager
                            LastLogon = $user.LastLogonDate
                            Enabled = $user.Enabled
                            Violations = $violations -join "; "
                            ViolationCount = $violations.Count
                            RiskLevel = $riskLevel
                            RequiresReview = $violations.Count -gt 0
                        }
                    }
                }
            } catch {
                Write-AuditLog "Erreur lors de l'audit du groupe $groupName : $_" -Level "WARNING" -LogFile $LogFile
            }
        }
        
        Write-AuditLog "Audit des permissions terminé" -Level "SUCCESS" -LogFile $LogFile
        return $auditResults
        
    } catch {
        Write-AuditLog "Erreur lors de l'audit des permissions : $_" -Level "ERROR" -LogFile $LogFile
        throw
    }
}

function Invoke-InactiveUsersAudit {
    param(
        [int]$InactiveDays,
        [string]$SearchBase,
        [string]$LogFile
    )
    
    Write-AuditLog "Début de l'audit des comptes inactifs ($InactiveDays jours)" -Level "INFO" -LogFile $LogFile
    
    try {
        $cutoffDate = (Get-Date).AddDays(-$InactiveDays)
        
        $filterParams = @{
            Filter = "LastLogonDate -lt '$cutoffDate' -and Enabled -eq 'True'"
            Properties = @("LastLogonDate", "Created", "MemberOf", "Department", "Title", "Manager")
        }
        
        if ($SearchBase) {
            $filterParams.SearchBase = $SearchBase
        }
        
        $inactiveUsers = Get-ADUser @filterParams
        Write-AuditLog "Trouvé $($inactiveUsers.Count) comptes inactifs" -Level "INFO" -LogFile $LogFile
        
        $auditResults = @()
        
        foreach ($user in $inactiveUsers) {
            $daysSinceLastLogon = if ($user.LastLogonDate) { 
                ((Get-Date) - $user.LastLogonDate).Days 
            } else { 
                "Jamais connecté" 
            }
            
            $hasSensitiveAccess = $false
            $groups = @()
            
            if ($user.MemberOf) {
                foreach ($groupDN in $user.MemberOf) {
                    $group = Get-ADGroup $groupDN
                    $groups += $group.Name
                    if ($group.Name -in $ComplianceRules.ComplianceRules.Groups.SensitiveGroups) {
                        $hasSensitiveAccess = $true
                    }
                }
            }
            
            $riskLevel = if ($hasSensitiveAccess) { "Critical" } else { "Medium" }
            
            $auditResults += @{
                Username = $user.SamAccountName
                Name = $user.Name
                Department = $user.Department
                Title = $user.Title
                Manager = $user.Manager
                Created = $user.Created
                LastLogon = $user.LastLogonDate
                DaysInactive = $daysSinceLastLogon
                Groups = $groups -join "; "
                HasSensitiveAccess = $hasSensitiveAccess
                RiskLevel = $riskLevel
                RecommendedAction = if ($hasSensitiveAccess) { "Désactiver immédiatement" } else { "Désactiver après notification" }
            }
        }
        
        Write-AuditLog "Audit des comptes inactifs terminé" -Level "SUCCESS" -LogFile $LogFile
        return $auditResults
        
    } catch {
        Write-AuditLog "Erreur lors de l'audit des comptes inactifs : $_" -Level "ERROR" -LogFile $LogFile
        throw
    }
}

function New-ComplianceReport {
    param(
        [object[]]$UserAudit,
        [object[]]$GroupAudit,
        [object[]]$PermissionsAudit,
        [object[]]$InactiveAudit,
        [string]$LogFile
    )
    
    Write-AuditLog "Génération du rapport de conformité" -Level "INFO" -LogFile $LogFile
    
    try {
        $summary = @{
            TotalUsers = $UserAudit.Count
            NonCompliantUsers = ($UserAudit | Where-Object { $_.ViolationCount -gt 0 }).Count
            TotalGroups = $GroupAudit.Count
            NonCompliantGroups = ($GroupAudit | Where-Object { $_.ViolationCount -gt 0 }).Count
            PrivilegedUsers = $PermissionsAudit.Count
            PrivilegedUsersWithIssues = ($PermissionsAudit | Where-Object { $_.RequiresReview }).Count
            InactiveUsers = $InactiveAudit.Count
            CriticalRiskUsers = ($InactiveAudit | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            
            # Calculs de conformité
            UserComplianceRate = if ($UserAudit.Count -gt 0) { 
                [math]::Round((($UserAudit.Count - ($UserAudit | Where-Object { $_.ViolationCount -gt 0 }).Count) / $UserAudit.Count) * 100, 2) 
            } else { 100 }
            
            GroupComplianceRate = if ($GroupAudit.Count -gt 0) { 
                [math]::Round((($GroupAudit.Count - ($GroupAudit | Where-Object { $_.ViolationCount -gt 0 }).Count) / $GroupAudit.Count) * 100, 2) 
            } else { 100 }
            
            OverallComplianceScore = 0
        }
        
        # Calcul du score global de conformité
        $summary.OverallComplianceScore = [math]::Round(($summary.UserComplianceRate + $summary.GroupComplianceRate) / 2, 2)
        
        # Recommandations basées sur les résultats
        $recommendations = @()
        
        if ($summary.NonCompliantUsers -gt 0) {
            $recommendations += "Corriger les violations de conformité pour $($summary.NonCompliantUsers) utilisateurs"
        }
        
        if ($summary.InactiveUsers -gt 0) {
            $recommendations += "Désactiver ou nettoyer $($summary.InactiveUsers) comptes inactifs"
        }
        
        if ($summary.CriticalRiskUsers -gt 0) {
            $recommendations += "URGENT: Examiner $($summary.CriticalRiskUsers) comptes à risque critique"
        }
        
        if ($summary.PrivilegedUsersWithIssues -gt 0) {
            $recommendations += "Réviser les accès privilégiés pour $($summary.PrivilegedUsersWithIssues) utilisateurs"
        }
        
        $complianceReport = @{
            ReportDate = Get-Date
            Summary = $summary
            Recommendations = $recommendations
            UserAudit = $UserAudit
            GroupAudit = $GroupAudit
            PermissionsAudit = $PermissionsAudit
            InactiveAudit = $InactiveAudit
        }
        
        Write-AuditLog "Rapport de conformité généré avec succès" -Level "SUCCESS" -LogFile $LogFile
        return $complianceReport
        
    } catch {
        Write-AuditLog "Erreur lors de la génération du rapport de conformité : $_" -Level "ERROR" -LogFile $LogFile
        throw
    }
}

function Export-AuditReport {
    param(
        [object]$Data,
        [string]$OutputPath,
        [string]$Format,
        [string]$ReportType,
        [string]$LogFile
    )
    
    try {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $PSScriptRoot "..\Reports"
        }
        
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "$ReportType`_$timestamp"
        
        switch ($Format.ToUpper()) {
            "HTML" {
                $filePath = Join-Path $OutputPath "$filename.html"
                if ($ReportType -eq "Compliance") {
                    Export-ComplianceHTML -Data $Data -FilePath $filePath
                } else {
                    New-HTMLReport -Title "Rapport $ReportType" -Data $Data -OutputPath $filePath
                }
            }
            
            "CSV" {
                $filePath = Join-Path $OutputPath "$filename.csv"
                $Data | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
            }
            
            "JSON" {
                $filePath = Join-Path $OutputPath "$filename.json"
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
            }
            
            "Excel" {
                $filePath = Join-Path $OutputPath "$filename.xlsx"
                if (Get-Module -ListAvailable -Name ImportExcel) {
                    $Data | Export-Excel -Path $filePath -AutoSize -BoldTopRow
                } else {
                    Write-AuditLog "Module ImportExcel non disponible, export en CSV" -Level "WARNING" -LogFile $LogFile
                    $filePath = Join-Path $OutputPath "$filename.csv"
                    $Data | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
                }
            }
        }
        
        Write-AuditLog "Rapport exporté : $filePath" -Level "SUCCESS" -LogFile $LogFile
        return $filePath
        
    } catch {
        Write-AuditLog "Erreur lors de l'export : $_" -Level "ERROR" -LogFile $LogFile
        throw
    }
}

function Export-ComplianceHTML {
    param(
        [object]$Data,
        [string]$FilePath
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Rapport de Conformité Active Directory</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .summary-card .number { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
        .compliance-good { color: #27ae60; }
        .compliance-warning { color: #f39c12; }
        .compliance-critical { color: #e74c3c; }
        .recommendations { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .recommendations h2 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .recommendation { background: #ecf0f1; padding: 10px; margin: 10px 0; border-left: 4px solid #3498db; border-radius: 4px; }
        .section { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .section h2 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background-color: #34495e; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .risk-low { background-color: #d5f4e6; }
        .risk-medium { background-color: #ffeaa7; }
        .risk-high { background-color: #fab1a0; }
        .risk-critical { background-color: #e17055; color: white; }
        .footer { margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Rapport de Conformité Active Directory</h1>
        <p>Généré le $(Get-Date -Format 'dd/MM/yyyy à HH:mm:ss') par $env:USERNAME</p>
    </div>
    
    <div class="summary-grid">
        <div class="summary-card">
            <h3>Score Global</h3>
            <div class="number compliance-$(if($Data.Summary.OverallComplianceScore -ge 90){"good"}elseif($Data.Summary.OverallComplianceScore -ge 70){"warning"}else{"critical"})">
                $($Data.Summary.OverallComplianceScore)%
            </div>
        </div>
        <div class="summary-card">
            <h3>Utilisateurs</h3>
            <div class="number">$($Data.Summary.TotalUsers)</div>
            <p>$($Data.Summary.NonCompliantUsers) non conformes</p>
        </div>
        <div class="summary-card">
            <h3>Groupes</h3>
            <div class="number">$($Data.Summary.TotalGroups)</div>
            <p>$($Data.Summary.NonCompliantGroups) non conformes</p>
        </div>
        <div class="summary-card">
            <h3>Comptes Inactifs</h3>
            <div class="number compliance-$(if($Data.Summary.InactiveUsers -eq 0){"good"}elseif($Data.Summary.InactiveUsers -lt 10){"warning"}else{"critical"})">
                $($Data.Summary.InactiveUsers)
            </div>
            <p>$($Data.Summary.CriticalRiskUsers) à risque critique</p>
        </div>
    </div>
    
    <div class="recommendations">
        <h2>📋 Recommandations Prioritaires</h2>
        $(foreach($rec in $Data.Recommendations) { "<div class='recommendation'>$rec</div>" })
    </div>
    
    <div class="section">
        <h2>👥 Audit des Utilisateurs</h2>
        <p><strong>Taux de conformité :</strong> $($Data.Summary.UserComplianceRate)%</p>
        $($Data.UserAudit | Where-Object { $_.ViolationCount -gt 0 } | ConvertTo-Html -Fragment -Property Username,Name,Department,ViolationCount,RiskLevel,Violations)
    </div>
    
    <div class="section">
        <h2>🔐 Comptes Privilégiés</h2>
        <p><strong>Utilisateurs privilégiés :</strong> $($Data.Summary.PrivilegedUsers)</p>
        <p><strong>Nécessitent une révision :</strong> $($Data.Summary.PrivilegedUsersWithIssues)</p>
        $($Data.PermissionsAudit | Where-Object { $_.RequiresReview } | ConvertTo-Html -Fragment -Property Username,Name,PrivilegedGroup,Department,LastLogon,Violations)
    </div>
    
    <div class="section">
        <h2>⏰ Comptes Inactifs</h2>
        $($Data.InactiveAudit | ConvertTo-Html -Fragment -Property Username,Name,Department,DaysInactive,HasSensitiveAccess,RiskLevel,RecommendedAction)
    </div>
    
    <div class="footer">
        <p>Rapport généré par le système d'automatisation des habilitations Active Directory v1.0</p>
        <p>Pour plus d'informations, consultez la documentation technique</p>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $FilePath -Encoding UTF8
}

# Fonction principale
function Main {
    $logFile = Initialize-AuditLogging
    
    try {
        Write-AuditLog "=== Démarrage de l'audit AD - Type: $AuditType ===" -Level "INFO" -LogFile $logFile
        
        # Vérification de la connectivité AD
        $adTest = Test-ADConnectivity
        if (-not $adTest.Success) {
            throw "Erreur de connectivité Active Directory : $($adTest.Error)"
        }
        
        Write-AuditLog "Connectivité AD validée - Domaine: $($adTest.Domain)" -Level "SUCCESS" -LogFile $logFile
        
        $result = @{}
        
        switch ($AuditType) {
            "Users" {
                $result = Invoke-UserAudit -SearchBase $SearchBase -IncludeInactive $IncludeInactive.IsPresent -LogFile $logFile
            }
            
            "Groups" {
                $result = Invoke-GroupAudit -SearchBase $SearchBase -LogFile $logFile
            }
            
            "Permissions" {
                $result = Invoke-PermissionsAudit -LogFile $logFile
            }
            
            "InactiveUsers" {
                $result = Invoke-InactiveUsersAudit -InactiveDays $InactiveDays -SearchBase $SearchBase -LogFile $logFile
            }
            
            "Full" {
                Write-AuditLog "Exécution d'un audit complet" -Level "INFO" -LogFile $logFile
                
                $userAudit = Invoke-UserAudit -SearchBase $SearchBase -IncludeInactive $IncludeInactive.IsPresent -LogFile $logFile
                $groupAudit = Invoke-GroupAudit -SearchBase $SearchBase -LogFile $logFile
                $permissionsAudit = Invoke-PermissionsAudit -LogFile $logFile
                $inactiveAudit = Invoke-InactiveUsersAudit -InactiveDays $InactiveDays -SearchBase $SearchBase -LogFile $logFile
                
                $result = @{
                    UserAudit = $userAudit
                    GroupAudit = $groupAudit
                    PermissionsAudit = $permissionsAudit
                    InactiveAudit = $inactiveAudit
                }
            }
            
            "Compliance" {
                Write-AuditLog "Génération du rapport de conformité complet" -Level "INFO" -LogFile $logFile
                
                $userAudit = Invoke-UserAudit -SearchBase $SearchBase -IncludeInactive $IncludeInactive.IsPresent -LogFile $logFile
                $groupAudit = Invoke-GroupAudit -SearchBase $SearchBase -LogFile $logFile
                $permissionsAudit = Invoke-PermissionsAudit -LogFile $logFile
                $inactiveAudit = Invoke-InactiveUsersAudit -InactiveDays $InactiveDays -SearchBase $SearchBase -LogFile $logFile
                
                $result = New-ComplianceReport -UserAudit $userAudit -GroupAudit $groupAudit -PermissionsAudit $permissionsAudit -InactiveAudit $inactiveAudit -LogFile $logFile
            }
        }
        
        # Export du rapport
        $reportPath = Export-AuditReport -Data $result -OutputPath $OutputPath -Format $Format -ReportType $AuditType -LogFile $logFile
        
        # Envoi par email si demandé
        if ($SendEmail -and $Config.General.EnableEmailNotifications) {
            # TODO: Implémenter l'envoi d'email
            Write-AuditLog "Fonction d'envoi d'email à implémenter" -Level "INFO" -LogFile $logFile
        }
        
        Write-AuditLog "=== Audit terminé avec succès ===" -Level "SUCCESS" -LogFile $logFile
        Write-AuditLog "Rapport disponible : $reportPath" -Level "SUCCESS" -LogFile $logFile
        
        return @{
            Success = $true
            ReportPath = $reportPath
            AuditType = $AuditType
            Data = $result
        }
        
    } catch {
        Write-AuditLog "Erreur critique lors de l'audit : $_" -Level "ERROR" -LogFile $logFile
        return @{
            Success = $false
            Error = $_.Exception.Message
            AuditType = $AuditType
        }
    }
}

# Exécution du script
if ($MyInvocation.InvocationName -ne '.') {
    Main
}

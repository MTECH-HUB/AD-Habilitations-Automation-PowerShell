<#
.SYNOPSIS
    Script PowerShell pour l'automatisation de la gestion des comptes utilisateurs Active Directory

.DESCRIPTION
    Ce script permet de créer, modifier, supprimer et auditer les comptes utilisateurs Active Directory
    avec un suivi complet des droits attribués et une traçabilité des opérations.

.PARAMETER Action
    Action à effectuer : Create, Update, Delete, Disable, Enable, Audit

.PARAMETER UserData
    Hashtable contenant les données utilisateur (pour Create/Update)

.PARAMETER Username
    Nom d'utilisateur (pour Update/Delete/Disable/Enable)

.PARAMETER Template
    Modèle à utiliser pour la création (optionnel)

.PARAMETER ReportPath
    Chemin pour sauvegarder le rapport d'audit

.EXAMPLE
    .\AD-UserManagement.ps1 -Action Create -UserData $userData -Template "StandardUser"

.EXAMPLE
    .\AD-UserManagement.ps1 -Action Disable -Username "jdupont"

.NOTES
    Auteur: IT Security Team
    Version: 1.0
    Date: $(Get-Date -Format "dd/MM/yyyy")
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Create", "Update", "Delete", "Disable", "Enable", "Audit", "BulkCreate")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [hashtable]$UserData,
    
    [Parameter(Mandatory=$false)]
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$Template,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath,
    
    [Parameter(Mandatory=$false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Importation des modules requis
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot "..\Config\AD-Functions.psm1") -ErrorAction Stop

# Configuration globale
$script:ConfigPath = Join-Path $PSScriptRoot "..\Config\settings.json"
$script:LogPath = Join-Path $PSScriptRoot "..\Logs"
$script:Config = Get-Content $ConfigPath | ConvertFrom-Json

# Initialisation du logging
function Initialize-Logging {
    $logFile = Join-Path $LogPath "AD-UserManagement_$(Get-Date -Format 'yyyyMMdd').log"
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    return $logFile
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        [string]$LogFile
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Affichage console avec couleurs
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor White }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
    }
    
    # Écriture dans le fichier log
    Add-Content -Path $LogFile -Value $logEntry
}

function Get-UserTemplate {
    param([string]$TemplateName)
    
    $templatesPath = Join-Path $PSScriptRoot "..\Config\user-templates.json"
    $templates = Get-Content $templatesPath | ConvertFrom-Json
    
    if ($TemplateName -and $templates.$TemplateName) {
        return $templates.$TemplateName
    } elseif ($templates.Default) {
        return $templates.Default
    } else {
        throw "Aucun modèle trouvé : $TemplateName"
    }
}

function New-ADUserAccount {
    param(
        [hashtable]$UserData,
        [string]$Template,
        [string]$LogFile
    )
    
    try {
        Write-Log "Début de création du compte utilisateur : $($UserData.SamAccountName)" -Level "INFO" -LogFile $LogFile
        
        # Récupération du modèle
        if ($Template) {
            $templateData = Get-UserTemplate -TemplateName $Template
            # Fusion des données du modèle avec les données utilisateur
            foreach ($key in $templateData.PSObject.Properties.Name) {
                if (-not $UserData.ContainsKey($key)) {
                    $UserData[$key] = $templateData.$key
                }
            }
        }
        
        # Validation des données obligatoires
        $requiredFields = @("SamAccountName", "GivenName", "Surname", "UserPrincipalName")
        foreach ($field in $requiredFields) {
            if (-not $UserData.ContainsKey($field) -or [string]::IsNullOrWhiteSpace($UserData[$field])) {
                throw "Champ obligatoire manquant : $field"
            }
        }
        
        # Génération du mot de passe sécurisé
        if (-not $UserData.ContainsKey("Password")) {
            $UserData.Password = New-SecurePassword
        }
        
        # Création du compte AD
        $newUserParams = @{
            SamAccountName = $UserData.SamAccountName
            GivenName = $UserData.GivenName
            Surname = $UserData.Surname
            Name = "$($UserData.GivenName) $($UserData.Surname)"
            DisplayName = "$($UserData.GivenName) $($UserData.Surname)"
            UserPrincipalName = $UserData.UserPrincipalName
            EmailAddress = $UserData.EmailAddress
            Title = $UserData.Title
            Department = $UserData.Department
            Company = $UserData.Company
            Manager = $UserData.Manager
            Path = if ($UserData.OrganizationalUnit) { $UserData.OrganizationalUnit } else { $Config.DefaultOU }
            AccountPassword = (ConvertTo-SecureString $UserData.Password -AsPlainText -Force)
            Enabled = $true
            ChangePasswordAtLogon = $true
        }
        
        # Suppression des paramètres vides
        $cleanedParams = @{}
        foreach ($param in $newUserParams.GetEnumerator()) {
            if ($param.Value -ne $null -and $param.Value -ne "") {
                $cleanedParams[$param.Key] = $param.Value
            }
        }
        $newUserParams = $cleanedParams
        
        if ($WhatIf) {
            Write-Log "SIMULATION - Création de l'utilisateur : $($UserData.SamAccountName)" -Level "INFO" -LogFile $LogFile
            return @{ Success = $true; Action = "Simulated"; Username = $UserData.SamAccountName }
        }
        
        # Création effective
        New-ADUser @newUserParams
        Write-Log "Compte créé avec succès : $($UserData.SamAccountName)" -Level "SUCCESS" -LogFile $LogFile
        
        # Attribution des groupes si spécifiés
        if ($UserData.Groups) {
            foreach ($group in $UserData.Groups) {
                try {
                    Add-ADGroupMember -Identity $group -Members $UserData.SamAccountName
                    Write-Log "Ajouté au groupe $group : $($UserData.SamAccountName)" -Level "SUCCESS" -LogFile $LogFile
                } catch {
                    Write-Log "Erreur lors de l'ajout au groupe $group : $_" -Level "ERROR" -LogFile $LogFile
                }
            }
        }
        
        # Enregistrement de l'opération pour audit
        $auditEntry = @{
            Timestamp = Get-Date
            Action = "UserCreated"
            Username = $UserData.SamAccountName
            Operator = $env:USERNAME
            Details = $UserData
        }
        
        Add-AuditEntry -AuditEntry $auditEntry
        
        return @{ 
            Success = $true
            Action = "Created"
            Username = $UserData.SamAccountName
            Password = $UserData.Password
        }
        
    } catch {
        Write-Log "Erreur lors de la création du compte $($UserData.SamAccountName) : $_" -Level "ERROR" -LogFile $LogFile
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Update-ADUserAccount {
    param(
        [string]$Username,
        [hashtable]$UserData,
        [string]$LogFile
    )
    
    try {
        Write-Log "Début de mise à jour du compte : $Username" -Level "INFO" -LogFile $LogFile
        
        # Vérification de l'existence de l'utilisateur
        $user = Get-ADUser -Identity $Username -Properties * -ErrorAction Stop
        
        # Préparation des modifications
        $updateParams = @{}
        $validProperties = @("GivenName", "Surname", "DisplayName", "EmailAddress", "Title", "Department", "Company", "Manager", "Description")
        
        foreach ($property in $validProperties) {
            if ($UserData.ContainsKey($property)) {
                $updateParams[$property] = $UserData[$property]
            }
        }
        
        if ($WhatIf) {
            Write-Log "SIMULATION - Mise à jour de l'utilisateur : $Username" -Level "INFO" -LogFile $LogFile
            return @{ Success = $true; Action = "Simulated"; Username = $Username }
        }
        
        # Application des modifications
        if ($updateParams.Count -gt 0) {
            Set-ADUser -Identity $Username @updateParams
            Write-Log "Compte mis à jour avec succès : $Username" -Level "SUCCESS" -LogFile $LogFile
        }
        
        # Gestion des groupes si spécifiée
        if ($UserData.ContainsKey("Groups")) {
            $currentGroups = (Get-ADUser -Identity $Username -Properties MemberOf).MemberOf | ForEach-Object { (Get-ADGroup $_).Name }
            $targetGroups = $UserData.Groups
            
            # Groupes à ajouter
            $groupsToAdd = $targetGroups | Where-Object { $_ -notin $currentGroups }
            foreach ($group in $groupsToAdd) {
                Add-ADGroupMember -Identity $group -Members $Username
                Write-Log "Ajouté au groupe $group : $Username" -Level "SUCCESS" -LogFile $LogFile
            }
            
            # Groupes à supprimer (si RemoveOtherGroups est spécifié)
            if ($UserData.RemoveOtherGroups) {
                $groupsToRemove = $currentGroups | Where-Object { $_ -notin $targetGroups -and $_ -notin $Config.ProtectedGroups }
                foreach ($group in $groupsToRemove) {
                    Remove-ADGroupMember -Identity $group -Members $Username -Confirm:$false
                    Write-Log "Supprimé du groupe $group : $Username" -Level "SUCCESS" -LogFile $LogFile
                }
            }
        }
        
        # Audit
        $auditEntry = @{
            Timestamp = Get-Date
            Action = "UserUpdated"
            Username = $Username
            Operator = $env:USERNAME
            Details = $updateParams
        }
        Add-AuditEntry -AuditEntry $auditEntry
        
        return @{ Success = $true; Action = "Updated"; Username = $Username }
        
    } catch {
        Write-Log "Erreur lors de la mise à jour du compte $Username : $_" -Level "ERROR" -LogFile $LogFile
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Remove-ADUserAccount {
    param(
        [string]$Username,
        [string]$LogFile,
        [switch]$Archive
    )
    
    try {
        Write-Log "Début de suppression du compte : $Username" -Level "INFO" -LogFile $LogFile
        
        # Vérification de l'existence
        $user = Get-ADUser -Identity $Username -Properties * -ErrorAction Stop
        
        if ($WhatIf) {
            Write-Log "SIMULATION - Suppression de l'utilisateur : $Username" -Level "INFO" -LogFile $LogFile
            return @{ Success = $true; Action = "Simulated"; Username = $Username }
        }
        
        # Archivage des données si demandé
        if ($Archive) {
            $archiveData = @{
                User = $user
                Groups = (Get-ADUser -Identity $Username -Properties MemberOf).MemberOf
                Timestamp = Get-Date
            }
            
            $archivePath = Join-Path $PSScriptRoot "..\Backups\DeletedUsers_$(Get-Date -Format 'yyyyMMdd').json"
            if (-not (Test-Path (Split-Path $archivePath))) {
                New-Item -Path (Split-Path $archivePath) -ItemType Directory -Force | Out-Null
            }
            
            $archiveData | ConvertTo-Json -Depth 10 | Add-Content -Path $archivePath
            Write-Log "Données archivées pour : $Username" -Level "INFO" -LogFile $LogFile
        }
        
        # Suppression effective
        Remove-ADUser -Identity $Username -Confirm:$false
        Write-Log "Compte supprimé avec succès : $Username" -Level "SUCCESS" -LogFile $LogFile
        
        # Audit
        $auditEntry = @{
            Timestamp = Get-Date
            Action = "UserDeleted"
            Username = $Username
            Operator = $env:USERNAME
            Archived = $Archive.IsPresent
        }
        Add-AuditEntry -AuditEntry $auditEntry
        
        return @{ Success = $true; Action = "Deleted"; Username = $Username }
        
    } catch {
        Write-Log "Erreur lors de la suppression du compte $Username : $_" -Level "ERROR" -LogFile $LogFile
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Set-ADUserStatus {
    param(
        [string]$Username,
        [bool]$Enable,
        [string]$LogFile
    )
    
    try {
        $action = if ($Enable) { "activation" } else { "désactivation" }
        Write-Log "Début de $action du compte : $Username" -Level "INFO" -LogFile $LogFile
        
        if ($WhatIf) {
            Write-Log "SIMULATION - $action de l'utilisateur : $Username" -Level "INFO" -LogFile $LogFile
            return @{ Success = $true; Action = "Simulated"; Username = $Username }
        }
        
        if ($Enable) {
            Enable-ADAccount -Identity $Username
        } else {
            Disable-ADAccount -Identity $Username
        }
        
        $status = if ($Enable) { "activé" } else { "désactivé" }
        Write-Log "Compte $status avec succès : $Username" -Level "SUCCESS" -LogFile $LogFile
        
        # Audit
        $auditEntry = @{
            Timestamp = Get-Date
            Action = if ($Enable) { "UserEnabled" } else { "UserDisabled" }
            Username = $Username
            Operator = $env:USERNAME
        }
        Add-AuditEntry -AuditEntry $auditEntry
        
        return @{ Success = $true; Action = $status; Username = $Username }
        
    } catch {
        Write-Log "Erreur lors de $action du compte $Username : $_" -Level "ERROR" -LogFile $LogFile
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Invoke-BulkUserCreation {
    param(
        [string]$CsvPath,
        [string]$Template,
        [string]$LogFile
    )
    
    try {
        Write-Log "Début de création en masse depuis : $CsvPath" -Level "INFO" -LogFile $LogFile
        
        if (-not (Test-Path $CsvPath)) {
            throw "Fichier CSV introuvable : $CsvPath"
        }
        
        $users = Import-Csv -Path $CsvPath -Encoding UTF8
        $results = @()
        
        foreach ($user in $users) {
            $userData = @{}
            foreach ($property in $user.PSObject.Properties) {
                $userData[$property.Name] = $property.Value
            }
            
            $result = New-ADUserAccount -UserData $userData -Template $Template -LogFile $LogFile
            $results += $result
            
            Start-Sleep -Milliseconds 500  # Pause pour éviter la surcharge
        }
        
        # Génération du rapport de résultats
        $reportPath = Join-Path $PSScriptRoot "..\Reports\BulkCreation_$(Get-Date -Format 'yyyyMMddHHmmss').csv"
        $results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
        
        Write-Log "Création en masse terminée. Rapport : $reportPath" -Level "SUCCESS" -LogFile $LogFile
        return $results
        
    } catch {
        Write-Log "Erreur lors de la création en masse : $_" -Level "ERROR" -LogFile $LogFile
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Fonction principale
function Main {
    $logFile = Initialize-Logging
    
    try {
        Write-Log "=== Démarrage du script AD-UserManagement ===" -Level "INFO" -LogFile $logFile
        Write-Log "Action demandée : $Action" -Level "INFO" -LogFile $logFile
        
        switch ($Action) {
            "Create" {
                if (-not $UserData) {
                    throw "Paramètre UserData requis pour l'action Create"
                }
                $result = New-ADUserAccount -UserData $UserData -Template $Template -LogFile $logFile
            }
            
            "Update" {
                if (-not $Username -or -not $UserData) {
                    throw "Paramètres Username et UserData requis pour l'action Update"
                }
                $result = Update-ADUserAccount -Username $Username -UserData $UserData -LogFile $logFile
            }
            
            "Delete" {
                if (-not $Username) {
                    throw "Paramètre Username requis pour l'action Delete"
                }
                $result = Remove-ADUserAccount -Username $Username -LogFile $logFile -Archive
            }
            
            "Disable" {
                if (-not $Username) {
                    throw "Paramètre Username requis pour l'action Disable"
                }
                $result = Set-ADUserStatus -Username $Username -Enable $false -LogFile $logFile
            }
            
            "Enable" {
                if (-not $Username) {
                    throw "Paramètre Username requis pour l'action Enable"
                }
                $result = Set-ADUserStatus -Username $Username -Enable $true -LogFile $logFile
            }
            
            "BulkCreate" {
                if (-not $CsvPath) {
                    throw "Paramètre CsvPath requis pour l'action BulkCreate"
                }
                $result = Invoke-BulkUserCreation -CsvPath $CsvPath -Template $Template -LogFile $logFile
            }
            
            "Audit" {
                # Appel du script d'audit
                $auditScript = Join-Path $PSScriptRoot "AD-RightsAudit.ps1"
                $auditParams = @{
                    AuditType = "Users"
                    Format = "JSON"
                }
                if ($ReportPath) { $auditParams.OutputPath = $ReportPath }
                
                $result = & $auditScript @auditParams
            }
        }
        
        Write-Log "=== Fin du script AD-UserManagement ===" -Level "SUCCESS" -LogFile $logFile
        return $result
        
    } catch {
        Write-Log "Erreur critique : $_" -Level "ERROR" -LogFile $logFile
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Exécution du script
if ($MyInvocation.InvocationName -ne '.') {
    Main
}

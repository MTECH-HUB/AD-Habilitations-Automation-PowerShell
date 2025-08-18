<#
.SYNOPSIS
    Module de fonctions communes pour l'automatisation Active Directory

.DESCRIPTION
    Ce module contient les fonctions utilitaires partagées par les différents scripts
    de gestion des habilitations Active Directory.
#>

# Fonction pour générer un mot de passe sécurisé
function New-SecurePassword {
    param(
        [int]$Length = 12,
        [switch]$IncludeSymbols
    )
    
    $lowercase = "abcdefghijklmnopqrstuvwxyz"
    $uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $numbers = "0123456789"
    $symbols = "!@#$%^&*"
    
    $charset = $lowercase + $uppercase + $numbers
    if ($IncludeSymbols) {
        $charset += $symbols
    }
    
    $password = ""
    $random = New-Object System.Random
    
    # Assurer au moins un caractère de chaque type
    $password += $lowercase[$random.Next($lowercase.Length)]
    $password += $uppercase[$random.Next($uppercase.Length)]
    $password += $numbers[$random.Next($numbers.Length)]
    
    if ($IncludeSymbols) {
        $password += $symbols[$random.Next($symbols.Length)]
    }
    
    # Compléter avec des caractères aléatoires
    for ($i = $password.Length; $i -lt $Length; $i++) {
        $password += $charset[$random.Next($charset.Length)]
    }
    
    # Mélanger les caractères
    $passwordArray = $password.ToCharArray()
    for ($i = 0; $i -lt $passwordArray.Length; $i++) {
        $j = $random.Next($passwordArray.Length)
        $temp = $passwordArray[$i]
        $passwordArray[$i] = $passwordArray[$j]
        $passwordArray[$j] = $temp
    }
    
    return -join $passwordArray
}

# Fonction d'audit et logging
function Add-AuditEntry {
    param(
        [hashtable]$AuditEntry
    )
    
    $auditPath = Join-Path $PSScriptRoot "..\Logs\audit.json"
    
    # Créer le fichier d'audit s'il n'existe pas
    if (-not (Test-Path $auditPath)) {
        "[]" | Out-File -FilePath $auditPath -Encoding UTF8
    }
    
    # Lire les entrées existantes
    $existingEntries = Get-Content -Path $auditPath | ConvertFrom-Json
    
    # Ajouter la nouvelle entrée
    $existingEntries += $AuditEntry
    
    # Sauvegarder
    $existingEntries | ConvertTo-Json -Depth 10 | Out-File -FilePath $auditPath -Encoding UTF8
}

# Fonction pour valider les données utilisateur
function Test-UserData {
    param(
        [hashtable]$UserData,
        [string[]]$RequiredFields = @("SamAccountName", "GivenName", "Surname")
    )
    
    $errors = @()
    
    foreach ($field in $RequiredFields) {
        if (-not $UserData.ContainsKey($field) -or [string]::IsNullOrWhiteSpace($UserData[$field])) {
            $errors += "Champ obligatoire manquant : $field"
        }
    }
    
    # Validation du format UPN
    if ($UserData.ContainsKey("UserPrincipalName") -and $UserData.UserPrincipalName) {
        if ($UserData.UserPrincipalName -notmatch "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$") {
            $errors += "Format UPN invalide : $($UserData.UserPrincipalName)"
        }
    }
    
    # Validation du SamAccountName
    if ($UserData.ContainsKey("SamAccountName") -and $UserData.SamAccountName) {
        if ($UserData.SamAccountName.Length -gt 20) {
            $errors += "SamAccountName trop long (max 20 caractères) : $($UserData.SamAccountName)"
        }
        if ($UserData.SamAccountName -match "[^a-zA-Z0-9._-]") {
            $errors += "SamAccountName contient des caractères invalides : $($UserData.SamAccountName)"
        }
    }
    
    return $errors
}

# Fonction pour générer un nom d'utilisateur unique
function New-UniqueUsername {
    param(
        [string]$FirstName,
        [string]$LastName,
        [string]$Domain
    )
    
    $baseUsername = "$($FirstName.ToLower()).$($LastName.ToLower())"
    $baseUsername = $baseUsername -replace "[^a-zA-Z0-9._-]", ""
    
    # Vérifier l'unicité
    $counter = 1
    $username = $baseUsername
    
    while (Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue) {
        $username = "$baseUsername$counter"
        $counter++
    }
    
    return $username
}

# Fonction pour obtenir les informations de domaine
function Get-DomainInfo {
    try {
        $domain = Get-ADDomain
        return @{
            Name = $domain.Name
            NetBIOSName = $domain.NetBIOSName
            DNSRoot = $domain.DNSRoot
            Forest = $domain.Forest
            DomainMode = $domain.DomainMode
            DefaultNamingContext = $domain.DistinguishedName
        }
    } catch {
        throw "Impossible de récupérer les informations du domaine : $_"
    }
}

# Fonction pour obtenir les OUs disponibles
function Get-OrganizationalUnits {
    param(
        [string]$SearchBase,
        [switch]$IncludeBuiltIn
    )
    
    $filter = "*"
    if (-not $IncludeBuiltIn) {
        $filter = "Name -notlike 'Builtin' -and Name -notlike 'Users' -and Name -notlike 'Computers'"
    }
    
    $searchParams = @{
        Filter = $filter
        SearchScope = "Subtree"
    }
    
    if ($SearchBase) {
        $searchParams.SearchBase = $SearchBase
    }
    
    return Get-ADOrganizationalUnit @searchParams | Select-Object Name, DistinguishedName
}

# Fonction pour valider l'existence d'un groupe
function Test-ADGroupExists {
    param([string]$GroupName)
    
    try {
        Get-ADGroup -Identity $GroupName -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Fonction pour obtenir les membres d'un groupe
function Get-GroupMembers {
    param(
        [string]$GroupName,
        [switch]$Recursive
    )
    
    try {
        $members = Get-ADGroupMember -Identity $GroupName -Recursive:$Recursive
        return $members | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
    } catch {
        Write-Warning "Impossible de récupérer les membres du groupe $GroupName : $_"
        return @()
    }
}

# Fonction pour analyser les permissions d'un utilisateur
function Get-UserPermissions {
    param([string]$Username)
    
    try {
        $user = Get-ADUser -Identity $Username -Properties MemberOf
        $groups = @()
        
        foreach ($groupDN in $user.MemberOf) {
            $group = Get-ADGroup -Identity $groupDN -Properties Description
            $groups += @{
                Name = $group.Name
                Description = $group.Description
                DistinguishedName = $group.DistinguishedName
                GroupScope = $group.GroupScope
                GroupCategory = $group.GroupCategory
            }
        }
        
        return @{
            Username = $Username
            Groups = $groups
            TotalGroups = $groups.Count
        }
    } catch {
        throw "Impossible d'analyser les permissions pour $Username : $_"
    }
}

# Fonction pour détecter les comptes inactifs
function Get-InactiveUsers {
    param(
        [int]$DaysInactive = 90,
        [string]$SearchBase
    )
    
    $cutoffDate = (Get-Date).AddDays(-$DaysInactive)
    
    $filterParams = @{
        Filter = "LastLogonDate -lt '$cutoffDate' -and Enabled -eq 'True'"
        Properties = "LastLogonDate", "Created", "MemberOf"
    }
    
    if ($SearchBase) {
        $filterParams.SearchBase = $SearchBase
    }
    
    $inactiveUsers = Get-ADUser @filterParams
    
    return $inactiveUsers | ForEach-Object {
        @{
            Username = $_.SamAccountName
            Name = $_.Name
            LastLogon = $_.LastLogonDate
            Created = $_.Created
            DaysInactive = if ($_.LastLogonDate) { (Get-Date) - $_.LastLogonDate | Select-Object -ExpandProperty Days } else { "Jamais connecté" }
            GroupCount = ($_.MemberOf | Measure-Object).Count
        }
    }
}

# Fonction pour générer un rapport HTML
function New-HTMLReport {
    param(
        [string]$Title,
        [object[]]$Data,
        [string]$OutputPath,
        [hashtable]$CustomCSS
    )
    
    $defaultCSS = @"
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
    .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
    .header h1 { margin: 0; }
    .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    table { width: 100%; border-collapse: collapse; background-color: white; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    th { background-color: #34495e; color: white; padding: 12px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
    tr:nth-child(even) { background-color: #f8f9fa; }
    tr:hover { background-color: #e3f2fd; }
    .status-active { color: #27ae60; font-weight: bold; }
    .status-inactive { color: #e74c3c; font-weight: bold; }
    .footer { margin-top: 20px; text-align: center; color: #7f8c8d; font-size: 12px; }
</style>
"@
    
    $css = if ($CustomCSS) { $CustomCSS } else { $defaultCSS }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>$Title</title>
    $css
</head>
<body>
    <div class="header">
        <h1>$Title</h1>
        <p>Généré le $(Get-Date -Format 'dd/MM/yyyy à HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <h2>Résumé</h2>
        <p><strong>Nombre total d'éléments :</strong> $($Data.Count)</p>
        <p><strong>Généré par :</strong> $env:USERNAME</p>
    </div>
    
    $($Data | ConvertTo-Html -Fragment)
    
    <div class="footer">
        <p>Rapport généré par le système d'automatisation des habilitations Active Directory</p>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

# Fonction pour envoyer des notifications par email
function Send-NotificationEmail {
    param(
        [string]$To,
        [string]$Subject,
        [string]$Body,
        [string]$SmtpServer,
        [int]$Port = 587,
        [pscredential]$Credential,
        [string]$AttachmentPath
    )
    
    try {
        $mailParams = @{
            To = $To
            Subject = $Subject
            Body = $Body
            BodyAsHtml = $true
            SmtpServer = $SmtpServer
            Port = $Port
            UseSsl = $true
        }
        
        if ($Credential) {
            $mailParams.Credential = $Credential
        }
        
        if ($AttachmentPath -and (Test-Path $AttachmentPath)) {
            $mailParams.Attachments = $AttachmentPath
        }
        
        Send-MailMessage @mailParams
        return $true
    } catch {
        Write-Warning "Erreur lors de l'envoi de l'email : $_"
        return $false
    }
}

# Fonction pour chiffrer les données sensibles
function Protect-SensitiveData {
    param(
        [string]$Data,
        [string]$KeyPath
    )
    
    if (-not (Test-Path $KeyPath)) {
        # Générer une nouvelle clé
        $key = New-Object Byte[] 32
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
        $key | Out-File $KeyPath
    }
    
    $key = Get-Content $KeyPath
    $secureString = ConvertTo-SecureString $Data -AsPlainText -Force
    return ConvertFrom-SecureString $secureString -Key $key
}

# Fonction pour déchiffrer les données
function Unprotect-SensitiveData {
    param(
        [string]$EncryptedData,
        [string]$KeyPath
    )
    
    if (-not (Test-Path $KeyPath)) {
        throw "Clé de chiffrement introuvable : $KeyPath"
    }
    
    $key = Get-Content $KeyPath
    $secureString = ConvertTo-SecureString $EncryptedData -Key $key
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# Fonction pour valider la connectivité AD
function Test-ADConnectivity {
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $dc = Get-ADDomainController -ErrorAction Stop
        
        return @{
            Success = $true
            Domain = $domain.Name
            DomainController = $dc.Name
            Message = "Connectivité AD OK"
        }
    } catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
            Message = "Erreur de connectivité AD"
        }
    }
}

# Export des fonctions
Export-ModuleMember -Function *

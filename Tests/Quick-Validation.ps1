# Script de validation simplifie
Write-Host "Verification de la syntaxe PowerShell..." -ForegroundColor Cyan

$projectPath = "c:\Users\Delvo\Documents\GitHub\AD-Habilitations-Automation"
$issues = @()
$totalFiles = 0
$validFiles = 0

# Test des fichiers PowerShell
Get-ChildItem $projectPath -Recurse -Filter "*.ps1" | ForEach-Object {
    $totalFiles++
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $_.FullName -Raw), [ref]$null)
        Write-Host "OK: $($_.Name)" -ForegroundColor Green
        $validFiles++
    } catch {
        Write-Host "ERREUR: $($_.Name) - $_" -ForegroundColor Red
        $issues += "Erreur dans $($_.Name): $_"
    }
}

# Test des fichiers PSM1
Get-ChildItem $projectPath -Recurse -Filter "*.psm1" | ForEach-Object {
    $totalFiles++
    try {
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $_.FullName -Raw), [ref]$null)
        Write-Host "OK: $($_.Name)" -ForegroundColor Green
        $validFiles++
    } catch {
        Write-Host "ERREUR: $($_.Name) - $_" -ForegroundColor Red
        $issues += "Erreur dans $($_.Name): $_"
    }
}

# Test des fichiers JSON
Get-ChildItem $projectPath -Recurse -Filter "*.json" | ForEach-Object {
    $totalFiles++
    try {
        Get-Content $_.FullName | ConvertFrom-Json | Out-Null
        Write-Host "OK: $($_.Name)" -ForegroundColor Green
        $validFiles++
    } catch {
        Write-Host "ERREUR: $($_.Name) - $_" -ForegroundColor Red
        $issues += "Erreur JSON dans $($_.Name): $_"
    }
}

Write-Host "`nRESULTATS:" -ForegroundColor Cyan
Write-Host "Fichiers valides: $validFiles/$totalFiles" -ForegroundColor Green

if ($issues.Count -eq 0) {
    Write-Host "Aucun probleme detecte! Projet valide." -ForegroundColor Green
} else {
    Write-Host "`nProblemes detectes:" -ForegroundColor Yellow
    foreach ($issue in $issues) {
        Write-Host "- $issue" -ForegroundColor Red
    }
}

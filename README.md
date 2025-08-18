# Automatisation des Habilitations Active Directory

## Description
Ce projet fournit une solution complète d'automatisation pour la gestion des comptes utilisateurs Active Directory, incluant la création, suppression, modification des comptes et le suivi des droits attribués avec génération de rapports de conformité.

## Fonctionnalités

### 🔧 Gestion des Comptes Utilisateurs
- **Création automatisée** de comptes utilisateurs avec profils prédéfinis
- **Suppression sécurisée** avec archivage des données
- **Modification en masse** des attributs utilisateur
- **Gestion des mots de passe** avec politique de sécurité

### 📊 Suivi des Droits et Permissions
- **Audit des groupes** et permissions attribuées
- **Traçabilité complète** des modifications de droits
- **Détection des permissions orphelines** ou obsolètes
- **Analyse des privilèges** élevés et sensibles

### 📈 Rapports de Conformité
- **Rapports automatisés** de conformité RGPD/SOX
- **Tableaux de bord** de suivi des habilitations
- **Alertes** sur les comptes inactifs ou à risque
- **Export** vers Excel/CSV/HTML

## Structure du Projet

```
AD-Habilitations-Automation/
├── Scripts/                    # Scripts PowerShell principaux
│   ├── AD-UserManagement.ps1   # Gestion des comptes utilisateurs
│   ├── AD-RightsAudit.ps1      # Audit des droits et permissions
│   ├── AD-ComplianceReport.ps1 # Génération des rapports
│   └── AD-MainMenu.ps1         # Interface utilisateur principale
├── Config/                     # Fichiers de configuration
│   ├── settings.json          # Configuration générale
│   ├── user-templates.json    # Modèles de comptes utilisateur
│   └── compliance-rules.json  # Règles de conformité
├── Logs/                      # Journaux d'activité
├── Reports/                   # Rapports générés
├── Templates/                 # Modèles de rapports
└── Tests/                     # Scripts de test
```

## Prérequis

- **Windows PowerShell 5.1** ou **PowerShell Core 7.x**
- **Module Active Directory** pour PowerShell
- **Privilèges administrateur** sur le domaine Active Directory
- **Module ImportExcel** (optionnel, pour les rapports Excel)

## Installation

1. Cloner le projet :
```powershell
git clone https://github.com/Eizi0/AD-Habilitations-Automation-PowerShell.git
cd AD-Habilitations-Automation-PowerShell
```

2. Installer les modules PowerShell requis :
```powershell
Install-Module -Name ActiveDirectory -Force
Install-Module -Name ImportExcel -Force
```

3. Configurer les paramètres dans `Config/settings.json`

4. Exécuter le script principal :
```powershell
.\Scripts\AD-MainMenu.ps1
```

## Configuration

Modifiez le fichier `Config/settings.json` pour adapter l'outil à votre environnement :
- Domaine Active Directory
- Unités organisationnelles par défaut
- Politiques de mots de passe
- Paramètres de reporting

## Utilisation

### Interface en Ligne de Commande
```powershell
# Lancer le menu principal
.\Scripts\AD-MainMenu.ps1

# Créer un utilisateur directement
.\Scripts\AD-UserManagement.ps1 -Action Create -UserData @{...}

# Générer un rapport de conformité
.\Scripts\AD-ComplianceReport.ps1 -ReportType Full
```

### Automatisation via Tâches Planifiées
Le projet inclut des scripts pour configurer des tâches planifiées Windows pour :
- Audits quotidiens des permissions
- Rapports hebdomadaires de conformité
- Nettoyage mensuel des comptes inactifs

## Sécurité

- **Chiffrement** des logs sensibles
- **Validation** des entrées utilisateur
- **Audit trail** complet de toutes les opérations
- **Gestion des erreurs** robuste avec rollback

## Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Commit vos changements (`git commit -am 'Ajout nouvelle fonctionnalité'`)
4. Push vers la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. Créer une Pull Request

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Support

Pour toute question ou problème :
- Ouvrir une issue sur GitHub
- Consulter la documentation dans le dossier `docs/`
- Vérifier les logs dans le dossier `Logs/`

---

**Version :** 1.0.0  
**Dernière mise à jour :10-08-2025

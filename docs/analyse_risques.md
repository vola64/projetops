# Analyse des Risques du Pipeline CI/CD
## Méthode STRIDE & Conformité OWASP CI/CD Top 10

**Projet :** Sécurisation de la Supply Chain Logicielle
**Date :** 2024
**Auteur :** DevSecOps Team
**Version :** 1.0

---

## 1. Introduction

Cette analyse identifie les menaces pesant sur chaque composant du pipeline CI/CD selon la méthode **STRIDE** :

| Lettre | Menace | Description |
|--------|--------|-------------|
| **S** | Spoofing | Usurpation d'identité |
| **T** | Tampering | Falsification de données |
| **R** | Repudiation | Déni d'une action effectuée |
| **I** | Information Disclosure | Fuite d'informations sensibles |
| **D** | Denial of Service | Indisponibilité du service |
| **E** | Elevation of Privilege | Escalade de privilèges |

---

## 2. Analyse par Composant

### 2.1 Dépôt Git (Code Source)

| ID | Menace | STRIDE | Probabilité | Impact | Risque | Mitigation |
|----|--------|--------|-------------|--------|--------|------------|
| G1 | Commit de secrets (clés, passwords) | I | Élevée | Critique | **CRITIQUE** | Gitleaks Stage 2 du pipeline |
| G2 | Accès non autorisé au dépôt | S | Moyenne | Élevé | **ÉLEVÉ** | MFA + branches protégées |
| G3 | Injection de code malveillant via PR | T | Faible | Critique | **ÉLEVÉ** | SAST + code review obligatoire |
| G4 | Manipulation des variables CI/CD | T/I | Faible | Critique | **ÉLEVÉ** | Variables protégées + masquées |

---

### 2.2 Pipeline Jenkins

| ID | Menace | STRIDE | Probabilité | Impact | Risque | Mitigation |
|----|--------|--------|-------------|--------|--------|------------|
| P1 | Modification du Jenkinsfile | T | Moyenne | Critique | **CRITIQUE** | Branche protégée + review |
| P2 | Injection de commandes dans les scripts | T/E | Faible | Critique | **ÉLEVÉ** | Images Docker officielles + versionnées |
| P3 | Fuite de secrets dans les logs | I | Moyenne | Élevé | **ÉLEVÉ** | Credentials Jenkins masqués |
| P4 | Dépendance tierce compromise | T | Moyenne | Critique | **ÉLEVÉ** | OWASP Dep-Check + version pinning |
| P5 | Runner Jenkins compromis | E | Faible | Critique | **ÉLEVÉ** | Agent Docker isolé |

---

### 2.3 Images Docker

| ID | Menace | STRIDE | Probabilité | Impact | Risque | Mitigation |
|----|--------|--------|-------------|--------|--------|------------|
| D1 | Image de base empoisonnée | T | Moyenne | Critique | **CRITIQUE** | Trivy + `--pull` + digest SHA fixé |
| D2 | Exécution en tant que root | E | Élevée | Élevé | **ÉLEVÉ** | USER 1001 dans Dockerfile |
| D3 | Secrets dans les layers Docker | I | Moyenne | Critique | **ÉLEVÉ** | Multi-stage build + .dockerignore |
| D4 | CVE dans les packages OS/Python | T | Élevée | Élevé | **ÉLEVÉ** | Trivy bloquant si HIGH/CRITICAL |
| D5 | Image falsifiée après le build | T | Faible | Critique | **ÉLEVÉ** | Signature Cosign obligatoire |

---

### 2.4 Harbor Registry

| ID | Menace | STRIDE | Probabilité | Impact | Risque | Mitigation |
|----|--------|--------|-------------|--------|--------|------------|
| H1 | Accès non autorisé au registry | S | Faible | Critique | **ÉLEVÉ** | RBAC Harbor + auth forte |
| H2 | Pull d'image non signée | T | Moyenne | Critique | **ÉLEVÉ** | Policy : signature obligatoire |
| H3 | Suppression malveillante d'images | T/R | Faible | Élevé | **MOYEN** | Tags immuables + audit logs |
| H4 | Déni de service sur le registry | D | Faible | Élevé | **MOYEN** | Rate limiting + HA |

---

### 2.5 Serveur de Déploiement

| ID | Menace | STRIDE | Probabilité | Impact | Risque | Mitigation |
|----|--------|--------|-------------|--------|--------|------------|
| S1 | Accès SSH non autorisé | S | Faible | Critique | **ÉLEVÉ** | Clé SSH dédiée CI/CD + known_hosts |
| S2 | Escalade de privilèges conteneur | E | Faible | Critique | **ÉLEVÉ** | `no-new-privileges` + `cap_drop ALL` |
| S3 | Communication inter-conteneurs non voulue | I | Faible | Moyen | **MOYEN** | Réseaux Docker isolés |
| S4 | Secrets dans les fichiers .env | I | Moyenne | Élevé | **ÉLEVÉ** | .env.secrets hors Git + vault |

---

## 3. Conformité OWASP CI/CD Security Top 10

| # | Risque OWASP | Statut | Mesure Appliquée |
|---|-------------|--------|-----------------|
| CICD-SEC-1 | Insufficient Flow Control | ✅ Conforme | Approbation manuelle obligatoire avant prod |
| CICD-SEC-2 | Inadequate IAM | ✅ Conforme | RBAC Jenkins + Harbor + MFA Git |
| CICD-SEC-3 | Dependency Chain Abuse | ✅ Conforme | OWASP Dep-Check + Trivy + version pinning |
| CICD-SEC-4 | Poisoned Pipeline Execution | ✅ Conforme | Branches protégées + agent Docker isolé |
| CICD-SEC-5 | Insufficient PBAC | ✅ Conforme | Credentials Jenkins par environnement |
| CICD-SEC-6 | Insufficient Credential Hygiene | ✅ Conforme | Gitleaks + credentials masqués + rotation |
| CICD-SEC-7 | Insecure System Configuration | ✅ Conforme | Dockerfile durci + cap_drop + read_only |
| CICD-SEC-8 | Ungoverned 3rd Party Services | ⚠️ Partiel | Images officielles vérifiées (à compléter) |
| CICD-SEC-9 | Improper Artifact Integrity | ✅ Conforme | Cosign signature + Harbor policy check |
| CICD-SEC-10 | Insufficient Logging | ⚠️ Partiel | Prometheus/Grafana optionnel (à activer) |

---

## 4. Plan de Remédiation Priorisé

### Priorité CRITIQUE (immédiat)
1. Fixer les digest SHA des images de base : `FROM python:3.11-slim@sha256:...`
2. Activer la politique Harbor bloquant les images non signées
3. Activer Gitleaks en hook pre-commit local (`gitleaks protect --staged`)

### Priorité ÉLEVÉE (30 jours)
4. Migrer les secrets vers HashiCorp Vault
5. Mettre en place un miroir interne des dépendances Python
6. Activer l'authentification OIDC Harbor avec l'IdP entreprise

### Priorité MOYENNE (90 jours)
7. Déployer un SIEM centralisé (logs Jenkins + Harbor + app)
8. Inventaire complet des plugins Jenkins tiers

---

## 5. Conclusion

Le pipeline couvre **8/10 des risques OWASP CI/CD** et adresse toutes les menaces STRIDE critiques identifiées.

**Score de maturité DevSecOps : 7.5/10**

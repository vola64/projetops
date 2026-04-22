# Cahier des Charges
## Sécurisation de la Supply Chain Logicielle

**Projet :** Pipeline CI/CD Sécurisé avec Jenkins, Docker et Harbor
**Encadrant :** M. Bonitah RAMBELOSON — Consultant DevOps | Cloud Engineer | MLOps
**Date :** 2024

---

## 1. Contexte et Enjeux

Les attaques sur la supply chain logicielle (SolarWinds 2020, Log4Shell 2021, Docker Hub poisoning) ont démontré que le pipeline CI/CD est une cible privilégiée des attaquants. Ce projet simule une organisation adoptant une démarche **DevSecOps** pour sécuriser son pipeline de bout en bout.

---

## 2. Objectifs

### Objectif Principal
Garantir qu'une application déployée en production est exactement celle écrite par le développeur — sans modification, sans secret compromis, sans vulnérabilité connue.

### Objectifs Techniques
- Pipeline Jenkins multi-stages avec SAST, scans, signature et déploiement contrôlé
- Harbor comme registre privé avec politique de signature obligatoire
- Gestion sécurisée des secrets (aucun secret en clair dans le code)
- Analyse de risques STRIDE + conformité OWASP CI/CD Top 10

---

## 3. Pipeline CI/CD — 10 Stages Jenkins

| Stage | Outil | Critère de succès |
|-------|-------|-------------------|
| 1. Checkout | Git | Code récupéré |
| 2. Secrets Scan | Gitleaks | 0 secret détecté |
| 3. SAST | Semgrep + Bandit + OWASP | 0 finding critique |
| 4. Tests | Pytest | ≥ 80% couverture |
| 5. Build | Docker BuildKit multi-stage | Build réussi |
| 6. Container Scan | Trivy | 0 CVE HIGH/CRITICAL |
| 7. Signature | Cosign (Sigstore) | Image signée + vérifiée |
| 8. Push | Harbor Registry | Image disponible |
| 9. Policy Check | Harbor API | Signature validée |
| 10. Déploiement | Docker Compose + SSH | Approbation manuelle |

---

## 4. Stack Technique

| Composant | Technologie | Version |
|-----------|------------|---------|
| CI/CD | Jenkins | ≥ LTS |
| Registre | Harbor | ≥ 2.10 |
| Conteneurisation | Docker + Compose | ≥ 24.x |
| Scan images | Trivy | ≥ 0.51 |
| Signature | Cosign (Sigstore) | ≥ 2.2 |
| SAST | Semgrep + Bandit | Latest |
| Secret scan | Gitleaks | ≥ 8.18 |
| Dépendances | OWASP Dependency Check | ≥ 9.x |
| Application | Python 3.11 + FastAPI | 3.11 / 0.111 |
| Proxy | Nginx | 1.25 |
| Monitoring | Prometheus + Grafana | Optionnel |

---

## 5. Exigences de Sécurité

| ID | Exigence | Priorité |
|----|---------|---------|
| SEC-01 | Aucun secret en clair dans Git | CRITIQUE |
| SEC-02 | Images signées avant push Harbor | CRITIQUE |
| SEC-03 | CVE HIGH/CRITICAL bloquent le pipeline | CRITIQUE |
| SEC-04 | Conteneurs exécutés en non-root | ÉLEVÉE |
| SEC-05 | Clés SSH dédiées pour le déploiement | ÉLEVÉE |
| SEC-06 | Approbation manuelle avant production | ÉLEVÉE |
| SEC-07 | Headers sécurité Nginx (HSTS, CSP...) | MOYENNE |
| SEC-08 | Rate limiting sur les endpoints | MOYENNE |

---

## 6. Livrables

| # | Fichier | Description |
|---|---------|-------------|
| 1 | `Jenkinsfile` | Pipeline 10 stages |
| 2 | `src/app.py` | Application FastAPI |
| 3 | `src/utils.py` | Utilitaires sécurité |
| 4 | `tests/test_app.py` | Tests unitaires ≥ 80% |
| 5 | `docker/Dockerfile` | Multi-stage, non-root |
| 6 | `docker-compose.yml` | Déploiement sécurisé |
| 7 | `scripts/scan.sh` | Scan local pré-push |
| 8 | `.gitleaks.toml` | Config détection secrets |
| 9 | `nginx/nginx.conf` | Reverse proxy TLS |
| 10 | `monitoring/` | Prometheus + Grafana |
| 11 | `docs/analyse_risques.md` | STRIDE + OWASP |
| 12 | `docs/cahier_des_charges.md` | Ce document |

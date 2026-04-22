#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  scan.sh - Script de scan de sécurité local (avant push)
#  Usage: ./scripts/scan.sh [IMAGE_NAME] [TAG]
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

IMAGE_NAME="${1:-devsecops-api}"
IMAGE_TAG="${2:-local}"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
REPORT_DIR="./security-reports"
SEVERITY="HIGH,CRITICAL"

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }

check_dependencies() {
    log_info "Vérification des outils..."
    local missing=()
    for tool in docker trivy gitleaks; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    [ ${#missing[@]} -gt 0 ] && { log_error "Manquants : ${missing[*]}"; exit 1; }
    log_success "Tous les outils disponibles"
}

scan_secrets() {
    log_info "🔑 Scan secrets Gitleaks..."
    mkdir -p "${REPORT_DIR}"
    if gitleaks detect --source="." \
        --config=".gitleaks.toml" \
        --report-format=json \
        --report-path="${REPORT_DIR}/gitleaks-report.json" \
        --redact 2>/dev/null; then
        log_success "Aucun secret détecté"
    else
        log_error "Secrets détectés ! Voir ${REPORT_DIR}/gitleaks-report.json"
        exit 1
    fi
}

build_image() {
    log_info "🐳 Build Docker : ${FULL_IMAGE}"
    DOCKER_BUILDKIT=1 docker build --no-cache --pull \
        --file docker/Dockerfile --tag "${FULL_IMAGE}" . \
        && log_success "Image construite" || { log_error "Échec build"; exit 1; }
}

scan_sast() {
    log_info "🔎 Analyse Bandit (SAST)..."
    if command -v bandit &>/dev/null; then
        bandit -r src/ -f json -o "${REPORT_DIR}/bandit-report.json" \
            --severity-level medium -ll 2>/dev/null || true
        log_success "Rapport Bandit : ${REPORT_DIR}/bandit-report.json"
    else
        log_warn "Bandit non installé. Installer : pip install bandit"
    fi
}

scan_image() {
    log_info "🔍 Scan vulnérabilités Trivy : ${FULL_IMAGE}"
    mkdir -p "${REPORT_DIR}"

    trivy image --severity "${SEVERITY}" --format json \
        --output "${REPORT_DIR}/trivy-report.json" \
        --no-progress --ignore-unfixed "${FULL_IMAGE}" || true

    local EXIT_CODE=0
    trivy image --severity "${SEVERITY}" --exit-code 1 \
        --no-progress --ignore-unfixed "${FULL_IMAGE}" || EXIT_CODE=$?

    if [ "$EXIT_CODE" -eq 0 ]; then
        log_success "Aucune CVE ${SEVERITY} détectée"
    else
        log_error "CVE ${SEVERITY} détectées ! Voir ${REPORT_DIR}/trivy-report.json"
        exit 1
    fi
}

audit_dockerfile() {
    log_info "📋 Audit Dockerfile..."
    grep -q "USER"        docker/Dockerfile && log_success "Utilisateur non-root ✓" || log_warn "Pas de USER défini"
    grep -c "^FROM" docker/Dockerfile | grep -q "^[2-9]" && log_success "Multi-stage ✓" || log_warn "Pas de multi-stage"
    grep -q "HEALTHCHECK" docker/Dockerfile && log_success "HEALTHCHECK ✓" || log_warn "Pas de HEALTHCHECK"
}

print_summary() {
    echo ""
    echo "════════════════════════════════════════"
    log_info "RÉSUMÉ SCAN SÉCURITÉ"
    echo "  Image     : ${FULL_IMAGE}"
    echo "  Rapports  : ${REPORT_DIR}/"
    echo "  Date      : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "════════════════════════════════════════"
    log_success "Scan terminé avec succès ✅"
}

main() {
    echo "════════════════════════════════════════"
    echo "   DevSecOps - Scan Sécurité Local     "
    echo "════════════════════════════════════════"
    check_dependencies
    scan_secrets
    build_image
    scan_sast
    scan_image
    audit_dockerfile
    print_summary
}

main "$@"

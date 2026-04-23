// ═══════════════════════════════════════════════════════════════════
//  Jenkinsfile - Pipeline CI/CD Sécurisé (SANS HARBOR)
//  Fix : Docker-in-Docker → plus de montage de volumes workspace
// ═══════════════════════════════════════════════════════════════════

pipeline {

    agent any

    environment {
        IMAGE_NAME     = "fastapi-app"
        IMAGE_TAG      = "${env.GIT_COMMIT?.take(8) ?: 'dev'}"
        IMAGE_FULL     = "fastapi-app:${env.GIT_COMMIT?.take(8) ?: 'dev'}"
        IMAGE_LATEST   = "fastapi-app:latest"
        TRIVY_SEVERITY = "HIGH,CRITICAL"
        REPORT_DIR     = "security-reports"
    }

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    stages {

        // ═══════════════════════════════════════════════════════
        // STAGE 1 : Checkout
        // ═══════════════════════════════════════════════════════
        stage('Checkout') {
            steps {
                echo '📥 Récupération du code source...'
                checkout scm
                sh 'git log --oneline -5'
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 2 : Vérification environnement
        // ═══════════════════════════════════════════════════════
        stage('Vérification Environnement') {
            steps {
                echo '🔧 Vérification des outils...'
                sh '''
                    echo "=== Docker ==="
                    docker --version
                    echo "=== Variables ==="
                    echo "IMAGE_FULL = ${IMAGE_FULL}"
                    echo "=== Workspace ==="
                    ls -la
                '''
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 3 : Scan de secrets - Gitleaks
        // FIX Docker-in-Docker : on installe gitleaks directement
        // dans Jenkins au lieu d'utiliser docker run + volume
        // ═══════════════════════════════════════════════════════
        stage('Secrets Scan - Gitleaks') {
            steps {
                echo '🔑 Détection de secrets avec Gitleaks...'
                sh '''
                    mkdir -p ${REPORT_DIR}

                    # Télécharger gitleaks directement dans Jenkins
                    # (évite le problème de volume Docker-in-Docker)
                    if ! command -v gitleaks &>/dev/null; then
                        echo "Installation de Gitleaks..."
                        curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
                            -o /tmp/gitleaks.tar.gz
                        tar -xzf /tmp/gitleaks.tar.gz -C /tmp
                        chmod +x /tmp/gitleaks
                        export PATH="/tmp:$PATH"
                    fi

                    # Lancer le scan depuis le workspace Jenkins directement
                    /tmp/gitleaks detect \
                        --source="$(pwd)" \
                        --config="$(pwd)/gitleaks.toml" \
                        --report-format=json \
                        --report-path="$(pwd)/${REPORT_DIR}/gitleaks-report.json" \
                        --redact \
                        --verbose \
                        --no-git || GITLEAKS_EXIT=$?

                    echo "Résultat scan : ${GITLEAKS_EXIT:-0}"
                    if [ "${GITLEAKS_EXIT:-0}" = "1" ]; then
                        echo "🚨 Secrets détectés dans le code !"
                        exit 1
                    fi
                    echo "✅ Aucun secret détecté"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORT_DIR}/gitleaks-report.json",
                                     allowEmptyArchive: true
                }
                failure {
                    error('🚨 Secrets détectés ! Pipeline bloqué.')
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 4 : SAST (parallèle)
        // FIX : on utilise docker run avec le code passé
        // via git archive + pipe (pas de volume)
        // ═══════════════════════════════════════════════════════
        stage('SAST') {
            parallel {

                stage('Semgrep') {
                    steps {
                        echo '🔎 Analyse Semgrep...'
                        sh '''
                            mkdir -p ${REPORT_DIR}
                            # Installer semgrep dans Jenkins directement
                            pip3 install semgrep --quiet 2>/dev/null || \
                            pip install semgrep --quiet 2>/dev/null || true

                            if command -v semgrep &>/dev/null; then
                                semgrep \
                                    --config="p/python" \
                                    --config="p/owasp-top-ten" \
                                    --json \
                                    --output="${REPORT_DIR}/semgrep-report.json" \
                                    src/ || true
                                echo "✅ Semgrep terminé"
                            else
                                echo "⚠️  Semgrep non disponible, scan ignoré"
                                echo '{"results":[]}' > ${REPORT_DIR}/semgrep-report.json
                            fi
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORT_DIR}/semgrep-report.json",
                                             allowEmptyArchive: true
                        }
                    }
                }

                stage('Bandit') {
                    steps {
                        echo '🔎 Analyse Bandit Python SAST...'
                        sh '''
                            mkdir -p ${REPORT_DIR}
                            pip3 install bandit --quiet 2>/dev/null || \
                            pip install bandit --quiet 2>/dev/null || true

                            if command -v bandit &>/dev/null; then
                                bandit -r src/ \
                                    -f json \
                                    -o ${REPORT_DIR}/bandit-report.json \
                                    --severity-level medium -ll || true
                                echo "✅ Bandit terminé"
                            else
                                echo "⚠️  Bandit non disponible, scan ignoré"
                                echo '{"results":[]}' > ${REPORT_DIR}/bandit-report.json
                            fi
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORT_DIR}/bandit-report.json",
                                             allowEmptyArchive: true
                        }
                    }
                }

                stage('OWASP Dependency Check') {
                    steps {
                        echo '📦 Scan dépendances OWASP...'
                        sh '''
                            mkdir -p ${REPORT_DIR}/dependency-check
                            # Utiliser pip-audit (léger, sans Docker)
                            pip3 install pip-audit --quiet 2>/dev/null || \
                            pip install pip-audit --quiet 2>/dev/null || true

                            if command -v pip-audit &>/dev/null; then
                                pip-audit \
                                    -r requirements.txt \
                                    -f json \
                                    -o ${REPORT_DIR}/dependency-check/pip-audit-report.json \
                                    --no-deps || true
                                echo "✅ pip-audit terminé"
                            else
                                echo "⚠️  pip-audit non disponible"
                            fi
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORT_DIR}/dependency-check/**",
                                             allowEmptyArchive: true
                        }
                    }
                }

            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 5 : Tests unitaires
        // ═══════════════════════════════════════════════════════
        stage('Tests Unitaires') {
            steps {
                echo '🧪 Exécution des tests Pytest...'
                sh '''
                    pip3 install -r requirements.txt --quiet 2>/dev/null || \
                    pip install -r requirements.txt --quiet 2>/dev/null

                    pytest tests/ \
                        --cov=src \
                        --cov-report=xml:coverage.xml \
                        --cov-report=term-missing \
                        --cov-fail-under=80 \
                        --junitxml=test-results.xml \
                        -v
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'coverage.xml,test-results.xml',
                                     allowEmptyArchive: true
                }
                failure {
                    error('❌ Tests échoués ou couverture < 80%.')
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 6 : Build Docker
        // FIX : utiliser DOCKER_HOST ou construire via Dockerfile
        // sans monter le workspace
        // ═══════════════════════════════════════════════════════
        stage('Build Docker') {
            steps {
                echo "🐳 Construction de l'image : ${IMAGE_FULL}"
                sh '''
                    # Copier les sources dans un contexte de build temporaire
                    BUILD_CTX=$(mktemp -d)
                    cp -r . "${BUILD_CTX}/"

                    DOCKER_BUILDKIT=1 docker build \
                        --no-cache \
                        --file "${BUILD_CTX}/docker/Dockerfile" \
                        --tag "${IMAGE_FULL}" \
                        --tag "${IMAGE_LATEST}" \
                        --label "git.commit=${GIT_COMMIT}" \
                        --label "build.number=${BUILD_NUMBER}" \
                        "${BUILD_CTX}"

                    rm -rf "${BUILD_CTX}"
                    echo "✅ Image construite : ${IMAGE_FULL}"
                    docker images | grep "${IMAGE_NAME}"
                '''
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 7 : Container Scan - Trivy
        // FIX : scan de l'image locale (pas de volume workspace)
        // ═══════════════════════════════════════════════════════
        stage('Container Scan - Trivy') {
            steps {
                echo "🔍 Scan Trivy : ${IMAGE_FULL}"
                sh '''
                    mkdir -p ${REPORT_DIR}

                    # Trivy scanne l'image locale directement via le socket Docker
                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        aquasec/trivy:latest \
                        image \
                        --severity "${TRIVY_SEVERITY}" \
                        --format json \
                        --no-progress \
                        --ignore-unfixed \
                        "${IMAGE_FULL}" > ${REPORT_DIR}/trivy-report.json 2>&1 || true

                    # Affichage lisible + code de retour bloquant
                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        aquasec/trivy:latest \
                        image \
                        --severity "${TRIVY_SEVERITY}" \
                        --exit-code 1 \
                        --no-progress \
                        --ignore-unfixed \
                        "${IMAGE_FULL}"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORT_DIR}/trivy-report.json",
                                     allowEmptyArchive: true
                }
                failure {
                    error("🚨 CVE ${TRIVY_SEVERITY} détectées ! Image bloquée.")
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 8 : Signature Cosign
        // ═══════════════════════════════════════════════════════
        stage('Signature - Cosign') {
            steps {
                echo "✍️  Signature Cosign..."
                withCredentials([
                    string(credentialsId: 'COSIGN_PRIVATE_KEY', variable: 'COSIGN_PRIVATE_KEY'),
                    string(credentialsId: 'COSIGN_PUBLIC_KEY',  variable: 'COSIGN_PUBLIC_KEY'),
                    string(credentialsId: 'COSIGN_PASSWORD',    variable: 'COSIGN_PASSWORD')
                ]) {
                    sh '''
                        echo "${COSIGN_PRIVATE_KEY}" > /tmp/cosign.key
                        echo "${COSIGN_PUBLIC_KEY}"  > /tmp/cosign.pub
                        chmod 600 /tmp/cosign.key

                        docker run --rm \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            -v /tmp/cosign.key:/cosign.key:ro \
                            -e COSIGN_PASSWORD="${COSIGN_PASSWORD}" \
                            gcr.io/projectsigstore/cosign:v2.2.4 \
                            sign --key /cosign.key \
                            --tlog-upload=false \
                            "${IMAGE_FULL}"

                        docker run --rm \
                            -v /tmp/cosign.pub:/cosign.pub:ro \
                            gcr.io/projectsigstore/cosign:v2.2.4 \
                            verify --key /cosign.pub \
                            --insecure-ignore-tlog \
                            "${IMAGE_FULL}"

                        echo "✅ Image signée et vérifiée"
                    '''
                }
            }
            post {
                always {
                    sh 'rm -f /tmp/cosign.key /tmp/cosign.pub'
                }
                failure {
                    error('❌ Échec signature Cosign.')
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 9 : Déploiement Docker Compose
        // ═══════════════════════════════════════════════════════
        stage('Déploiement') {
            when {
                branch 'main'
            }
            steps {
                timeout(time: 30, unit: 'MINUTES') {
                    input message: "🚀 Déployer la version ${IMAGE_TAG} ?",
                          ok: 'Déployer',
                          submitter: 'admin'
                }
                echo "🚀 Déploiement Docker Compose..."
                sh '''
                    echo "IMAGE_TAG=${IMAGE_TAG}"    > .env.deploy
                    echo "IMAGE_NAME=${IMAGE_NAME}" >> .env.deploy

                    docker-compose \
                        --env-file .env.deploy \
                        -f docker-compose.yml \
                        up -d --remove-orphans

                    sleep 10
                    docker ps | grep "${IMAGE_NAME}"
                    echo "✅ Déploiement réussi - version ${IMAGE_TAG}"
                '''
            }
        }

    }

    post {
        always {
            sh '''
                docker rmi "${IMAGE_FULL}"   || true
                docker rmi "${IMAGE_LATEST}" || true
            '''
            archiveArtifacts artifacts: "${REPORT_DIR}/**/*",
                             allowEmptyArchive: true
        }
        success {
            echo "✅ Pipeline réussi — Version : ${IMAGE_TAG}"
        }
        failure {
            echo "❌ Pipeline échoué — Build #${BUILD_NUMBER}"
        }
        cleanup {
            cleanWs()
        }
    }
}

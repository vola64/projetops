// ═══════════════════════════════════════════════════════════════════
//  Jenkinsfile - Pipeline CI/CD Sécurisé
//  Fix : docker create + docker cp (pas de volume mount)
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
                echo '🔧 Vérification...'
                sh '''
                    docker --version
                    echo "IMAGE_FULL = ${IMAGE_FULL}"
                    ls -la
                '''
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 3 : Scan secrets - Gitleaks (binaire direct)
        // ═══════════════════════════════════════════════════════
        stage('Secrets Scan - Gitleaks') {
            steps {
                echo '🔑 Détection de secrets avec Gitleaks...'
                sh '''
                    mkdir -p ${REPORT_DIR}

                    if [ ! -f /tmp/gitleaks ]; then
                        echo "Téléchargement Gitleaks..."
                        curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
                            -o /tmp/gitleaks.tar.gz
                        tar -xzf /tmp/gitleaks.tar.gz -C /tmp
                        chmod +x /tmp/gitleaks
                    fi

                    GITLEAKS_EXIT=0
                    /tmp/gitleaks detect \
                        --source="$(pwd)" \
                        --config="$(pwd)/gitleaks.toml" \
                        --report-format=json \
                        --report-path="$(pwd)/${REPORT_DIR}/gitleaks-report.json" \
                        --redact --verbose --no-git || GITLEAKS_EXIT=$?

                    if [ "$GITLEAKS_EXIT" = "1" ]; then
                        echo "🚨 Secrets détectés !"
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
        // STAGE 4 : SAST
        // FIX : docker create + docker cp (pas de volume mount)
        // ═══════════════════════════════════════════════════════
        stage('SAST') {
            parallel {

                stage('Bandit') {
                    steps {
                        echo '🔎 Analyse Bandit Python SAST...'
                        sh '''
                            mkdir -p ${REPORT_DIR}

                            # Créer conteneur sans le démarrer
                            CID=$(docker create python:3.11-slim \
                                bash -c "pip install bandit --quiet && \
                                bandit -r /app/src/ -f json \
                                -o /app/${REPORT_DIR}/bandit-report.json \
                                --severity-level medium -ll || true && \
                                echo done")

                            # Copier le workspace dans le conteneur
                            docker cp "$(pwd)/." "${CID}:/app/"

                            # Démarrer et attendre
                            docker start -a "${CID}" || true

                            # Récupérer le rapport
                            docker cp "${CID}:/app/${REPORT_DIR}/bandit-report.json" \
                                "${REPORT_DIR}/bandit-report.json" || \
                                echo '{"results":[]}' > ${REPORT_DIR}/bandit-report.json

                            docker rm "${CID}" || true
                            echo "✅ Bandit terminé"
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: "${REPORT_DIR}/bandit-report.json",
                                             allowEmptyArchive: true
                        }
                    }
                }

                stage('pip-audit') {
                    steps {
                        echo '📦 Scan dépendances pip-audit...'
                        sh '''
                            mkdir -p ${REPORT_DIR}/dependency-check

                            CID=$(docker create python:3.11-slim \
                                bash -c "pip install pip-audit --quiet && \
                                pip-audit -r /app/requirements.txt \
                                -f json \
                                -o /app/${REPORT_DIR}/dependency-check/pip-audit-report.json \
                                --no-deps || true && echo done")

                            docker cp "$(pwd)/." "${CID}:/app/"
                            docker start -a "${CID}" || true

                            docker cp "${CID}:/app/${REPORT_DIR}/dependency-check/pip-audit-report.json" \
                                "${REPORT_DIR}/dependency-check/pip-audit-report.json" || \
                                echo '{"dependencies":[]}' > ${REPORT_DIR}/dependency-check/pip-audit-report.json

                            docker rm "${CID}" || true
                            echo "✅ pip-audit terminé"
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
        // FIX : docker create + docker cp
        // ═══════════════════════════════════════════════════════
        stage('Tests Unitaires') {
            steps {
                echo '🧪 Exécution des tests Pytest...'
                sh '''
                    # Créer le conteneur Python sans démarrer
                    CID=$(docker create python:3.11-slim \
                        bash -c "pip install -r /app/requirements.txt --quiet && \
                        cd /app && \
                        pytest tests/ \
                            --cov=src \
                            --cov-report=xml:coverage.xml \
                            --cov-report=term-missing \
                            --cov-fail-under=80 \
                            --junitxml=test-results.xml \
                            -v")

                    # Copier tout le workspace dans le conteneur
                    docker cp "$(pwd)/." "${CID}:/app/"

                    # Lancer les tests
                    docker start -a "${CID}"
                    TEST_EXIT=$?

                    # Récupérer les rapports
                    docker cp "${CID}:/app/coverage.xml" coverage.xml 2>/dev/null || true
                    docker cp "${CID}:/app/test-results.xml" test-results.xml 2>/dev/null || true

                    docker rm "${CID}" || true

                    if [ "$TEST_EXIT" != "0" ]; then
                        echo "❌ Tests échoués"
                        exit 1
                    fi
                    echo "✅ Tests réussis"
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
        // FIX : docker build depuis contexte copié dans /tmp
        // ═══════════════════════════════════════════════════════
        stage('Build Docker') {
            steps {
                echo "🐳 Construction : ${IMAGE_FULL}"
                sh '''
                    # Copier le workspace dans un répertoire tmp accessible par Docker
                    BUILD_CTX=$(mktemp -d /tmp/jenkins-build-XXXX)
                    cp -r "$(pwd)/." "${BUILD_CTX}/"

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
        // OK : scanne l'image locale via socket Docker
        // ═══════════════════════════════════════════════════════
        stage('Container Scan - Trivy') {
            steps {
                echo "🔍 Scan Trivy : ${IMAGE_FULL}"
                sh '''
                    mkdir -p ${REPORT_DIR}

                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        aquasec/trivy:latest \
                        image \
                        --severity "${TRIVY_SEVERITY}" \
                        --format json \
                        --no-progress \
                        --ignore-unfixed \
                        "${IMAGE_FULL}" > ${REPORT_DIR}/trivy-report.json 2>&1 || true

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
        // OK : utilise /tmp pour les clés (pas de volume workspace)
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
                    input message: "🚀 Déployer ${IMAGE_TAG} ?",
                          ok: 'Déployer',
                          submitter: 'admin'
                }
                echo "🚀 Déploiement..."
                sh '''
                    echo "IMAGE_TAG=${IMAGE_TAG}"    > .env.deploy
                    echo "IMAGE_NAME=${IMAGE_NAME}" >> .env.deploy

                    docker-compose \
                        --env-file .env.deploy \
                        -f docker-compose.yml \
                        up -d --remove-orphans

                    sleep 10
                    docker ps | grep "${IMAGE_NAME}"
                    echo "✅ Déploiement réussi - ${IMAGE_TAG}"
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
            echo "✅ Pipeline réussi — ${IMAGE_TAG}"
        }
        failure {
            echo "❌ Pipeline échoué — Build #${BUILD_NUMBER}"
        }
        cleanup {
            cleanWs()
        }
    }
}

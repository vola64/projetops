// ═══════════════════════════════════════════════════════════════════
//  Jenkinsfile - Pipeline CI/CD Sécurisé (SANS HARBOR)
//  Stack : Jenkins + Docker + Trivy + Cosign + Semgrep + Gitleaks
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
                    echo "IMAGE_NAME = ${IMAGE_NAME}"
                    echo "IMAGE_TAG  = ${IMAGE_TAG}"
                    echo "IMAGE_FULL = ${IMAGE_FULL}"

                    echo "=== Workspace ==="
                    ls -la
                '''
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 3 : Scan de secrets - Gitleaks
        // ═══════════════════════════════════════════════════════
        stage('Secrets Scan - Gitleaks') {
            steps {
                echo '🔑 Détection de secrets avec Gitleaks...'
                sh '''
                    mkdir -p ${REPORT_DIR}
                    docker run --rm \
                        -v "$(pwd):/repo" \
                        zricethezav/gitleaks:latest \
                        detect \
                        --source=/repo \
                        --config=/repo/gitleaks.toml \
                        --report-format=json \
                        --report-path=/repo/${REPORT_DIR}/gitleaks-report.json \
                        --redact --verbose
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: "${REPORT_DIR}/gitleaks-report.json",
                                     allowEmptyArchive: true
                }
                failure {
                    error('🚨 Secrets détectés dans le code ! Pipeline bloqué.')
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 4 : SAST (parallèle)
        // ═══════════════════════════════════════════════════════
        stage('SAST') {
            parallel {

                stage('Semgrep') {
                    steps {
                        echo '🔎 Analyse Semgrep OWASP Top 10...'
                        sh '''
                            mkdir -p ${REPORT_DIR}
                            docker run --rm \
                                -v "$(pwd):/src" \
                                returntocorp/semgrep:latest \
                                semgrep \
                                --config="p/python" \
                                --config="p/owasp-top-ten" \
                                --json \
                                --output=/src/${REPORT_DIR}/semgrep-report.json \
                                /src/src/ || true
                            echo "✅ Semgrep terminé"
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
                            docker run --rm \
                                -v "$(pwd):/app" \
                                python:3.11-slim \
                                bash -c "
                                    pip install bandit --quiet &&
                                    bandit -r /app/src/ \
                                        -f json \
                                        -o /app/${REPORT_DIR}/bandit-report.json \
                                        --severity-level medium -ll || true
                                "
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

                stage('OWASP Dependency Check') {
                    steps {
                        echo '📦 Scan dépendances OWASP...'
                        sh '''
                            mkdir -p ${REPORT_DIR}/dependency-check
                            docker run --rm \
                                -v "$(pwd):/src" \
                                -v "$(pwd)/${REPORT_DIR}/dependency-check:/report" \
                                owasp/dependency-check:latest \
                                --project "DevSecOps-API" \
                                --scan /src/requirements.txt \
                                --format JSON --format HTML \
                                --out /report || true
                            echo "✅ OWASP Dep-Check terminé"
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
                    docker run --rm \
                        -v "$(pwd):/app" \
                        -w /app \
                        python:3.11-slim \
                        bash -c "
                            pip install -r requirements.txt --quiet &&
                            pytest tests/ \
                                --cov=src \
                                --cov-report=xml:coverage.xml \
                                --cov-report=term-missing \
                                --cov-fail-under=80 \
                                --junitxml=test-results.xml \
                                -v
                        "
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
        // ═══════════════════════════════════════════════════════
        stage('Build Docker') {
            steps {
                echo "🐳 Construction de l'image : ${IMAGE_FULL}"
                sh '''
                    DOCKER_BUILDKIT=1 docker build \
                        --no-cache --pull \
                        --file docker/Dockerfile \
                        --tag "${IMAGE_FULL}" \
                        --tag "${IMAGE_LATEST}" \
                        --label "git.commit=${GIT_COMMIT}" \
                        --label "build.number=${BUILD_NUMBER}" \
                        --label "build.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                        .
                    echo "✅ Image construite : ${IMAGE_FULL}"
                    docker images | grep "${IMAGE_NAME}"
                '''
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 7 : Container Scan - Trivy
        // ═══════════════════════════════════════════════════════
        stage('Container Scan - Trivy') {
            steps {
                echo "🔍 Scan vulnérabilités Trivy : ${IMAGE_FULL}"
                sh '''
                    mkdir -p ${REPORT_DIR}

                    # Rapport JSON
                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        -v "$(pwd)/${REPORT_DIR}:/report" \
                        aquasec/trivy:latest \
                        image \
                        --severity "${TRIVY_SEVERITY}" \
                        --format json \
                        --output /report/trivy-report.json \
                        --no-progress --ignore-unfixed \
                        "${IMAGE_FULL}" || true

                    # Bloquant si CVE critique
                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        aquasec/trivy:latest \
                        image \
                        --severity "${TRIVY_SEVERITY}" \
                        --exit-code 1 \
                        --no-progress --ignore-unfixed \
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
                echo "✍️  Signature de l'image avec Cosign..."
                withCredentials([
                    string(credentialsId: 'COSIGN_PRIVATE_KEY', variable: 'COSIGN_PRIVATE_KEY'),
                    string(credentialsId: 'COSIGN_PUBLIC_KEY',  variable: 'COSIGN_PUBLIC_KEY'),
                    string(credentialsId: 'COSIGN_PASSWORD',    variable: 'COSIGN_PASSWORD')
                ]) {
                    sh '''
                        echo "${COSIGN_PRIVATE_KEY}" > /tmp/cosign.key
                        echo "${COSIGN_PUBLIC_KEY}"  > /tmp/cosign.pub
                        chmod 600 /tmp/cosign.key

                        # Signer l'image
                        docker run --rm \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            -v /tmp/cosign.key:/cosign.key:ro \
                            -e COSIGN_PASSWORD="${COSIGN_PASSWORD}" \
                            -e COSIGN_EXPERIMENTAL=1 \
                            gcr.io/projectsigstore/cosign:v2.2.4 \
                            sign --key /cosign.key \
                            --tlog-upload=false \
                            "${IMAGE_FULL}"

                        # Vérifier la signature
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
        // STAGE 9 : Déploiement local Docker Compose
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
                    # Mettre à jour la variable d'image
                    echo "IMAGE_TAG=${IMAGE_TAG}" > .env.deploy
                    echo "IMAGE_NAME=${IMAGE_NAME}" >> .env.deploy

                    # Déployer
                    docker-compose \
                        --env-file .env.deploy \
                        -f docker-compose.yml \
                        up -d --remove-orphans

                    # Vérifier que l'app est saine
                    sleep 10
                    docker ps | grep "${IMAGE_NAME}"

                    echo "✅ Déploiement réussi - version ${IMAGE_TAG}"
                '''
            }
            post {
                success {
                    echo "✅ Application disponible sur http://localhost:8000"
                }
            }
        }

    }

    // ─────────────────────────────────────────────────────────────
    // Post-actions globales
    // ─────────────────────────────────────────────────────────────
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

// ═══════════════════════════════════════════════════════════════════
//  Jenkinsfile - Pipeline CI/CD Sécurisé
//  Supply Chain Logicielle : Build · Scan · Sign · Push · Deploy
//  Stack : Jenkins + Docker + Harbor + Trivy + Cosign + Semgrep
// ═══════════════════════════════════════════════════════════════════

pipeline {
    agent any

    // ─────────────────────────────────────────────────────────────
    // Variables globales
    // ─────────────────────────────────────────────────────────────
    environment {
        HARBOR_REGISTRY  = "${env.HARBOR_HOST}/devsecops"
        IMAGE_NAME       = "fastapi-app"
        IMAGE_TAG        = "${env.GIT_COMMIT?.take(8) ?: 'latest'}"
        IMAGE_FULL       = "${HARBOR_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
        IMAGE_LATEST     = "${HARBOR_REGISTRY}/${IMAGE_NAME}:latest"
        TRIVY_SEVERITY   = "HIGH,CRITICAL"
        REPORT_DIR       = "security-reports"
    }

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    triggers {
        pollSCM('H/5 * * * *')
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
        // STAGE 2 : Scan de secrets - Gitleaks
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
                        --config=/repo/.gitleaks.toml \
                        --report-format=json \
                        --report-path=/repo/${REPORT_DIR}/gitleaks-report.json \
                        --redact \
                        --verbose
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
        // STAGE 3 : SAST (parallèle)
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
                                --config="p/secrets" \
                                --json \
                                --output=/src/${REPORT_DIR}/semgrep-report.json \
                                --error \
                                /src/src/
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
                                        --severity-level medium -ll
                                "
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
                                --scan /src \
                                --format JSON \
                                --format HTML \
                                --out /report \
                                --failOnCVSS 7
                        '''
                    }
                    post {
                        always {
                            publishHTML([
                                allowMissing: true,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: "${REPORT_DIR}/dependency-check",
                                reportFiles: 'dependency-check-report.html',
                                reportName: 'OWASP Dependency Check'
                            ])
                        }
                    }
                }

            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 4 : Tests unitaires
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
                    junit 'test-results.xml'
                    publishCoverage adapters: [coberturaAdapter('coverage.xml')],
                                    sourceFileResolver: sourceFiles('NEVER_STORE')
                }
                failure {
                    error('❌ Tests échoués ou couverture < 80%.')
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 5 : Build Docker multi-stage
        // ═══════════════════════════════════════════════════════
        stage('Build Docker') {
            steps {
                echo "🐳 Construction de l'image : ${IMAGE_FULL}"
                sh '''
                    DOCKER_BUILDKIT=1 docker build \
                        --no-cache \
                        --pull \
                        --file docker/Dockerfile \
                        --tag "${IMAGE_FULL}" \
                        --tag "${IMAGE_LATEST}" \
                        --label "git.commit=${GIT_COMMIT}" \
                        --label "git.branch=${GIT_BRANCH}" \
                        --label "build.number=${BUILD_NUMBER}" \
                        --label "build.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                        .
                '''
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 6 : Container Scan - Trivy
        // ═══════════════════════════════════════════════════════
        stage('Container Scan - Trivy') {
            steps {
                echo "🔍 Scan vulnérabilités Trivy : ${IMAGE_FULL}"
                sh '''
                    mkdir -p ${REPORT_DIR}
                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        -v "$(pwd)/${REPORT_DIR}:/report" \
                        aquasec/trivy:latest \
                        image \
                        --severity "${TRIVY_SEVERITY}" \
                        --format json \
                        --output /report/trivy-report.json \
                        --no-progress \
                        --ignore-unfixed \
                        "${IMAGE_FULL}"

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
        // STAGE 7 : Signature Cosign
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

                        docker run --rm \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            -v /tmp/cosign.key:/cosign.key:ro \
                            -e COSIGN_PASSWORD="${COSIGN_PASSWORD}" \
                            -e COSIGN_EXPERIMENTAL=1 \
                            gcr.io/projectsigstore/cosign:v2.2.4 \
                            sign --key /cosign.key --tlog-upload=true "${IMAGE_FULL}"

                        docker run --rm \
                            -v /tmp/cosign.pub:/cosign.pub:ro \
                            gcr.io/projectsigstore/cosign:v2.2.4 \
                            verify --key /cosign.pub "${IMAGE_FULL}"

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
        // STAGE 8 : Push vers Harbor
        // ═══════════════════════════════════════════════════════
        stage('Push vers Harbor') {
            steps {
                echo "📤 Push vers Harbor : ${IMAGE_FULL}"
                withCredentials([
                    usernamePassword(
                        credentialsId: 'HARBOR_CREDENTIALS',
                        usernameVariable: 'HARBOR_USER',
                        passwordVariable: 'HARBOR_PASSWORD'
                    )
                ]) {
                    sh '''
                        echo "${HARBOR_PASSWORD}" | docker login "${HARBOR_HOST}" \
                            --username "${HARBOR_USER}" --password-stdin
                        docker push "${IMAGE_FULL}"
                        docker push "${IMAGE_LATEST}"
                        echo "✅ Image disponible : ${IMAGE_FULL}"
                    '''
                }
            }
            post {
                always {
                    sh "docker logout ${env.HARBOR_HOST} || true"
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 9 : Harbor Policy Check
        // ═══════════════════════════════════════════════════════
        stage('Harbor Policy Check') {
            steps {
                echo '🛡️  Vérification politique Harbor...'
                withCredentials([
                    usernamePassword(
                        credentialsId: 'HARBOR_CREDENTIALS',
                        usernameVariable: 'HARBOR_USER',
                        passwordVariable: 'HARBOR_PASSWORD'
                    )
                ]) {
                    sh '''
                        curl -s -X POST \
                            "https://${HARBOR_HOST}/api/v2.0/projects/devsecops/repositories/${IMAGE_NAME}/artifacts/${IMAGE_TAG}/scan" \
                            -H "Authorization: Basic $(echo -n ${HARBOR_USER}:${HARBOR_PASSWORD} | base64)" \
                            -H "Content-Type: application/json"

                        echo "Attente scan Harbor (30s)..."
                        sleep 30

                        CRITICAL=$(curl -s \
                            "https://${HARBOR_HOST}/api/v2.0/projects/devsecops/repositories/${IMAGE_NAME}/artifacts/${IMAGE_TAG}/additions/vulnerabilities" \
                            -H "Authorization: Basic $(echo -n ${HARBOR_USER}:${HARBOR_PASSWORD} | base64)" | \
                            python3 -c "
import sys, json
data = json.load(sys.stdin)
report = data.get('application/vnd.security.vulnerability.report; version=1.1', {})
print(report.get('summary', {}).get('critical', 0))
")
                        echo "CVE Critiques Harbor : ${CRITICAL}"
                        if [ "${CRITICAL}" -gt "0" ]; then
                            echo "🚨 Bloqué par Harbor : ${CRITICAL} CVE critiques"
                            exit 1
                        fi
                        echo "✅ Politique Harbor OK"
                    '''
                }
            }
        }

        // ═══════════════════════════════════════════════════════
        // STAGE 10 : Déploiement Production
        // ═══════════════════════════════════════════════════════
        stage('Déploiement Production') {
            when {
                branch 'main'
            }
            steps {
                timeout(time: 30, unit: 'MINUTES') {
                    input message: "🚀 Déployer la version ${IMAGE_TAG} en production ?",
                          ok: 'Déployer',
                          submitter: 'admin,devops-lead'
                }
                echo "🚀 Déploiement de ${IMAGE_FULL}..."
                withCredentials([
                    sshUserPrivateKey(
                        credentialsId: 'DEPLOY_SSH_KEY',
                        keyFileVariable: 'SSH_KEY',
                        usernameVariable: 'DEPLOY_USER'
                    )
                ]) {
                    sh '''
                        ssh -i "${SSH_KEY}" \
                            -o StrictHostKeyChecking=no \
                            "${DEPLOY_USER}@${DEPLOY_HOST}" "
                                cosign verify --key /etc/cosign/cosign.pub ${IMAGE_FULL} &&
                                echo IMAGE_TAG=${IMAGE_TAG} > /opt/app/.env &&
                                echo HARBOR_REGISTRY=${HARBOR_REGISTRY} >> /opt/app/.env &&
                                docker-compose -f /opt/app/docker-compose.yml pull &&
                                docker-compose -f /opt/app/docker-compose.yml up -d --remove-orphans &&
                                docker image prune -f &&
                                echo 'Déploiement réussi ✅'
                            "
                    '''
                }
            }
        }

    }

    // ─────────────────────────────────────────────────────────────
    // Post-actions
    // ─────────────────────────────────────────────────────────────
    post {
        always {
            sh """
                docker rmi ${IMAGE_FULL} || true
                docker rmi ${IMAGE_LATEST} || true
            """
            archiveArtifacts artifacts: "${REPORT_DIR}/**/*", allowEmptyArchive: true
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

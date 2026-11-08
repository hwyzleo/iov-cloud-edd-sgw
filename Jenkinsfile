pipeline {
    agent {
        label 'java17'
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(
            numToKeepStr: '20',
            artifactNumToKeepStr: '10'
        ))
    }

    environment {
        // Maven
        MAVEN_SETTINGS = '/var/jenkins_home/.m2/settings.xml'
        MAVEN_ARCHIVE  = '/var/jenkins_home/apache-maven-3.6.3-bin.tar.gz'
        REPO_ID       = 'snapshots'
        REPO_URL      = "http://${env.MAVEN_URL}/repository/maven-snapshots/"

        // 项目目录（多模块：edd-sgw-api + edd-sgw-service）
        SGW_DIR_KEY  = "${env.DIR_KEY ?: 'edd-sgw'}"
        DIR_API      = "${SGW_DIR_KEY}-api"
        DIR_SERVICE  = "${SGW_DIR_KEY}-service"
        // 默认复用平台多模块 ServiceDockerfile；如网关需要专用运行时，可在 Job 环境变量
        // 设置 SGW_DOCKERFILE=/var/jenkins_home/GwDockerfile（并确保其按 service 模块产物构建）
        DOCKERFILE   = "${env.SGW_DOCKERFILE ?: '/var/jenkins_home/ServiceDockerfile'}"

        // Docker/TCR
        PROJECT_NAME = "${env.JOB_BASE_NAME}"
        TCR_REGISTRY = 'ccr.ccs.tencentyun.com'
        IMAGE_NAME   = "${env.REGISTRY_URL}/${env.JOB_BASE_NAME}:${env.BUILD_NUMBER}"
        DOCKER_NETWORK = 'openiov-management'

        // 容器运行配置
        NACOS_ENV_FILE = '/var/jenkins_home/nacos.env'

        // 启动检查：15 × 5 秒
        STARTUP_MAX_RETRIES = '15'
        STARTUP_INTERVAL    = '5'
    }

    parameters {
        booleanParam(
            name: 'DEPLOY_API',
            defaultValue: false,
            description: '是否构建并发布 API（MPT 依赖 edd-sgw-api，首次发布或契约变更时必须执行）'
        )

        booleanParam(
            name: 'DOCKER_NO_CACHE',
            defaultValue: false,
            description: '构建镜像时是否禁用 Docker 缓存'
        )
    }

    tools {
        jdk   'temurin-17'
        maven 'M3'
    }

    stages {
        stage('环境检查') {
            steps {
                sh '''
                    set -eu

                    echo '============================== 环境检查 =============================='
                    echo "Jenkins 用户：$(whoami)"
                    echo "项目名称：${PROJECT_NAME}"
                    echo "镜像名称：${IMAGE_NAME}"
                    echo "API 目录：${DIR_API}"
                    echo "Service 目录：${DIR_SERVICE}"
                    echo "Dockerfile：${DOCKERFILE}"
                    echo "Docker 网络：${DOCKER_NETWORK}"

                    java -version
                    mvn -version
                    docker version

                    test -f "${MAVEN_SETTINGS}"
                    test -f "${MAVEN_ARCHIVE}"
                    test -f "${DOCKERFILE}"
                    test -f "${NACOS_ENV_FILE}"
                    test -d "${DIR_API}"
                    test -f "${DIR_API}/pom.xml"
                    test -d "${DIR_SERVICE}"
                    test -f "${DIR_SERVICE}/pom.xml"

                    docker network inspect \
                        "${DOCKER_NETWORK}" >/dev/null
                '''
            }
        }

        stage('构建并发布 API') {
            when {
                expression {
                    return params.DEPLOY_API
                }
            }

            steps {
                dir("${DIR_API}") {
                    sh '''
                        set -eu

                        echo '============================== 构建并发布 API =============================='

                        mvn \
                            --settings "${MAVEN_SETTINGS}" \
                            --batch-mode \
                            --update-snapshots \
                            clean deploy \
                            -DskipTests \
                            -DaltDeploymentRepository="${REPO_ID}::default::${REPO_URL}"
                    '''
                }
            }
        }

        stage('构建网关镜像') {
            steps {
                script {
                    def noCacheArg = params.DOCKER_NO_CACHE
                        ? '--no-cache'
                        : ''

                    sh """
                        set -eu

                        echo '============================== 构建网关镜像 =============================='

                        # 多模块：仅以 service 模块作为镜像构建上下文
                        SETTINGS_TARGET='${DIR_SERVICE}/settings.xml'
                        MAVEN_TARGET='${DIR_SERVICE}/apache-maven-3.6.3-bin.tar.gz'

                        cleanup_build_files() {
                            rm -f "\${SETTINGS_TARGET}" "\${MAVEN_TARGET}"
                        }

                        trap cleanup_build_files EXIT

                        cp '${MAVEN_SETTINGS}' "\${SETTINGS_TARGET}"
                        cp '${MAVEN_ARCHIVE}' "\${MAVEN_TARGET}"

                        docker build \
                            --network '${DOCKER_NETWORK}' \
                            ${noCacheArg} \
                            --tag '${IMAGE_NAME}' \
                            --file '${DOCKERFILE}' \
                            '${DIR_SERVICE}'

                        docker image inspect \
                            '${IMAGE_NAME}' >/dev/null
                    """
                }
            }
        }

        stage('上传网关镜像') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'tencent-tcr',
                        usernameVariable: 'TCR_USERNAME',
                        passwordVariable: 'TCR_PASSWORD'
                    )
                ]) {
                    sh '''
                        set -eu

                        echo '============================== 上传网关镜像 =============================='

                        logout_tcr() {
                            docker logout \
                                "${TCR_REGISTRY}" >/dev/null 2>&1 || true
                        }

                        trap logout_tcr EXIT

                        echo "${TCR_PASSWORD}" |
                            docker login \
                                --username "${TCR_USERNAME}" \
                                --password-stdin \
                                "${TCR_REGISTRY}"

                        docker push "${IMAGE_NAME}"
                    '''
                }
            }
        }

        stage('部署网关') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'tencent-tcr',
                        usernameVariable: 'TCR_USERNAME',
                        passwordVariable: 'TCR_PASSWORD'
                    )
                ]) {
                    sh '''
                        set -eu

                        echo '============================== 部署网关 =============================='

                        ROLLBACK_CONTAINER="${PROJECT_NAME}-rollback"
                        ROLLBACK_AVAILABLE=0

                        logout_tcr() {
                            docker logout \
                                "${TCR_REGISTRY}" >/dev/null 2>&1 || true
                        }

                        rollback() {
                            echo '============================== 部署回滚 =============================='

                            echo "删除启动失败的新容器：${PROJECT_NAME}"
                            docker rm -f \
                                "${PROJECT_NAME}" >/dev/null 2>&1 || true

                            if [ "${ROLLBACK_AVAILABLE}" -eq 1 ]; then
                                echo "恢复旧容器：${PROJECT_NAME}"

                                docker rename \
                                    "${ROLLBACK_CONTAINER}" \
                                    "${PROJECT_NAME}"

                                if ! docker start "${PROJECT_NAME}"; then
                                    echo '错误：旧容器恢复失败，请立即人工处理。'
                                    exit 2
                                fi

                                echo '旧容器已恢复。'
                            else
                                echo '没有可用于回滚的旧容器。'
                            fi
                        }

                        deployment_failed() {
                            echo '============================== 部署失败 =============================='
                            echo '新容器最后 500 行日志：'

                            docker logs \
                                --tail 500 \
                                "${PROJECT_NAME}" 2>&1 || true

                            rollback
                            exit 1
                        }

                        trap logout_tcr EXIT

                        # 私有仓库拉取镜像前必须登录
                        echo "${TCR_PASSWORD}" |
                            docker login \
                                --username "${TCR_USERNAME}" \
                                --password-stdin \
                                "${TCR_REGISTRY}"

                        # 确保目标镜像已经成功上传至仓库
                        echo "拉取镜像：${IMAGE_NAME}"
                        docker pull "${IMAGE_NAME}"

                        # 清理上一次异常部署遗留的回滚容器
                        if docker container inspect \
                            "${ROLLBACK_CONTAINER}" >/dev/null 2>&1; then

                            echo "清理遗留回滚容器：${ROLLBACK_CONTAINER}"
                            docker rm -f "${ROLLBACK_CONTAINER}"
                        fi

                        # 保留当前容器，启动失败时用于回滚
                        if docker container inspect \
                            "${PROJECT_NAME}" >/dev/null 2>&1; then

                            echo "停止旧容器：${PROJECT_NAME}"
                            docker stop "${PROJECT_NAME}"

                            echo "保留旧容器：${ROLLBACK_CONTAINER}"
                            docker rename \
                                "${PROJECT_NAME}" \
                                "${ROLLBACK_CONTAINER}"

                            ROLLBACK_AVAILABLE=1
                        else
                            echo '未发现旧容器，本次为首次部署。'
                        fi

                        echo "启动新容器：${PROJECT_NAME}"

                        if ! docker run \
                            --detach \
                            --name "${PROJECT_NAME}" \
                            --network "${DOCKER_NETWORK}" \
                            --restart unless-stopped \
                            --env-file "${NACOS_ENV_FILE}" \
                            "${IMAGE_NAME}"; then

                            echo '新容器创建失败。'
                            rollback
                            exit 1
                        fi

                        echo '开始检查网关启动状态……'

                        count=1
                        SUCCESS=0

                        while [ "${count}" -le "${STARTUP_MAX_RETRIES}" ]
                        do
                            echo "检查服务状态：${count}/${STARTUP_MAX_RETRIES}"

                            RUNNING=$(
                                docker inspect \
                                    --format '{{.State.Running}}' \
                                    "${PROJECT_NAME}" 2>/dev/null || true
                            )

                            if [ "${RUNNING}" != 'true' ]; then
                                echo '网关容器已经退出。'
                                deployment_failed
                            fi

                            if docker logs "${PROJECT_NAME}" 2>&1 |
                                grep -Eiq 'Started .+ in .+ seconds'; then

                                SUCCESS=1
                                break
                            fi

                            count=$((count + 1))
                            sleep "${STARTUP_INTERVAL}"
                        done

                        if [ "${SUCCESS}" -ne 1 ]; then
                            echo '网关未在规定时间内完成启动。'
                            deployment_failed
                        fi

                        echo '============================== 部署成功 =============================='

                        docker ps \
                            --filter "name=^/${PROJECT_NAME}$" \
                            --format \
                            '容器={{.Names}} 镜像={{.Image}} 状态={{.Status}}'

                        # 部署成功后，旧容器不再保留
                        if [ "${ROLLBACK_AVAILABLE}" -eq 1 ]; then
                            echo "删除旧容器：${ROLLBACK_CONTAINER}"
                            docker rm -f "${ROLLBACK_CONTAINER}"
                        fi
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "网关部署成功：${IMAGE_NAME}"
        }

        failure {
            echo "网关流水线执行失败：${env.BUILD_URL}"
        }

        always {
            sh '''
                docker logout \
                    ccr.ccs.tencentyun.com >/dev/null 2>&1 || true
            '''
        }
    }
}
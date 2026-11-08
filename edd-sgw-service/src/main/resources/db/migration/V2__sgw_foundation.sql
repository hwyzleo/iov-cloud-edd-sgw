-- V2: 服务网关基础设计（EDD-SGW-DSN-CR-001）
-- 结构化配置、不可变版本、发布协议、审计与运行时状态。
-- 依据：EDD-SGW-SPEC 设计 §3.5；无历史路由数据迁移要求，原始 tb_route 直接废弃。

DROP TABLE IF EXISTS `tb_route`;

-- 路由草稿
CREATE TABLE `sgw_route`
(
    `id`                  BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `route_code`          VARCHAR(128) NOT NULL COMMENT '路由编码（不可变，永不复用）',
    `route_name`          VARCHAR(128) NOT NULL COMMENT '路由名称',
    `description`         VARCHAR(512)          DEFAULT NULL COMMENT '说明',
    `priority`            INT          NOT NULL COMMENT '优先级，数值小者优先',
    `enabled`             TINYINT      NOT NULL DEFAULT 1 COMMENT '是否启用',
    `match_json`          JSON         NOT NULL COMMENT '匹配条件（路径/方法/主机/请求头/查询参数/客户端类型）',
    `target_type`         VARCHAR(16)  NOT NULL COMMENT '目标类型：SERVICE、HTTP、HTTPS',
    `target_value`        VARCHAR(255) NOT NULL COMMENT '服务ID或直连URI',
    `client_types`        VARCHAR(512)          DEFAULT NULL COMMENT '客户端类型列表（分页筛选冗余列）',
    `transform_json`      JSON                  DEFAULT NULL COMMENT '请求变换（路径重写/请求头增删）',
    `auth_policy_code`    VARCHAR(128)          DEFAULT NULL COMMENT '认证授权策略编码',
    `traffic_policy_code` VARCHAR(128)          DEFAULT NULL COMMENT '流量治理策略编码',
    `canary_policy_code`  VARCHAR(128)          DEFAULT NULL COMMENT '灰度策略编码',
    `row_version`         INT          NOT NULL DEFAULT 1 COMMENT '乐观锁版本',
    `row_valid`           TINYINT      NOT NULL DEFAULT 1 COMMENT '逻辑有效标记',
    `create_by`           VARCHAR(64)           DEFAULT NULL COMMENT '创建者',
    `create_time`         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `modify_by`           VARCHAR(64)           DEFAULT NULL COMMENT '修改者',
    `modify_time`         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '修改时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sgw_route_code` (`route_code`),
    KEY `idx_sgw_route_enabled` (`enabled`),
    KEY `idx_sgw_route_target` (`target_type`, `target_value`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关路由草稿';

-- 认证授权策略草稿
CREATE TABLE `sgw_auth_policy`
(
    `id`                    BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `policy_code`           VARCHAR(128) NOT NULL COMMENT '策略编码（不可变，永不复用）',
    `policy_name`           VARCHAR(128) NOT NULL COMMENT '策略名称',
    `description`           VARCHAR(512)          DEFAULT NULL COMMENT '说明',
    `access_mode`           VARCHAR(16)  NOT NULL COMMENT '访问模式：ANONYMOUS、AUTHENTICATED',
    `allowed_client_types`  VARCHAR(512)          DEFAULT NULL COMMENT '允许的客户端类型',
    `required_scopes`       VARCHAR(2048)         DEFAULT NULL COMMENT '必需 scope',
    `required_permissions`  VARCHAR(2048)         DEFAULT NULL COMMENT '必需权限点',
    `enabled`               TINYINT      NOT NULL DEFAULT 1 COMMENT '是否启用',
    `row_version`           INT          NOT NULL DEFAULT 1 COMMENT '乐观锁版本',
    `row_valid`             TINYINT      NOT NULL DEFAULT 1 COMMENT '逻辑有效标记',
    `create_by`             VARCHAR(64)           DEFAULT NULL COMMENT '创建者',
    `create_time`           TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `modify_by`             VARCHAR(64)           DEFAULT NULL COMMENT '修改者',
    `modify_time`           TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '修改时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sgw_auth_policy_code` (`policy_code`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关认证授权策略草稿';

-- 流量治理策略草稿
CREATE TABLE `sgw_traffic_policy`
(
    `id`                       BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `policy_code`              VARCHAR(128) NOT NULL COMMENT '策略编码（不可变，永不复用）',
    `policy_name`              VARCHAR(128) NOT NULL COMMENT '策略名称',
    `description`              VARCHAR(512)          DEFAULT NULL COMMENT '说明',
    `connect_timeout_millis`   INT          NOT NULL COMMENT '连接超时（毫秒）',
    `response_timeout_millis`  INT          NOT NULL COMMENT '响应超时（毫秒）',
    `rate_limits_json`         JSON                  DEFAULT NULL COMMENT '限流规则集合',
    `max_concurrent_requests`  INT                   DEFAULT NULL COMMENT '最大并发请求数',
    `circuit_breaker_json`     JSON                  DEFAULT NULL COMMENT '熔断配置',
    `retry_json`               JSON                  DEFAULT NULL COMMENT '重试配置',
    `enabled`                  TINYINT      NOT NULL DEFAULT 1 COMMENT '是否启用',
    `row_version`              INT          NOT NULL DEFAULT 1 COMMENT '乐观锁版本',
    `row_valid`                TINYINT      NOT NULL DEFAULT 1 COMMENT '逻辑有效标记',
    `create_by`                VARCHAR(64)           DEFAULT NULL COMMENT '创建者',
    `create_time`              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `modify_by`                VARCHAR(64)           DEFAULT NULL COMMENT '修改者',
    `modify_time`              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '修改时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sgw_traffic_policy_code` (`policy_code`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关流量治理策略草稿';

-- 灰度策略草稿
CREATE TABLE `sgw_canary_policy`
(
    `id`          BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `policy_code` VARCHAR(128) NOT NULL COMMENT '策略编码（不可变，永不复用）',
    `policy_name` VARCHAR(128) NOT NULL COMMENT '策略名称',
    `description` VARCHAR(512)          DEFAULT NULL COMMENT '说明',
    `stable_key`  VARCHAR(32)  NOT NULL COMMENT '稳定灰度键',
    `rules_json`  JSON         NOT NULL COMMENT '灰度规则集合',
    `enabled`     TINYINT      NOT NULL DEFAULT 1 COMMENT '是否启用',
    `row_version` INT          NOT NULL DEFAULT 1 COMMENT '乐观锁版本',
    `row_valid`   TINYINT      NOT NULL DEFAULT 1 COMMENT '逻辑有效标记',
    `create_by`   VARCHAR(64)           DEFAULT NULL COMMENT '创建者',
    `create_time` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `modify_by`   VARCHAR(64)           DEFAULT NULL COMMENT '修改者',
    `modify_time` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '修改时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sgw_canary_policy_code` (`policy_code`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关灰度策略草稿';

-- 配置工作区（单行）
CREATE TABLE `sgw_config_workspace`
(
    `id`                BIGINT   NOT NULL COMMENT '主键（固定为1）',
    `draft_revision`    BIGINT   NOT NULL DEFAULT 0 COMMENT '草稿修订号',
    `target_version_no` BIGINT            DEFAULT NULL COMMENT '当前目标版本号',
    `row_version`       INT      NOT NULL DEFAULT 1 COMMENT '乐观锁版本',
    `modify_by`         VARCHAR(64)       DEFAULT NULL COMMENT '修改者',
    `modify_time`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '修改时间',
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关配置工作区';

INSERT INTO `sgw_config_workspace` (`id`, `draft_revision`, `target_version_no`, `row_version`)
VALUES (1, 0, NULL, 1);

-- 不可变配置版本
CREATE TABLE `sgw_config_version`
(
    `id`                BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `version_no`        BIGINT       NOT NULL COMMENT '版本号',
    `operation`         VARCHAR(16)  NOT NULL COMMENT '操作类型：PUBLISH、ROLLBACK',
    `source_version_no` BIGINT                DEFAULT NULL COMMENT '来源版本号',
    `snapshot_json`     LONGTEXT     NOT NULL COMMENT '完整结构化配置快照',
    `checksum`          CHAR(64)     NOT NULL COMMENT '快照SHA-256校验和',
    `description`       VARCHAR(512)          DEFAULT NULL COMMENT '说明',
    `create_by`         VARCHAR(64)           DEFAULT NULL COMMENT '创建者',
    `create_time`       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sgw_config_version_no` (`version_no`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关不可变配置版本';

-- 发布记录
CREATE TABLE `sgw_publication`
(
    `id`                BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `publication_id`    VARCHAR(36)  NOT NULL COMMENT '发布ID',
    `target_version_no` BIGINT       NOT NULL COMMENT '目标版本号',
    `source_version_no` BIGINT                DEFAULT NULL COMMENT '来源版本号',
    `type`              VARCHAR(16)  NOT NULL COMMENT '发布类型：PUBLISH、ROLLBACK、RETRY',
    `status`            VARCHAR(32)  NOT NULL COMMENT '发布状态',
    `actor`             VARCHAR(64)           DEFAULT NULL COMMENT '操作者',
    `comment`           VARCHAR(512)          DEFAULT NULL COMMENT '说明',
    `error_message`     VARCHAR(1024)         DEFAULT NULL COMMENT '脱敏失败信息',
    `create_time`       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `update_time`       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '更新时间',
    `completed_at`      TIMESTAMP             DEFAULT NULL COMMENT '完成时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sgw_publication_id` (`publication_id`),
    KEY `idx_sgw_publication_version` (`target_version_no`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关配置发布记录';

-- 逐实例发布结果
CREATE TABLE `sgw_instance_publication`
(
    `id`                BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `publication_id`    VARCHAR(36)  NOT NULL COMMENT '发布ID',
    `instance_id`       VARCHAR(128) NOT NULL COMMENT '实例ID',
    `target_version_no` BIGINT       NOT NULL COMMENT '目标版本号',
    `active_version_no` BIGINT                DEFAULT NULL COMMENT '生效版本号',
    `status`            VARCHAR(16)  NOT NULL COMMENT '实例状态：PENDING、SUCCEEDED、FAILED、TIMEOUT',
    `error_message`     VARCHAR(1024)         DEFAULT NULL COMMENT '脱敏错误信息',
    `report_time`       TIMESTAMP             DEFAULT NULL COMMENT '上报时间',
    `create_time`       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_sgw_instance_publication` (`publication_id`, `instance_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关逐实例发布结果';

-- 实例最新运行时状态
CREATE TABLE `sgw_instance_state`
(
    `instance_id`          VARCHAR(128) NOT NULL COMMENT '实例ID',
    `active_version_no`    BIGINT                DEFAULT NULL COMMENT '当前生效版本号',
    `last_publication_id`  VARCHAR(36)           DEFAULT NULL COMMENT '最近发布ID',
    `status`               VARCHAR(32)           DEFAULT NULL COMMENT '最近发布状态',
    `last_error`           VARCHAR(1024)         DEFAULT NULL COMMENT '脱敏错误信息',
    `update_time`          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`instance_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关实例运行时状态';

-- 配置变更审计
CREATE TABLE `sgw_config_change_log`
(
    `id`             BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `actor`          VARCHAR(64)           DEFAULT NULL COMMENT '操作者',
    `action`         VARCHAR(32)  NOT NULL COMMENT '动作',
    `object_type`    VARCHAR(32)  NOT NULL COMMENT '对象类型',
    `object_code`    VARCHAR(128)          DEFAULT NULL COMMENT '对象编码',
    `before_json`    LONGTEXT              DEFAULT NULL COMMENT '变更前',
    `after_json`     LONGTEXT              DEFAULT NULL COMMENT '变更后',
    `result`         VARCHAR(16)  NOT NULL COMMENT '结果：SUCCESS、FAILURE',
    `failure_reason` VARCHAR(1024)         DEFAULT NULL COMMENT '失败原因',
    `request_id`     VARCHAR(64)           DEFAULT NULL COMMENT '请求ID',
    `create_time`    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '时间',
    PRIMARY KEY (`id`),
    KEY `idx_sgw_change_log_object` (`object_type`, `object_code`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='服务网关配置变更审计';

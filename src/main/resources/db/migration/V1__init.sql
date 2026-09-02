-- V1: 初始化数据库表结构
-- 服务网关初始化脚本（当前仅一张路由表）

-- 路由表
CREATE TABLE IF NOT EXISTS `tb_route`
(
    `id`          BIGINT       NOT NULL AUTO_INCREMENT COMMENT '主键',
    `predicates`  JSON         NOT NULL COMMENT '断言集合',
    `filters`     JSON                  DEFAULT NULL COMMENT '过滤器集合',
    `target_type` VARCHAR(255) NOT NULL COMMENT '目标类型：LB、HTTP、HTTPS、WS、FORWARD',
    `target_uri`  VARCHAR(255) NOT NULL COMMENT '目标URI',
    `sort`        INT          NOT NULL COMMENT '排序',
    `description` VARCHAR(255)          DEFAULT NULL COMMENT '备注',
    `create_time` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `create_by`   VARCHAR(64)           DEFAULT NULL COMMENT '创建者',
    `modify_time` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '修改时间',
    `modify_by`   VARCHAR(64)           DEFAULT NULL COMMENT '修改者',
    `row_version` INT                   DEFAULT 1 COMMENT '记录版本',
    `row_valid`   TINYINT               DEFAULT 1 COMMENT '记录是否有效',
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4 COMMENT ='路由表';

-- V3: 路由与认证策略基线（EDD-SGW-DSN-CR-003 / EDD-SGW-REQ-CR-003）
-- 仅 INSERT 数据种子；幂等（INSERT ... SELECT ... WHERE NOT EXISTS）；不覆盖管理员已修改行；不产生 DDL。
--
-- 依据：EDD-SGW-DSN-CR-003 §4.1/§4.2/§4.3、§19.1（BLK-5）、§19.2（BLK-6）、§19.3（R-7）、
--       §19.5（R-9）、第 1 轮裁决 adjudication-1.md「SGW 专项」。
-- 状态：CR 状态「待评审」，本迁移为设计实现产物，未合入 SPEC 正文。
--
-- 要点：
--   1) 策略先于引用它的路由插入（P1..P6 → R1..R13）；
--   2) 只写草稿，不自动发布（RD-003-4）；
--   3) 已存在同编码行不更新，避免覆盖环境内的修改；种子需要升级时另开 V4（RD-003-1）；
--   4) 选路仅按路径（BLK-5）：所有种子路由 match_json.clientTypes 为空数组，
--      客户端类型门禁由认证策略 allowed_client_types 承担（R5/R9-R12=MOBILE、R6=IVI），
--      保证「选路成功、鉴权拒绝」（401/403 而非 404），见 TC-003-15/18；
--   5) sgw_route.client_types 仅作分页筛选冗余列；
--   6) 内部服务域（900 段）路由必须落在代码常量 INTERNAL_DOMAIN_PREFIXES 内（R-9）；
--      存在 INTERNAL 路由时 sgw.runtime.internal-cidrs 必填，否则启动 fail-fast（R-7）。

-- ---------------------------------------------------------------------------
-- P1..P6 认证授权策略
-- ---------------------------------------------------------------------------

-- P1 车机认证入口（匿名）：车机首次登录/令牌获取时尚无令牌；客户端资格由 CIAM 允许清单核对
INSERT INTO sgw_auth_policy (policy_code, policy_name, description, access_mode,
                             allowed_client_types, required_scopes, required_permissions, enabled,
                             row_version, row_valid, create_by)
SELECT 'sgw-anon-ivi-auth', '车机认证入口（匿名）',
       '匿名理由：车机首次登录无令牌；客户端资格由 CIAM 允许清单核对（BLK-5：SGW 不做头匹配）',
       'ANONYMOUS', NULL, NULL, NULL, 1, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_auth_policy WHERE policy_code = 'sgw-anon-ivi-auth');

-- P2 开放平台端点（匿名）：OAuth/OIDC 标准端点先于令牌存在；userinfo 由 CIAM 自行验签 Bearer
INSERT INTO sgw_auth_policy (policy_code, policy_name, description, access_mode,
                             allowed_client_types, required_scopes, required_permissions, enabled,
                             row_version, row_valid, create_by)
SELECT 'sgw-anon-open-api', '开放平台端点（匿名）',
       '匿名理由：OAuth/OIDC 标准端点（authorize/token/device/revoke/jwks/userinfo/openid-configuration）设计上先于令牌存在',
       'ANONYMOUS', NULL, NULL, NULL, 1, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_auth_policy WHERE policy_code = 'sgw-anon-open-api');

-- P3 手机认证入口（匿名）：手机验证码/密码登录尚无令牌
INSERT INTO sgw_auth_policy (policy_code, policy_name, description, access_mode,
                             allowed_client_types, required_scopes, required_permissions, enabled,
                             row_version, row_valid, create_by)
SELECT 'sgw-anon-mobile-auth', '手机认证入口（匿名）',
       '匿名理由：手机验证码/密码登录尚无令牌；同前缀内需令牌的端点由 CIAM 控制器自行验签',
       'ANONYMOUS', NULL, NULL, NULL, 1, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_auth_policy WHERE policy_code = 'sgw-anon-mobile-auth');

-- P4 手机端已认证用户：有效令牌 + client_type=MOBILE（scope 待与 CIAM 对齐后补登）
INSERT INTO sgw_auth_policy (policy_code, policy_name, description, access_mode,
                             allowed_client_types, required_scopes, required_permissions, enabled,
                             row_version, row_valid, create_by)
SELECT 'sgw-mobile-user', '手机端已认证用户',
       '本期以有效令牌 + client_type=MOBILE 为门禁；required_scopes 与 CIAM 对齐后由 V4 补登',
       'AUTHENTICATED', 'MOBILE', NULL, NULL, 1, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_auth_policy WHERE policy_code = 'sgw-mobile-user');

-- P5 车机端车辆会话：client_type=IVI 且令牌必须含 vehicle_id（缺失由 CiamTokenVerifier 拦截为 401）
INSERT INTO sgw_auth_policy (policy_code, policy_name, description, access_mode,
                             allowed_client_types, required_scopes, required_permissions, enabled,
                             row_version, row_valid, create_by)
SELECT 'sgw-vehicle-user', '车机端车辆会话',
       'vehicle_id 为强制：CiamTokenVerifier 对 IVI/TBOX/ADCM 验签阶段强制，缺失即 401；SGW 注入 X-Vin',
       'AUTHENTICATED', 'IVI', NULL, NULL, 1, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_auth_policy WHERE policy_code = 'sgw-vehicle-user');

-- P6 内部服务域：内网来源（internal-cidrs 必填）+ 内部 HMAC 签名；不注入任何身份头
INSERT INTO sgw_auth_policy (policy_code, policy_name, description, access_mode,
                             allowed_client_types, required_scopes, required_permissions, enabled,
                             row_version, row_valid, create_by)
SELECT 'sgw-internal-service', '内部服务域',
       '内网来源 + 内部 HMAC 签名（时间窗 + 业务面 nonce），任一不满足即 SGW-403001；R-7：internal-cidrs 必填',
       'INTERNAL', NULL, NULL, NULL, 1, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_auth_policy WHERE policy_code = 'sgw-internal-service');

-- ---------------------------------------------------------------------------
-- R1..R13 路由（认证域 100 段 / 开放平台 110 段 / 手机域 200、220-250 / 车机 210 / 内部服务域 900-920）
-- ---------------------------------------------------------------------------

-- R1 车机认证入口（BLK-5：已删除 X-Client-Id 匹配，任意客户端值含缺失头均可选路）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'ivi-auth-v1', '车机认证入口', 'EDD-SGW-DSN-CR-003 R1（BLK-5：仅路径选路）',
       100, 1,
       '{"paths":["/api/ivi/auth/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'sec-ciam', 'IVI',
       NULL, 'sgw-anon-ivi-auth', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'ivi-auth-v1');

-- R2 开放平台 OAuth 端点
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'open-oauth-v1', '开放平台OAuth端点', 'EDD-SGW-DSN-CR-003 R2',
       110, 1,
       '{"paths":["/api/open/oauth/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'sec-ciam', NULL,
       NULL, 'sgw-anon-open-api', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'open-oauth-v1');

-- R3 开放平台 OIDC 端点（/api/open/** 未列子路径一律 404，fail-closed）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'open-oidc-v1', '开放平台OIDC端点', 'EDD-SGW-DSN-CR-003 R3',
       120, 1,
       '{"paths":["/api/open/oidc/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'sec-ciam', NULL,
       NULL, 'sgw-anon-open-api', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'open-oidc-v1');

-- R4 手机认证入口（D-003-2 补登；CR-002 声明头透传为其服务）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-auth-v1', '手机认证入口', 'EDD-SGW-DSN-CR-003 R4（D-003-2）',
       130, 1,
       '{"paths":["/api/mobile/auth/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'sec-ciam', NULL,
       NULL, 'sgw-anon-mobile-auth', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-auth-v1');

-- R5 手机激活域（App 在用前缀 A5）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-activation-v1', '手机激活域', 'EDD-SGW-DSN-CR-003 R5（BLK-6 A5）',
       200, 1,
       '{"paths":["/api/mobile/activation/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'iov-tsp', 'MOBILE',
       NULL, 'sgw-mobile-user', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-activation-v1');

-- R6 车机激活域（client_type=IVI 且令牌含 vehicle_id，SGW 注入 X-Vin）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'vehicle-activation-v1', '车机激活域', 'EDD-SGW-DSN-CR-003 R6（X-Vin 仅由令牌 vehicle_id 注入）',
       210, 1,
       '{"paths":["/api/vehicle/activation/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'iov-tsp', 'IVI',
       NULL, 'sgw-vehicle-user', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'vehicle-activation-v1');

-- R7 内部服务域：登录票据消费（R-9：CIAM 当前经 Feign 直连 TSP，不经 SGW；本行语义为禁止公网匿名的静态可达性声明）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'service-activation-v1', '内部服务域-激活票据', 'EDD-SGW-DSN-CR-003 R7（R-9 叙述更正）',
       900, 1,
       '{"paths":["/api/service/activation/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'iov-tsp', NULL,
       NULL, 'sgw-internal-service', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'service-activation-v1');

-- R8 内部服务域：设备证明校验（R-9：CIAM 当前经 Feign 直连 SEC-VIAM）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'service-device-proof-v1', '内部服务域-设备证明', 'EDD-SGW-DSN-CR-003 R8（R-9 叙述更正）',
       910, 1,
       '{"paths":["/api/service/deviceProof/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'sec-viam', NULL,
       NULL, 'sgw-internal-service', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'service-device-proof-v1');

-- R9 手机购车域（App 在用前缀 A2）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-vso-v1', '手机购车域', 'EDD-SGW-DSN-CR-003 R9（BLK-6 A2）',
       220, 1,
       '{"paths":["/api/mobile/vso/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'otd-vso', 'MOBILE',
       NULL, 'sgw-mobile-user', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-vso-v1');

-- R10 手机车型域（App 在用前缀 A3；** 覆盖精确路径 /api/mobile/saleModel/v1，TC-003-17）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-sale-model-v1', '手机车型域', 'EDD-SGW-DSN-CR-003 R10（BLK-6 A3）',
       230, 1,
       '{"paths":["/api/mobile/saleModel/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'otd-vso', 'MOBILE',
       NULL, 'sgw-mobile-user', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-sale-model-v1');

-- R11 手机账号域（App 在用前缀 A4；sec-ciam 以令牌 sub 取用户）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-account-v1', '手机账号域', 'EDD-SGW-DSN-CR-003 R11（BLK-6 A4）',
       240, 1,
       '{"paths":["/api/mobile/account/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'sec-ciam', 'MOBILE',
       NULL, 'sgw-mobile-user', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-account-v1');

-- R12 手机 MFA/风险（A6：按裁决登记**精确路径**，不扩面；TC-003-17 断言 /api/mobile/v1/risk/events 不命中）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-risk-v1', '手机MFA与风险事件', 'EDD-SGW-DSN-CR-003 R12（BLK-6 A6，精确路径）',
       250, 1,
       '{"paths":["/api/mobile/v1/risk"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'sec-ciam', 'MOBILE',
       NULL, 'sgw-mobile-user', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-risk-v1');

-- R13 内部服务域：VMD 首激活只读查询（R-9 新增 / EDD-VMD-DSN-CR-077 R-18 第 7 项）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'service-vehicle-activation-v1', '内部服务域-首激活查询', 'EDD-SGW-DSN-CR-003 R13（R-9）',
       920, 1,
       '{"paths":["/api/service/vehicleActivation/v1/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'edd-vmd', NULL,
       NULL, 'sgw-internal-service', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'service-vehicle-activation-v1');

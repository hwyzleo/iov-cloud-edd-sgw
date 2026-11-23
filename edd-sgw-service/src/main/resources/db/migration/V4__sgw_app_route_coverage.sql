-- V4: App 在用路径全覆盖 + 存量路由认证策略回填（EDD-SGW-DSN-CR-003 终审修复 B-2 / B-3）
-- ===========================================================================
-- 阻断 B-2（路由覆盖不全 + 门禁形同虚设）
--   现状：V3 只登记 6 条 /api/mobile/** 前缀；iOS App 经 SGW（AppGlobalState.tspUrl =
--   https://sgw.openiov.top）实际调用、但 V3 无任何路由覆盖的前缀：
--     · 车控：/unlockVehicle、/lockVehicle、/setWindow、/setTrunk、/mp/rvc/**
--     · 账号：/mp/account/**、/account/mp/account/**
--   后果：选路失败返回 404（而非「选路成功、鉴权拒绝」401/403），且这些调用天然绕过认证策略。
--   修复：新增策略 P7 + 路由 R14..R20 全覆盖；车控类必须已认证 + client_type=MOBILE +
--         权限点/scope，严禁匿名。
--
-- 阻断 B-3（存量路由无 auth_policy_code → 上线即 403，无回填）
--   现状：RequestAuthorizer 对 auth_policy_code 为空的路由 fail-closed（SGW-403001，
--         RequestAuthorizer#authorize: policyCode == null → FORBIDDEN）。运营在管理端
--         自行创建、或历史导入的路由若未配策略，上线即全量 403 且无回填脚本。
--   修复：本迁移按「路径前缀」对存量空策略路由回填 auth_policy_code（并把策略的
--         allowed_client_types 同步到冗余列 client_types 以便管理端分页筛选）。
--         守卫：仅当 auth_policy_code IS NULL 或去空白后为空 时才回填，
--               绝不覆盖运营已显式配置的行（其 auth_policy_code 非空 → 被守卫排除）。
--         若运营已显式配置 client_types，则保留运营值（COALESCE(NULLIF(TRIM(...),''), 策略值)）。
--         另对 access_mode 为空白的存量策略回填为 AUTHENTICATED（只收紧不放宽，fail-closed）。
--   结论：不存在「无需回填」的例外——本地 db_sgw / 历史数据均无法证明该类行为空是安全的，
--         故按阻断处理，必须提供回填（见文末「回填规则」表）。
--
-- 幂等性（RD-003-1：V3 发布后不可改，补登只通过新迁移）
--   · 全部 INSERT 为 INSERT ... SELECT ... WHERE NOT EXISTS → 重跑不产生重复行；
--   · 全部 UPDATE 带「仅空值行」守卫 → 重跑第二次影响 0 行；
--   · 不产生任何 DDL。
--
-- 回滚方案（见文件末尾「回滚脚本」；RD-003-4：迁移本身只写草稿，不自动发布）
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- P7 手机车控（已认证 + MOBILE + 权限点/scope；严禁匿名 —— 终审 B-2）
--   说明：车控为高风险写操作，匿名放行等价于任意公网请求可下发车控指令。
--   required_scopes / required_permissions 为上线前置条件，须由 CIAM 在
--   crypto 令牌中签发（对齐前排期见 CR 风险清单；不对齐将返回 403 而非 500，行为 fail-closed）。
-- ---------------------------------------------------------------------------
INSERT INTO sgw_auth_policy (policy_code, policy_name, description, access_mode,
                             allowed_client_types, required_scopes, required_permissions, enabled,
                             row_version, row_valid, create_by)
SELECT 'sgw-mobile-vehicle-control', '手机车控',
       '终审 B-2：车控类必须已认证且 client_type=MOBILE，并持有 scope=vehicle.control 与权限点 edd:vehicle:control；严禁匿名放行',
       'AUTHENTICATED', 'MOBILE', 'vehicle.control', 'edd:vehicle:control', 1, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_auth_policy WHERE policy_code = 'sgw-mobile-vehicle-control');

-- ---------------------------------------------------------------------------
-- R14..R20 App 在用但 V3 未登记的路由（终审 B-2）
--   选路仅按路径（BLK-5）：match_json.clientTypes 为空数组，
--   客户端类型门禁由认证策略 allowed_client_types 承担（全部为 MOBILE），
--   保证「选路成功、鉴权拒绝」（401/403 而非 404）。
--   client_types 列为管理端分页筛选冗余列。
-- ---------------------------------------------------------------------------

-- R14 车控：解锁车门（精确路径，不扩面；严禁匿名）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-vehicle-unlock', '手机车控-解锁', '终审 B-2 R14（TspApi.swift: requestPost /unlockVehicle）',
       260, 1,
       '{"paths":["/unlockVehicle"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'rvc-service', 'MOBILE',
       NULL, 'sgw-mobile-vehicle-control', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-vehicle-unlock');

-- R15 车控：闭锁车门（精确路径）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-vehicle-lock', '手机车控-闭锁', '终审 B-2 R15（TspApi.swift: requestPost /lockVehicle）',
       261, 1,
       '{"paths":["/lockVehicle"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'rvc-service', 'MOBILE',
       NULL, 'sgw-mobile-vehicle-control', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-vehicle-lock');

-- R16 车控：车窗控制（精确路径）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-vehicle-window', '手机车控-车窗', '终审 B-2 R16（TspApi.swift: requestPost /setWindow）',
       262, 1,
       '{"paths":["/setWindow"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'rvc-service', 'MOBILE',
       NULL, 'sgw-mobile-vehicle-control', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-vehicle-window');

-- R17 车控：尾门控制（精确路径）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-vehicle-trunk', '手机车控-尾门', '终审 B-2 R17（TspApi.swift: requestPost /setTrunk）',
       263, 1,
       '{"paths":["/setTrunk"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'rvc-service', 'MOBILE',
       NULL, 'sgw-mobile-vehicle-control', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-vehicle-trunk');

-- R18 车控：远程车控域（寻车 action/findVehicle、指令状态 cmd 等）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-rvc-v1', '手机车控域', '终审 B-2 R18（TspApi.swift: /mp/rvc/action/findVehicle、/mp/rvc/cmd）',
       264, 1,
       '{"paths":["/mp/rvc/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'rvc-service', 'MOBILE',
       NULL, 'sgw-mobile-vehicle-control', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-rvc-v1');

-- R19 账号：手机账号域（二维码、资料修改）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-account-mp-v1', '手机账号域-基础', '终审 B-2 R19（TspApi.swift: /mp/account/qrcode、/mp/account/action/modify*）',
       265, 1,
       '{"paths":["/mp/account/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'tsp-account', 'MOBILE',
       NULL, 'sgw-mobile-user', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-account-mp-v1');

-- R20 账号：账号信息/内容域（历史 /account/mp/account/** 调用点）
INSERT INTO sgw_route (route_code, route_name, description, priority, enabled,
                       match_json, target_type, target_value, client_types,
                       transform_json, auth_policy_code, traffic_policy_code, canary_policy_code,
                       row_version, row_valid, create_by)
SELECT 'mobile-account-info-v1', '手机账号域-信息', '终审 B-2 R20（TspApi.swift: /account/mp/account/info、/account/mp/account/action/modifyBirthday）',
       266, 1,
       '{"paths":["/account/mp/account/**"],"methods":[],"hosts":[],"headers":[],"queryParams":[],"clientTypes":[]}',
       'SERVICE', 'tsp-account', 'MOBILE',
       NULL, 'sgw-mobile-user', NULL, NULL, 1, 1, 'flyway'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM sgw_route WHERE route_code = 'mobile-account-info-v1');

-- ---------------------------------------------------------------------------
-- B-3 存量路由 auth_policy_code 回填（仅对空策略行生效；不覆盖运营显式配置）
--   回填规则（按路径前缀 → 策略）：
--     /mp/rvc/**、/unlockVehicle、/lockVehicle、/setWindow、/setTrunk → sgw-mobile-vehicle-control
--     /mp/account/**、/account/mp/account/**                        → sgw-mobile-user
--     /api/mobile/auth/v1/**                                        → sgw-anon-mobile-auth
--     /api/mobile/{account,vso,saleModel,activation}/v1/**          → sgw-mobile-user
--     /api/mobile/v1/risk                                           → sgw-mobile-user
--     /api/vehicle/activation/v1/**                                 → sgw-vehicle-user
--     /api/ivi/auth/v1/**                                           → sgw-anon-ivi-auth
--     /api/open/{oauth,oidc}/v1/**                                  → sgw-anon-open-api
--     /api/service/**                                               → sgw-internal-service
--   守卫（每条 UPDATE 均带）：(auth_policy_code IS NULL OR TRIM(auth_policy_code) = '')
--                             AND row_valid = 1 AND 策略行 row_valid=1 AND enabled=1
--   路径匹配用 JSON_SEARCH（支持 %/_ 通配），兼容 match_json.paths 为单元素或多元素数组。
--   幂等：回填后 auth_policy_code 非空 → 重跑守卫不成立 → 影响 0 行。
-- ---------------------------------------------------------------------------

-- B-3-1 车控域（终审 B-2/B-3 交叉项：车控存量路由不得停留在匿名/空策略）
UPDATE sgw_route r
    JOIN sgw_auth_policy p
    ON p.policy_code = 'sgw-mobile-vehicle-control' AND p.row_valid = 1 AND p.enabled = 1
SET r.auth_policy_code = p.policy_code,
    r.client_types     = COALESCE(NULLIF(TRIM(r.client_types), ''), p.allowed_client_types),
    r.modify_by        = 'flyway-v4-backfill',
    r.modify_time      = CURRENT_TIMESTAMP,
    r.row_version      = r.row_version + 1
WHERE (r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = '')
  AND r.row_valid = 1
  AND (JSON_SEARCH(r.match_json, 'one', '/mp/rvc%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/unlockVehicle%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/lockVehicle%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/setWindow%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/setTrunk%') IS NOT NULL);

-- B-3-2 手机账号域（/mp/account/**、/account/mp/account/**、/api/mobile/account/v1/**）
UPDATE sgw_route r
    JOIN sgw_auth_policy p
    ON p.policy_code = 'sgw-mobile-user' AND p.row_valid = 1 AND p.enabled = 1
SET r.auth_policy_code = p.policy_code,
    r.client_types     = COALESCE(NULLIF(TRIM(r.client_types), ''), p.allowed_client_types),
    r.modify_by        = 'flyway-v4-backfill',
    r.modify_time      = CURRENT_TIMESTAMP,
    r.row_version      = r.row_version + 1
WHERE (r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = '')
  AND r.row_valid = 1
  AND (JSON_SEARCH(r.match_json, 'one', '/mp/account%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/account/mp/account%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/api/mobile/account/%') IS NOT NULL);

-- B-3-3 手机认证入口（匿名策略是既定设计：登录时尚无令牌，仅此域允许匿名）
UPDATE sgw_route r
    JOIN sgw_auth_policy p
    ON p.policy_code = 'sgw-anon-mobile-auth' AND p.row_valid = 1 AND p.enabled = 1
SET r.auth_policy_code = p.policy_code,
    r.client_types     = COALESCE(NULLIF(TRIM(r.client_types), ''), p.allowed_client_types),
    r.modify_by        = 'flyway-v4-backfill',
    r.modify_time      = CURRENT_TIMESTAMP,
    r.row_version      = r.row_version + 1
WHERE (r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = '')
  AND r.row_valid = 1
  AND JSON_SEARCH(r.match_json, 'one', '/api/mobile/auth/%') IS NOT NULL;

-- B-3-4 手机业务域（购车 vso / 车型 saleModel / 激活 activation / 风险 risk）
UPDATE sgw_route r
    JOIN sgw_auth_policy p
    ON p.policy_code = 'sgw-mobile-user' AND p.row_valid = 1 AND p.enabled = 1
SET r.auth_policy_code = p.policy_code,
    r.client_types     = COALESCE(NULLIF(TRIM(r.client_types), ''), p.allowed_client_types),
    r.modify_by        = 'flyway-v4-backfill',
    r.modify_time      = CURRENT_TIMESTAMP,
    r.row_version      = r.row_version + 1
WHERE (r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = '')
  AND r.row_valid = 1
  AND (JSON_SEARCH(r.match_json, 'one', '/api/mobile/vso/%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/api/mobile/saleModel/%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/api/mobile/activation/%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/api/mobile/v1/risk%') IS NOT NULL);

-- B-3-5 车机激活域（令牌必须含 vehicle_id）
UPDATE sgw_route r
    JOIN sgw_auth_policy p
    ON p.policy_code = 'sgw-vehicle-user' AND p.row_valid = 1 AND p.enabled = 1
SET r.auth_policy_code = p.policy_code,
    r.client_types     = COALESCE(NULLIF(TRIM(r.client_types), ''), p.allowed_client_types),
    r.modify_by        = 'flyway-v4-backfill',
    r.modify_time      = CURRENT_TIMESTAMP,
    r.row_version      = r.row_version + 1
WHERE (r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = '')
  AND r.row_valid = 1
  AND JSON_SEARCH(r.match_json, 'one', '/api/vehicle/activation/%') IS NOT NULL;

-- B-3-6 车机认证入口（匿名策略是既定设计）
UPDATE sgw_route r
    JOIN sgw_auth_policy p
    ON p.policy_code = 'sgw-anon-ivi-auth' AND p.row_valid = 1 AND p.enabled = 1
SET r.auth_policy_code = p.policy_code,
    r.client_types     = COALESCE(NULLIF(TRIM(r.client_types), ''), p.allowed_client_types),
    r.modify_by        = 'flyway-v4-backfill',
    r.modify_time      = CURRENT_TIMESTAMP,
    r.row_version      = r.row_version + 1
WHERE (r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = '')
  AND r.row_valid = 1
  AND JSON_SEARCH(r.match_json, 'one', '/api/ivi/auth/%') IS NOT NULL;

-- B-3-7 开放平台端点（匿名策略是既定设计：OAuth/OIDC 标准端点先于令牌存在）
UPDATE sgw_route r
    JOIN sgw_auth_policy p
    ON p.policy_code = 'sgw-anon-open-api' AND p.row_valid = 1 AND p.enabled = 1
SET r.auth_policy_code = p.policy_code,
    r.client_types     = COALESCE(NULLIF(TRIM(r.client_types), ''), p.allowed_client_types),
    r.modify_by        = 'flyway-v4-backfill',
    r.modify_time      = CURRENT_TIMESTAMP,
    r.row_version      = r.row_version + 1
WHERE (r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = '')
  AND r.row_valid = 1
  AND (JSON_SEARCH(r.match_json, 'one', '/api/open/oauth/%') IS NOT NULL
    OR JSON_SEARCH(r.match_json, 'one', '/api/open/oidc/%') IS NOT NULL);

-- B-3-8 内部服务域（内网来源 + 内部 HMAC；不得因空策略被误当匿名）
UPDATE sgw_route r
    JOIN sgw_auth_policy p
    ON p.policy_code = 'sgw-internal-service' AND p.row_valid = 1 AND p.enabled = 1
SET r.auth_policy_code = p.policy_code,
    r.client_types     = COALESCE(NULLIF(TRIM(r.client_types), ''), p.allowed_client_types),
    r.modify_by        = 'flyway-v4-backfill',
    r.modify_time      = CURRENT_TIMESTAMP,
    r.row_version      = r.row_version + 1
WHERE (r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = '')
  AND r.row_valid = 1
  AND JSON_SEARCH(r.match_json, 'one', '/api/service/%') IS NOT NULL;

-- B-3-9 存量策略 access_mode 空白回填（只收紧不放宽：空白 → AUTHENTICATED）
--   说明：access_mode 为 NOT NULL 列，但历史直接 INSERT 可能写入空串；
--   空串在 RequestAuthorizer 中属于未知访问模式 → fail-closed（SGW-403001）。
--   此处置为 AUTHENTICATED，语义与 fail-closed 一致，且不会放宽任何权限。
UPDATE sgw_auth_policy
SET access_mode = 'AUTHENTICATED',
    modify_by   = 'flyway-v4-backfill',
    modify_time = CURRENT_TIMESTAMP,
    row_version = row_version + 1
WHERE access_mode IS NULL OR TRIM(access_mode) = '';

-- ===========================================================================
-- 回滚脚本（人工执行，不在迁移内自动运行；执行前先回退 edd-sgw 发布版本号）
-- ---------------------------------------------------------------------------
-- 1) 恢复被本迁移回填的历史行为（仅针对本次回填写入的行，按 modify_by 精确定位）
--    UPDATE sgw_route SET auth_policy_code = NULL, modify_by = 'flyway-v4-rollback'
--     WHERE modify_by = 'flyway-v4-backfill';
--    UPDATE sgw_auth_policy SET access_mode = '', modify_by = 'flyway-v4-rollback'
--     WHERE modify_by = 'flyway-v4-backfill';
-- 2) 撤销本迁移新增的路由与策略（先删路由，避免悬空引用）
--    DELETE FROM sgw_route WHERE route_code IN ('mobile-vehicle-unlock', 'mobile-vehicle-lock',
--        'mobile-vehicle-window', 'mobile-vehicle-trunk', 'mobile-rvc-v1',
--        'mobile-account-mp-v1', 'mobile-account-info-v1');
--    DELETE FROM sgw_auth_policy WHERE policy_code = 'sgw-mobile-vehicle-control';
-- 3) 回退应用版本（V3 基线版本），并删除 flyway_schema_history 中 version = 4 的记录
--    仅当 2) 已执行且确认无引用时才可删除该历史记录。
-- ===========================================================================

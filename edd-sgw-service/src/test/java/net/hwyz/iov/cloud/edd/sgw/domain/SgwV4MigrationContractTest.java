package net.hwyz.iov.cloud.edd.sgw.domain;

import net.hwyz.iov.cloud.edd.sgw.api.enums.AccessMode;
import net.hwyz.iov.cloud.edd.sgw.domain.catalog.SgwAppPathCatalog;
import net.hwyz.iov.cloud.edd.sgw.support.SeedSql;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V4 迁移契约静态校验（EDD-SGW-DSN-CR-003 终审修复 B-2 / B-3）。
 * <p>
 * 不依赖数据库，保证：
 * <ul>
 *     <li>V4 只做数据（无 DDL），且全部 INSERT 幂等（{@code WHERE NOT EXISTS}）；</li>
 *     <li>全部 {@code UPDATE sgw_route} 都带「仅空策略行」守卫，绝不覆盖运营显式配置；</li>
 *     <li>存量回填按路径前缀映射，车控前缀只映射到车控策略（严禁映射到匿名策略）；</li>
 *     <li>回填与回滚规则在迁移注释中成文（可审计、可回退）。</li>
 * </ul>
 * 真实库上的幂等重跑与行级回填结果由 {@code SgwRouteMigrationIT} 覆盖。
 *
 * @author hwyz_leo
 */
class SgwV4MigrationContractTest {

    private static final String EMPTY_POLICY_GUARD =
            "r.auth_policy_code IS NULL OR TRIM(r.auth_policy_code) = ''";

    private static final String EMPTY_MODE_GUARD =
            "access_mode IS NULL OR TRIM(access_mode) = ''";

    @Test
    @DisplayName("V4 只做数据：无 DDL，全部 INSERT 为 WHERE NOT EXISTS 幂等形态")
    void v4IsDataOnlyAndIdempotent() {
        List<String> statements = statements();
        assertThat(statements).as("V4 必须包含路由与回填语句").isNotEmpty();
        assertThat(statements)
                .allSatisfy(statement -> assertThat(upper(statement)).as("V4 不允许 DDL/DELETE: %s", head(statement))
                        .doesNotStartWith("CREATE")
                        .doesNotStartWith("ALTER")
                        .doesNotStartWith("DROP")
                        .doesNotStartWith("TRUNCATE")
                        .doesNotStartWith("DELETE"));

        List<String> inserts = statements.stream()
                .filter(statement -> upper(statement).startsWith("INSERT INTO SGW_")).toList();
        assertThat(inserts).as("V4 应新增 1 条车控策略 + 7 条路由").hasSize(8);
        assertThat(inserts).allSatisfy(insert -> {
            assertThat(insert).as("INSERT 必须幂等（WHERE NOT EXISTS）").contains("WHERE NOT EXISTS");
            assertThat(insert).as("INSERT 必须 FROM DUAL").contains("FROM DUAL");
            assertThat(insert).as("INSERT 不得使用 REPLACE/ON DUPLICATE")
                    .doesNotContainIgnoringCase("ON DUPLICATE").doesNotContainIgnoringCase("REPLACE INTO");
        });
        long guards = inserts.stream().filter(insert -> insert.contains("WHERE NOT EXISTS (SELECT 1 FROM sgw_")).count();
        assertThat(guards).as("每条 INSERT 都必须有同表存在性守卫").isEqualTo(inserts.size());
    }

    @Test
    @DisplayName("B-3：全部存量回填 UPDATE 只作用于空策略行，绝不覆盖运营显式配置")
    void backfillUpdatesAreGuarded() {
        List<String> routeUpdates = statements().stream()
                .filter(statement -> upper(statement).startsWith("UPDATE SGW_ROUTE")).toList();
        assertThat(routeUpdates).as("存量路由回填语句数量（车控/账号/认证/手机业务/车机/开放平台/内部域）")
                .hasSize(8);
        assertThat(routeUpdates).allSatisfy(update -> {
            assertThat(update).as("回填必须带空策略守卫: %s", head(update)).contains(EMPTY_POLICY_GUARD);
            assertThat(update).as("回填必须只作用于有效行").contains("r.row_valid = 1");
            assertThat(update).as("回填必须与策略表 JOIN 且策略有效可用")
                    .contains("JOIN sgw_auth_policy").contains("p.row_valid = 1").contains("p.enabled = 1");
            assertThat(update).as("回填必须留痕以便精确回滚").contains("'flyway-v4-backfill'");
            assertThat(update).as("回填必须按路径前缀匹配（JSON_SEARCH 通配）").contains("JSON_SEARCH");
            assertThat(update).as("运营已显式配置的 client_types 必须保留")
                    .contains("COALESCE(NULLIF(TRIM(r.client_types), '')");
        });

        List<String> policyUpdates = statements().stream()
                .filter(statement -> upper(statement).startsWith("UPDATE SGW_AUTH_POLICY")).toList();
        assertThat(policyUpdates).as("access_mode 空白回填恰好 1 条").hasSize(1);
        assertThat(policyUpdates.get(0)).contains(EMPTY_MODE_GUARD)
                .contains("access_mode = 'AUTHENTICATED'");
    }

    @Test
    @DisplayName("B-3：车控前缀的回填目标只能是车控策略，严禁落到匿名策略")
    void vehicleControlBackfillNeverAnonymous() {
        List<String> routeUpdates = statements().stream()
                .filter(statement -> upper(statement).startsWith("UPDATE SGW_ROUTE")).toList();
        List<String> vehicleControlUpdates = routeUpdates.stream()
                .filter(update -> update.contains("'/unlockVehicle%'") || update.contains("'/mp/rvc%'"))
                .toList();
        assertThat(vehicleControlUpdates).as("车控域必须有独立回填语句").hasSize(1);
        String update = vehicleControlUpdates.get(0);
        assertThat(update).contains("p.policy_code = 'sgw-mobile-vehicle-control'");
        assertThat(update).doesNotContain("sgw-anon-");
        assertThat(update).contains("'/lockVehicle%'").contains("'/setWindow%'").contains("'/setTrunk%'");

        // 任何回填语句都不得把匿名策略分配给车控路径
        routeUpdates.forEach(item -> {
            if (item.contains("'/unlockVehicle%'") || item.contains("'/mp/rvc%'")) {
                return;
            }
            assertThat(item).as("非车控回填不得引用车控路径").doesNotContain("'/unlockVehicle%'");
        });

        // 匿名策略只允许出现在「认证入口 / 开放平台」这类先于令牌存在的域
        List<String> anonymousBackfills = routeUpdates.stream()
                .filter(item -> item.contains("sgw-anon-")).toList();
        assertThat(anonymousBackfills).hasSize(3);
        anonymousBackfills.forEach(item ->
                assertThat(item).containsAnyOf("'/api/mobile/auth/%'", "'/api/ivi/auth/%'", "'/api/open/"));
    }

    @Test
    @DisplayName("B-2：V4 新增车控策略为已认证 + MOBILE + scope/权限点，且被 5 条车控路由引用")
    void vehicleControlPolicyIsStrict() {
        SeedSql.SeedPolicy policy = SeedSql.policiesV4().stream()
                .filter(item -> item.policyCode().equals("sgw-mobile-vehicle-control"))
                .findFirst().orElseThrow(() -> new AssertionError("V4 缺少车控策略 sgw-mobile-vehicle-control"));
        assertThat(policy.accessMode()).isEqualTo(AccessMode.AUTHENTICATED.name());
        assertThat(policy.accessMode()).isNotEqualTo(AccessMode.ANONYMOUS.name());
        assertThat(policy.allowedClientTypes()).isEqualTo("MOBILE");
        assertThat(policy.requiredScopes()).isNotBlank();
        assertThat(policy.requiredPermissions()).isNotBlank();

        List<SeedSql.SeedRoute> vehicleControlRoutes = SeedSql.routesV4().stream()
                .filter(route -> "sgw-mobile-vehicle-control".equals(route.authPolicyCode()))
                .toList();
        assertThat(vehicleControlRoutes).hasSize(5);
        assertThat(vehicleControlRoutes).allSatisfy(route -> {
            assertThat(route.targetService()).isEqualTo("rvc-service");
            assertThat(route.paths()).hasSize(1);
        });
        assertThat(vehicleControlRoutes.stream().flatMap(route -> route.paths().stream()).toList())
                .containsExactlyInAnyOrder("/unlockVehicle", "/lockVehicle", "/setWindow", "/setTrunk", "/mp/rvc/**");

        List<SeedSql.SeedRoute> accountRoutes = SeedSql.routesV4().stream()
                .filter(route -> "sgw-mobile-user".equals(route.authPolicyCode()))
                .toList();
        assertThat(accountRoutes).hasSize(2);
        assertThat(accountRoutes.stream().flatMap(route -> route.paths().stream()).toList())
                .containsExactlyInAnyOrder("/mp/account/**", "/account/mp/account/**");
    }

    @Test
    @DisplayName("B-2/B-3：清单、V4 路由、回填规则三者路径一致（无遗漏无多余）")
    void catalogAndMigrationAreInSync() {
        List<String> catalogPrefixes = SgwAppPathCatalog.APP_IN_USE_PREFIXES.stream()
                .map(SgwAppPathCatalog.AppPrefix::prefix)
                .toList();
        List<String> v4Paths = SeedSql.routesV4().stream()
                .flatMap(route -> route.paths().stream())
                .toList();
        assertThat(catalogPrefixes).containsAll(v4Paths);
        assertThat(v4Paths).hasSize(7);
        assertThat(v4Paths).as("V4 不得重复登记 V3 已有路径")
                .doesNotContainAnyElementsOf(SeedSql.routes().stream()
                        .flatMap(route -> route.paths().stream()).toList());
    }

    @Test
    @DisplayName("B-3：迁移注释成文回填规则与回滚方案（可审计、可回退）")
    void rollbackIsDocumented() {
        String sql = SeedSql.loadV4();
        assertThat(sql).contains("回滚脚本");
        assertThat(sql).contains("flyway-v4-rollback");
        assertThat(sql).contains(EMPTY_POLICY_GUARD);
        assertThat(sql).as("必须写明不覆盖运营显式配置").contains("不覆盖运营已显式配置");
        assertThat(sql).as("必须写明幂等").contains("幂等");
    }

    /**
     * 去注释后按分号切分语句
     *
     * @return 语句清单（已 trim，去除空项）
     */
    private List<String> statements() {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (String line : SeedSql.loadV4().split("\n")) {
            String stripped = line.contains("--") ? line.substring(0, line.indexOf("--")) : line;
            if (stripped.isBlank()) {
                continue;
            }
            current.append(stripped).append('\n');
            if (stripped.trim().endsWith(";")) {
                statements.add(current.toString().trim());
                current.setLength(0);
            }
        }
        if (!current.toString().isBlank()) {
            statements.add(current.toString().trim());
        }
        return statements;
    }

    private String upper(String statement) {
        return statement.trim().toUpperCase(java.util.Locale.ROOT);
    }

    private String head(String statement) {
        String trimmed = statement.trim().replaceAll("\\s+", " ");
        return trimmed.length() > 80 ? trimmed.substring(0, 80) : trimmed;
    }

}

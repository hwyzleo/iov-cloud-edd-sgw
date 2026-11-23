package net.hwyz.iov.cloud.edd.sgw.domain;

import net.hwyz.iov.cloud.edd.sgw.domain.catalog.SgwAppPathCatalog;
import net.hwyz.iov.cloud.edd.sgw.support.SeedSql;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * V3/V4 种子迁移静态校验（EDD-SGW-DSN-CR-003 TC-003-1 / TC-003-15b / 反向门禁）。
 * <p>
 * 不依赖数据库：直接解析迁移脚本，保证种子规模、幂等形态与策略引用同步。
 * 真实库上的幂等与可达性由 {@code SgwFoundationIT} / {@code SgwRouteMigrationIT} 覆盖。
 * <p>
 * 【设计纠错】内部服务域概念已撤回（内部服务间经 Nacos + Feign 直连，不经网关），
 * 因此 V3 不得再登记任何内部服务域策略与路由，且 V3/V4 都不得出现 service 前缀。
 *
 * @author hwyz_leo
 */
class SgwSeedMigrationTest {

    @Test
    @DisplayName("种子规模：策略 5 行 / 路由 10 行")
    void seedCounts() {
        assertThat(SeedSql.policies()).hasSize(5);
        assertThat(SeedSql.routes()).hasSize(10);
    }

    @Test
    @DisplayName("每条 INSERT 均为 WHERE NOT EXISTS 幂等形态")
    void everyInsertIsIdempotent() {
        String sql = SeedSql.load();
        long inserts = sql.lines().filter(line -> line.startsWith("INSERT INTO sgw_")).count();
        long guards = sql.lines().filter(line -> line.startsWith("WHERE NOT EXISTS")).count();
        assertThat(inserts).isEqualTo(15);
        assertThat(guards).isEqualTo(inserts);
        assertThat(sql).doesNotContain("DELETE FROM").doesNotContain("UPDATE sgw_").doesNotContain("CREATE TABLE");
    }

    @Test
    @DisplayName("所有种子策略均被路由引用，且引用不悬空")
    void policyReferences() {
        Set<String> policies = SeedSql.policies().stream().map(SeedSql.SeedPolicy::policyCode)
                .collect(Collectors.toSet());
        Set<String> referenced = SeedSql.routes().stream().map(SeedSql.SeedRoute::authPolicyCode)
                .collect(Collectors.toSet());
        assertThat(referenced).isEqualTo(policies);
    }

    @Test
    @DisplayName("R1 车机认证入口仅按路径选路（BLK-5）")
    void iviAuthRouteIsPathOnly() {
        String sql = SeedSql.load();
        assertThat(sql).doesNotContain("\"name\":\"X-Client-Id\"");
        SeedSql.SeedRoute route = SeedSql.routes().stream()
                .filter(item -> "ivi-auth-v1".equals(item.routeCode()))
                .findFirst().orElseThrow();
        assertThat(route.paths()).containsExactly("/api/ivi/auth/v1/**");
    }

    @Test
    @DisplayName("防回归：V3/V4 不得出现内部服务域前缀与 INTERNAL 访问模式")
    void noInternalServiceDomainSeeded() {
        for (String sql : List.of(SeedSql.load(), SeedSql.loadV4())) {
            assertThat(sql).as("迁移脚本不得登记内部服务域前缀").doesNotContain("/api/service/");
            assertThat(sql).as("迁移脚本不得声明 INTERNAL 访问模式").doesNotContain("INTERNAL");
            assertThat(sql).as("迁移脚本不得登记内部服务域策略").doesNotContain("sgw-internal-service");
        }
        assertThat(SeedSql.allRoutes())
                .allSatisfy(route -> assertThat(route.paths())
                        .allSatisfy(path -> assertThat(path).doesNotContain("/api/service/")));
        assertThat(SeedSql.allPolicies())
                .allSatisfy(policy -> assertThat(policy.accessMode())
                        .isIn("ANONYMOUS", "AUTHENTICATED"));
    }

    @Test
    @DisplayName("反向门禁：不存在未登记的业务域影子路由（V3 + V4 全量）")
    void noShadowRoutes() {
        List<String> allowed = new java.util.ArrayList<>(SgwAppPathCatalog.APP_IN_USE_PREFIXES.stream()
                .map(SgwAppPathCatalog.AppPrefix::prefix)
                .toList());
        allowed.addAll(SgwAppPathCatalog.FORCED_PREFIXES);
        allowed.addAll(List.of("/api/ivi/auth/v1/**", "/api/open/oauth/v1/**", "/api/open/oidc/v1/**",
                "/api/vehicle/activation/v1/**"));
        SeedSql.allRoutes().forEach(route -> route.paths().forEach(path ->
                assertThat(allowed).as("路由 %s 的路径 %s 未在清单声明", route.routeCode(), path).contains(path)));
    }

    @Test
    @DisplayName("种子不登记 SGW 管理面前缀")
    void adminPrefixNotSeeded() {
        SeedSql.routes().forEach(route -> route.paths()
                .forEach(path -> assertThat(path).doesNotStartWith("/api/service/sgw/v1")));
    }

}

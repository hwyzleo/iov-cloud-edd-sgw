package net.hwyz.iov.cloud.edd.sgw.domain;

import net.hwyz.iov.cloud.edd.sgw.domain.catalog.SgwAppPathCatalog;
import net.hwyz.iov.cloud.edd.sgw.domain.catalog.SgwInternalDomain;
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
 * 不依赖数据库：直接解析迁移脚本，保证种子规模、幂等形态、策略引用与内部域前缀白名单同步。
 * 真实库上的幂等与可达性由 {@code SgwFoundationIT} / {@code SgwRouteMigrationIT} 覆盖。
 *
 * @author hwyz_leo
 */
class SgwSeedMigrationTest {

    @Test
    @DisplayName("种子规模：策略 6 行 / 路由 13 行")
    void seedCounts() {
        assertThat(SeedSql.policies()).hasSize(6);
        assertThat(SeedSql.routes()).hasSize(13);
    }

    @Test
    @DisplayName("每条 INSERT 均为 WHERE NOT EXISTS 幂等形态")
    void everyInsertIsIdempotent() {
        String sql = SeedSql.load();
        long inserts = sql.lines().filter(line -> line.startsWith("INSERT INTO sgw_")).count();
        long guards = sql.lines().filter(line -> line.startsWith("WHERE NOT EXISTS")).count();
        assertThat(inserts).isEqualTo(19);
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
    @DisplayName("内部服务域路由路径均落在已登记前缀（R-9）")
    void internalRoutesUseRegisteredPrefixes() {
        Set<String> internalPolicies = SeedSql.policies().stream()
                .filter(policy -> "INTERNAL".equals(policy.accessMode()))
                .map(SeedSql.SeedPolicy::policyCode)
                .collect(Collectors.toSet());
        List<SeedSql.SeedRoute> internalRoutes = SeedSql.routes().stream()
                .filter(route -> internalPolicies.contains(route.authPolicyCode()))
                .toList();
        assertThat(internalRoutes).hasSize(3);
        internalRoutes.forEach(route ->
                assertThat(SgwInternalDomain.isRegistered(route.paths().get(0)))
                        .as("内部域路由 %s 路径 %s 必须在白名单内", route.routeCode(), route.paths())
                        .isTrue());
        assertThat(SgwInternalDomain.INTERNAL_DOMAIN_PREFIXES)
                .allSatisfy(prefix -> assertThat(SeedSql.routes().stream()
                        .filter(route -> route.paths().contains(prefix)).count())
                        .as("内部域前缀 %s 必须存在种子路由", prefix).isEqualTo(1));
    }

    @Test
    @DisplayName("反向门禁：不存在未登记的业务域影子路由（V3 + V4 全量）")
    void noShadowRoutes() {
        List<String> allowed = new java.util.ArrayList<>(SgwAppPathCatalog.APP_IN_USE_PREFIXES.stream()
                .map(SgwAppPathCatalog.AppPrefix::prefix)
                .toList());
        allowed.addAll(SgwAppPathCatalog.FORCED_PREFIXES);
        allowed.addAll(SgwInternalDomain.INTERNAL_DOMAIN_PREFIXES);
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
